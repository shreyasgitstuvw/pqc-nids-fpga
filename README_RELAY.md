# Tier 1 build: the board decrypts, inspects, then RE-ENCRYPTS

No plaintext on any cable. A talks to B (and B to A) through the board; the board
verifies and vets every message, then sends it on encrypted under the *receiver's* key.

```
 Laptop A --JA--> [ decrypt | detectors | re-encrypt ] --JD--> Laptop B
 Laptop B --JD--> [ decrypt | detectors | re-encrypt ] --JA--> Laptop A
 Laptop C --JB--> (own handshake, own key; clean mail relayed to B, attacks dropped)
```

## What changed in the RTL (all under the repo's own paths)

| File | Change |
|---|---|
| `rtl/relay/msg_relay.v` (new) | holds the message until the drop engine passes it, encrypts it for the destination (own ChaCha20 + Poly1305), streams `B0 7E len ctr ciphertext tag`; **queues** up to 4 waiting messages; routes by link |
| `rtl/relay/rx_arbiter3.v` (new) | `rx_arbiter` with a third source (B's uplink), same pacing / round robin / truncated-frame hold; exports `out_src`, the link each frame arrived on |
| `rtl/top/pqc_nids_top.v` | third `uart_rx` (B), three `uart_tx` (A, B, C), handshake replies routed to the joiner's own link, relay + egress arbitration, LD0 fix, new ports |
| `rtl/control/entropy_src.v` | **bug fix**: `rng_valid` now pulses low after each take (see below) |
| `rtl/control/session_lookup.v` | **bug fix**: new combinational `session_id_now`; **identity changed from the claimed IP address to the physical link** (see below) |
| `constraints/pqc_nids.xdc` | three new pins (below) |

### Identity is the physical link, not the claimed address

The session table used to be keyed on `ip_src_addr`. The old comment in that file argued
a spoof "buys them nothing" because an attacker cannot forge a Poly1305 tag under the
victim's key. The tag argument is sound; the conclusion was too strong. Mapping onto the
victim's slot lets the attacker touch state that belongs to the victim: an HS_INIT
carrying A's address claims A's slot and overwrites A's key, and a DATA packet carrying
it advances A's nonce. Neither reads A's traffic; both break A's session. That is a
denial of service, not nothing.

It is now keyed on `src_link`, the Pmod link the frame arrived on, exported by the
arbiter and threaded into `session_lookup` and `msg_relay`. Nothing written inside a
packet can change which cable carried it, so the spoof is structurally impossible rather
than merely detected: a frame on the attacker's link resolves to the attacker's own slot
and own key whatever address it claims.

**Limit, and say it out loud:** this works only because every peer has a dedicated
point-to-point link. On a shared or routed network the arrival port identifies nothing,
and the answer there is cryptographic mutual authentication (ML-DSA). The demo shows a
real defence that is correct for this topology, not a general solution to spoofing.

### Queuing

The relay used to hold one message at a time; a second arriving while one was in flight
was counted and dropped. On stage that looks exactly like a lost message to whoever typed
it, and it happens whenever A types two lines quickly or A and B talk at the same instant.
There is now a 2 KB ring buffer plus a 4-deep descriptor queue, so up to 5 messages
(4 queued + 1 in flight) are in hand before anything is dropped, and a drop past that is
counted in `cnt_full`. Messages always leave in the order they were passed.

### Two pre-existing bugs found while building this (both fixed)

1. **One handshake per power-up.** `entropy_src` tied `rng_valid` high; `mlkem_top` only
   releases its `rng_lock` when it sees `rng_valid` low, so after the first Encaps every
   later HS_INIT hung in the ML-KEM core. A second peer, or the attacker joining, could
   never work. This also explains why a BTNC reset was needed between runs.
2. **Session lookup answered one cycle late.** `aead_framer` sampled `session_id` in the
   `hdr_valid` cycle but `session_lookup` registers it a cycle after, so a DATA packet was
   decrypted under the session of whichever packet came *before* it. Invisible with one
   sender; with several peers it gives BAD_TAG, or "no session" after an unrelated packet.

## Verified in simulation (cloud, iverilog + cocotb)

* `sim/relay/test_msg_relay.py` (3 tests): the encrypt path is bit-exact against
  `model.chacha_poly` (ciphertext + tag) for 1, 5, 16, 63, 64, 65, 100, 240 bytes;
  counters advance; routing by link correct; failed verdict relays nothing; empty message
  relays nothing; no peer key relays nothing; four back-to-back messages all relayed in
  order with consecutive counters; past the queue depth 5 are absorbed, the rest counted
  in `cnt_full`, and none of the frames that did go out are corrupted.
* `sim/cocotb/test_relay_top.py`: the whole board with real ML-KEM. A, B, C each handshake
  on their own link and each reply stays on that link; LD0 stays dark after boot and lights on
  the first peer handshake; A->B and B->A arrive as ciphertext that decrypts only under the
  receiver's key; no plaintext appears in any frame; a `${jndi:` payload, a bad tag, and a
  wrong-key attacker are never relayed; the attacker with a genuine key IS relayed (to B);
  **a handshake and a data packet sent on C's link carrying A's source address get C's own
  slot and key, and A's next message still passes under A's own key and next counter** —
  the spoof neither steals nor disturbs A's session; two back-to-back messages from A both
  arrive in order.

NOT yet done (Member D): Vivado synthesis, timing, bitstream, hardware. See checklist.

## Member D checklist

1. Copy the files in this folder over the repo (same relative paths). Make sure the Vivado
   source list includes `rtl/relay/*.v` (if `scripts/build_bitstream.tcl` globs per
   directory, add it).
2. Run every existing sim test again (`test_rx_arbiter`, `test_chacha_poly`, any session /
   entropy / handshake tests I did not have). Expect no change; report anything that does.
3. Run `sim/relay/test_msg_relay.py` and `sim/cocotb/test_relay_top.py` (the latter takes ~5 min).
4. **Verify the three new pins** against your Zedboard-Master.xdc: `V10` (JB3,
   attacker_tx_pin), `W7` (JD1_N, peer_rx_pin), `V5` (JD2_P, peer_tx_pin). Set the IOSTANDARD
   the same as the other Pmod pins (LVCMOS33 with VADJ on 3V3).
5. Synthesize (about 40 min). Needs: WNS >= 0 at 100 MHz. The relay adds one ChaCha20 core,
   one Poly1305 (20 DSP48) and a third frame buffer. If timing fails, the cheapest relief is
   `MAXMSG` or dropping telemetry (`u_tel`, unused with three modules).
6. Check the utilisation report has no surprises (DSP count goes up by 20).
7. Flash. BTNC. LD0 must be DARK. Then the demo run below.

## Demo run (hardware)

```
python demo_relay/peer.py --me A --port COMa      # LD0 lights when A's handshake completes
python demo_relay/peer.py --me B --port COMb      # B joins on its own link
A> /ping      -> B shows "ping arrived", A shows "SECURE LINE CONFIRMED ... ms"
A> hello B    -> B shows ciphertext, then plaintext decrypted locally on B
B> hi A       -> and the other way
python demo_relay/attacker_console.py --port COMc # join, say, tamper, inject, spoof, scan, flood
```

## Wiring (3 Pmod USB-UART modules, plug into the top row, pins 1 to 6)

| Header | Device | Board RX pin (module TXD, Pmod pin 2) | Board TX pin (module RXD, Pmod pin 3) |
|---|---|---|---|
| JA | A | AA11 (unchanged) | Y10 (unchanged) |
| JB | C attacker | W11 (unchanged) | **V10 (new)** |
| JD | B | **W7 (new)** | **V5 (new)** |
| JC | none (telemetry module dropped) | | |

## Limits to say out loud

* Identity is the physical link, which cannot be forged **on this topology**. It
  identifies nothing on a shared or routed network; production needs cryptographic mutual
  authentication (ML-DSA).
* Hybrid KEM (ML-KEM + X25519), rekeying, replay window, standard protocols, secure boot
  and no debug taps are the production list.
* A message is at most 240 B. Five may be in hand at once (4 queued + 1 in flight);
  beyond that a message is dropped and counted in `cnt_full`, not lost silently.

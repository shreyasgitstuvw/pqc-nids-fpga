# Member C → Member A: Interface Contract Response

**Re:** `docs/Member A/interface_contract.md` (DRAFT) — items marked
**[MEMBER A: CONFIRM]** that name Member C, plus one correction Member C is
raising unprompted.

**From:** Member C (ML-KEM-512 crypto lane)
**Status of Member C's lane at time of writing:** Python golden model complete
and passing the official FIPS 203 KAT vectors **80/80, zero skips** — 25 keyGen,
25 encapsulation, 10 decapsulation (5 valid + 5 tampered), 10 encapsulation-key
checks, 10 decapsulation-key checks. Every number in this document comes from
that verified model, not from estimation.

---

## 0. Summary — what Member A can close after reading this

| Contract item | Member C's answer | Action for A |
|---|---|---|
| §4 `packet_type` mechanism | **Port-based.** Reasoning in §1 below | Decide with D, then lock |
| §6 `HANDSHAKE_REJECT` (4'h8) | **Definition is wrong as written — it breaks the security property §5 demands.** Replacement proposed | **Must change before freeze** |
| §6 `fo_transform.v` verdict latency | **Does not participate in the per-packet drop path at all.** One fewer lane to synchronise | Remove the row, or mark N/A |
| §5 `shared_secret : 256 bits` | Correct. 32 bytes exactly | Confirm |
| §5 session count | 1 is sufficient for Member C; 4 is harmless | A's call |
| §3 payload delivery | Same-bus streaming works for Member C | Confirm |
| §1 2-byte length field | Sufficient. Largest object is 800 bytes | Confirm |

---

## 1. §4 — `packet_type` classification: use the port

**Recommendation: option 1, port-based.** Pick a fixed `l4_dst_port`, write the
number into the contract, done.

The reason is *when* the classification becomes available, not how clean it
looks. With a port, `packet_type` is known the moment the L4 header is parsed —
before a single payload byte arrives. `mlkem_top.v` can leave idle and begin
its input sequencing while the handshake payload is still streaming in.

With option 2 (a leading type byte in the payload), classification is not
available until the first payload byte lands, which is strictly later and adds
a dependency between the parser's payload path and the crypto lane's start
condition. It buys nothing in exchange: an attacker can set a payload tag byte
just as freely as a destination port, so it is not a security control either
way. Neither option authenticates anything — that is what the ML-KEM handshake
itself is for.

**One caveat Member A should be aware of, not solve:** a fixed handshake port
is trivially floodable. That is fine and expected — it is Member B's
`count_min_sketch.v` lane that handles volumetric abuse, not Member C's. Worth
confirming with B that the handshake port is inside the sketch's monitored
space.

---

## 2. §6 — `HANDSHAKE_REJECT` as defined is a security bug. Please change it.

This is the item Member C is raising unprompted, and it is the most important
thing in this document.

### What the contract currently says

> | `HANDSHAKE_REJECT` | `4'h8` | Member C — `fo_transform.v` | Implicit rejection on handshake (tampered/invalid ciphertext) |

### Why that cannot be implemented

The contract's own §5 states the requirement correctly:

> the `state` transition into `ESTABLISHED` via a genuine handshake and the
> transition via implicit rejection must be **externally indistinguishable** —
> same latency, same signal shape, from any observer outside `session_mgr.v`.

And Member C's own guide (`Member-C-ML-KEM-Crypto-Core.md`, §4 Step 5) states
the FIPS 203 requirement:

> On decapsulation failure, FIPS 203 requires returning a deterministic
> pseudo-random key derived from a stored secret — **never an explicit error**.

A reason code *is* an explicit error. If `fo_transform.v` asserts
`fail=1, reason=HANDSHAKE_REJECT` whenever implicit rejection occurs, then
`drop_engine.v` drops the packet and increments a distinguishable counter.
An observer watching whether the handshake proceeds learns exactly one bit:
*was my ciphertext valid?*

That bit is the entire thing the Fujisaki-Okamoto transform exists to deny.
The FO construction converts a CPA-secure PKE into a CCA-secure KEM precisely
by refusing to answer that question — on a bad ciphertext it returns a decoy
key `K̄ = J(z‖c)` that is indistinguishable from a real one. Re-exposing the
answer one layer up, in the drop engine, gives back the chosen-ciphertext
oracle the transform was built to remove. The crypto would be correct and the
system would still be broken.

This is verified behaviour in the model, not theory. From the golden model's
negative-path test:

```
tampered H(ek) in dk    : rejected — invalid decapsulation key (sec 7.3)
tampered ciphertext     : silent decoy key returned (correct)
```

A tampered *key* raises. A tampered *ciphertext* returns silently. The RTL
must preserve that asymmetry.

### What happens instead on a bad handshake

Nothing, at handshake time — by design. Decapsulation "succeeds", `K̄` is
installed as the session key, and `state` goes to `ESTABLISHED` on exactly the
same cycle it would have otherwise. The two sides now hold different keys, so
the peer's **first data packet fails its Poly1305 tag check** and surfaces as
`BAD_TAG` (`4'h7`) through Member D's existing lane.

That is the correct place for the failure to appear. It costs one wasted
packet and requires no new mechanism. It also handles a legitimate peer whose
packet was corrupted in transit identically to an attacker, which is the point.

### Proposed replacement

Keep the code point, change what it means:

| Code | Value | Source module | Meaning |
|---|---|---|---|
| `HANDSHAKE_KEY_INVALID` | `4'h8` | Member C — `mlkem_top.v` | Handshake **key material** failed FIPS 203 §7.2/§7.3 structural validation |

And add an explicit non-entry to the contract so nobody re-adds it later:

> **Implicit rejection emits no verdict.** `fo_transform.v` has no path to
> `drop_engine.v`. A tampered ciphertext is indistinguishable from a valid one
> at handshake time by construction; the failure surfaces downstream as
> `BAD_TAG`.

`HANDSHAKE_KEY_INVALID` is safe to signal openly because it is a structural
check on public, non-secret data — key lengths and coefficient canonicality —
and its outcome does not depend on any secret. It is a different failure class
from implicit rejection in exactly the way §2 of the contract already
distinguishes `CRC_FAIL` from `BAD_TAG`.

**What these checks are** (both implemented and KAT-verified in `kem.py`):

- **§7.2, encapsulation key** — an `ek` stores 512 coefficients at 12 bits
  each. 12 bits holds 0–4095, but q = 3329, so values 3329–4095 are
  *representable but invalid*, and nothing in the byte layout rejects them.
  Test: `ByteDecode₁₂` then re-`ByteEncode₁₂`; require byte equality. Decode
  reduces mod q, so a non-canonical 3500 returns as 171 and re-encodes
  differently. 10/10 KAT vectors.
- **§7.3, decapsulation key** — `dk` = `dk_pke‖ek‖H(ek)‖z`. Recompute
  `SHA3-256` over the embedded `ek` and require it to match the stored field.
  Catches a `dk` whose halves came from different keypairs. 10/10 KAT vectors.

Whether §7.2 sits on a receive path depends on the handshake role
`mlkem_top.v` plays: as **initiator** the FPGA receives the peer's `ek` and
§7.2 guards attacker-controlled input; as **responder** it receives a
*ciphertext*, for which there is deliberately no validity check — that is the
implicit-rejection path. §7.3 is a local integrity check on our own stored key
either way. Member A does not need to resolve this; Member C flags it so the
reason code isn't assumed to fire on every handshake.

---

## 3. §6 — verdict latency for `fo_transform.v`

**Answer: it does not participate.** Per §2 above, the FO transform emits no
verdict, so it never gates `drop_engine.v` and contributes nothing to the
slowest-lane calculation. Member A's hardest open item gets one row simpler.

`HANDSHAKE_KEY_INVALID` does emit a verdict, but only on handshake packets,
and it is not on the per-packet data path either. It can be treated as an
out-of-band session-establishment result rather than a lane in the per-packet
race.

### Cycle counts for the §6.3 synopsis timing table

Measured from the golden model (`model/mlkem/opcount.py`), exact call counts
per invocation:

| Operation | Keccak-f1600 | NTT | INTT | base-case mult | modular mults |
|---|---:|---:|---:|---:|---:|
| KeyGen | 31 | 4 | 0 | 512 | 6,144 |
| Encaps | 30 | 2 | 3 | 768 | 9,088 |
| Decaps | 30 | 4 | 4 | 1,024 | 13,312 |

Decaps is the largest because the FO transform is *decrypt + re-encrypt* — it
pays for an encryption it then throws away. That is inherent to the
construction, not an inefficiency to optimise out.

**First-order cycle estimate**, assuming one Keccak round/cycle (24 cycles per
permutation) and one NTT butterfly/cycle (896 cycles per transform, 7 stages ×
128):

| Operation | ≈ cycles | @100 MHz |
|---|---:|---:|
| KeyGen | 4,800 | 48 µs |
| Encaps | 6,000 | 60 µs |
| Decaps | 8,900 | 89 µs |

Treat these as a **lower bound**. They exclude control-FSM overhead, BRAM
access, and any serialisation forced by the ≈8 DSP-slice budget. Expect
1.5–2× once `mlkem_top.v` exists; Member C will replace these with measured
RTL numbers at that point.

### The number that actually matters for integration planning

At 3 Mbaud with 8N1 framing, moving the handshake objects over the wire costs:

| Object | Size | UART time |
|---|---:|---:|
| Encapsulation key `ek` | 800 B | ≈ 2.67 ms |
| Ciphertext `c` | 768 B | ≈ 2.56 ms |

**The link is roughly 30× slower than the crypto.** A full decapsulation is
~89 µs against ~2.6 ms just to receive the ciphertext. The handshake is
UART-bound, not compute-bound.

Two consequences worth Member A's attention:

1. The crypto lane is not the integration risk it looks like on paper. Member C
   remains the schedule risk for *getting it correct*, but not for handshake
   latency.
2. **Timing-side-channel checking gets easier.** Since the compute is buried
   under a link delay ~30× larger, the externally observable handshake time is
   dominated by transfer, not by which decapsulation branch ran. This does not
   remove the requirement that `fo_transform.v` be constant-shape internally —
   §5 still stands and Member C still owns proving it in the testbench — but
   it means an accidental few-cycle asymmetry is unlikely to be externally
   measurable over UART. Belt and braces, not a licence to skip the check.

---

## 4. §5 — session register file: confirmed

- **`shared_secret : 256 bits`** — correct, and exactly right. ML-KEM-512's
  shared secret is 32 bytes. Not truncated, not padded.
- **Session count** — Member C needs **one**. The crypto lane holds no
  per-session state of its own beyond the key it writes on completion. If
  Member D wants 4 entries for their own reasons that costs Member C nothing.
- **Write timing** — Member C writes `shared_secret` on decapsulation
  completion. Per §2 above, that write happens on the same cycle whether the
  handshake was genuine or implicitly rejected. `session_mgr.v` must not
  branch on which occurred, because it cannot be told.

---

## 5. §3 — packet bus: confirmed for Member C

Streaming payload bytes on `data`/`valid`/`sof`/`eof` after the header fields
latch is fine. Member C's consumption pattern is simple: on
`packet_type == handshake`, capture the payload byte stream into a buffer until
`eof`, then run the KEM. No random access into the payload, no need for a
second interface.

The only requirement is that the **full** payload arrives — 800 bytes for an
`ek`, 768 for a ciphertext — with `eof` marking the true end. A truncated
handshake payload must not be presented as complete; Member C would rather see
`FRAME_TIMEOUT` and never be started than receive a short buffer.

Member C has no opinion on IPv4 options or non-IPv4 EtherTypes. Rejecting both
as `MALFORMED` is fine.

---

## 6. §1 — framing: confirmed

2 bytes is sufficient. The largest object Member C puts on the wire is the
800-byte `ek`; with framing and CRC overhead a handshake frame stays under
~820 bytes, well inside the 65,535-byte ceiling. Member C does not need
fragmentation and would prefer not to have it — a whole handshake object in
one frame keeps `mlkem_top.v`'s input path a simple buffer-until-`eof`.

---

## 7. Open items Member C is *not* answering

- Verdict latencies for `count_min_sketch.v` (B) and `poly1305.v` (D).
- The drop-engine synchronisation approach (pad-to-slowest vs. track-outstanding).
  Member C's lane is out of that path either way, so Member C has no stake and
  defers entirely to A and D.
- Whether `FLOOD` and `SCAN` need separate codes — Member B's call.

---

*Prepared by Member C against `interface_contract.md` DRAFT. Every measured
number is reproducible with `python model/mlkem/kat_test.py` and
`python model/mlkem/opcount.py` from the repo root.*

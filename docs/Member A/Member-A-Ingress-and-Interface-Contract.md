# Member A — Master Guide
## Track: Ingress Pipeline, Packet Parser, and Interface Contract (Foundation Track)

You own the thing every other track depends on. Nobody else can write RTL that means anything until you've frozen the interface contract — so your Week 1 output isn't code, it's a document, and it is the single highest-leverage deliverable in the whole project. Treat it that way.

---

## 1. Your scope, in one sentence

Take raw bytes off the UART wire and turn them into a clean, parsed, well-defined packet struct that both crypto and detection lanes can read in the same clock cycle — and write down the exact shape of that struct, and every other cross-module interface, before anyone else starts.

## 2. Files you own

```
rtl/ingress/
├── uart_rx.v
├── uart_tx.v
├── deframer.v
├── crc32.v
└── parser.v

docs/
└── interface_contract.md      ← YOU author and freeze this. Everyone else reads it.

model/
└── pipeline.py (parsing portion — header extraction function)

sim/cocotb/
├── test_uart.py
├── test_deframer.py
├── test_crc32.py
└── test_parser.py
```

## 3. Task 0 (do this first, before any RTL): the interface contract

This is not a formality. Every bug in Phase VI integration traces back to an ambiguity here. Write `docs/interface_contract.md` and get every other member to read and sign off on it before you write a line of Verilog. It must nail down:

**a) The internal packet bus** — the struct that carries a parsed packet from your parser to both lanes simultaneously:
```
{ valid, sof, eof, data[7:0], eth_hdr, ip_hdr, tcp_udp_hdr, payload_len, session_id }
```
Decide the exact bit widths for every header field now. Ethernet: dest MAC (48b), src MAC (48b), ethertype (16b). IPv4: version/IHL, total length, protocol, src IP (32b), dst IP (32b). TCP/UDP: src port, dst port, flags (TCP only), length. Write the exact bit offsets — the other three members are going to instantiate wires against this, so ambiguity here means integration-week rework for everyone.

**b) The lane → drop-engine verdict interface** — `{fail, reason_code}`, asserted one cycle after a lane finishes evaluating a packet. Confirm with the ChaCha/control owner what "one cycle after" means precisely (is it aligned to `eof`? to a fixed latency count?).

**c) The session register file layout** — session_id width, where the shared secret lives, nonce counter width, state encoding (IDLE/HANDSHAKING/ESTABLISHED/REJECTED). Confirm this with the crypto-lane owner since they populate it.

**d) The reason-code enum** (`rtl/control/reason_codes.vh`) — BAD_TAG, MALFORMED, SIGNATURE, FLOOD, etc. Own this file; anyone needing a new reason code asks you to add it so it never diverges between lanes.

Once this is written, hold a 30-minute review with the other three before treating it as frozen. After that, changes to this file require notifying everyone — it's the shared contract, not your personal scratch file.

## 4. Build order

### Step 1 — `uart_rx.v` / `uart_tx.v`
Standard UART receiver/transmitter, parameterized for 3 Mbaud (matches the Pmod USB-UART / FTDI FT232RQ link). Byte-in/byte-out with a `valid` strobe. This is well-trodden ground — get it working and simulated first since everything else depends on having bytes to work with.

**Verify:** cocotb testbench that shifts known byte patterns in/out at 3 Mbaud against a 100 MHz system clock, checks byte alignment and baud-rate timing tolerance.

### Step 2 — `crc32.v`
Standard CRC-32 over the byte stream. This is link-layer integrity — separate from and prior to any cryptographic authentication (that's Poly1305, in someone else's lane, and checks a different thing at a different point in the pipeline). Packets failing CRC never even reach the parser.

**Verify:** against Python's `zlib.crc32` or `binascii.crc32` on the same byte sequences — this should agree bit-for-bit trivially, use it as a sanity check on your cocotb harness itself.

### Step 3 — `deframer.v`
Takes the raw byte stream (post-CRC-check) and finds packet boundaries. Decide your framing scheme now (length-prefixed is simplest and matches "800-byte encapsulation key / 768-byte ciphertext" fixed-ish sizes in the synopsis — variable-length data packets need either a length field or a delimiter). Write this decision into the interface contract too.

**Verify:** feed it a byte stream with multiple back-to-back packets (including edge cases: minimum-length packet, maximum-length packet, truncated packet) and confirm it emits `sof`/`eof` correctly aligned.

### Step 4 — `parser.v`
Walks Ethernet → IPv4 → TCP/UDP headers and populates the packet bus struct from step 0(a). This is the module both lanes actually consume.

**Verify:** this is the important one. Build `model/pipeline.py`'s header-parsing function first as your reference, then a cocotb testbench with 20+ hand-crafted packets:
- valid TCP packet, valid UDP packet
- IPv4 header with options (if you're supporting them — decide and document; simplest is to reject/flag them)
- truncated header (packet ends mid-IP-header)
- malformed length fields (claimed length doesn't match actual bytes received)
- non-IPv4 ethertype (ARP, IPv6) — decide whether these get flagged as malformed or silently passed through unparsed, and document it

Every one of these must produce identical output in RTL and in `model/pipeline.py`. This cocotb suite is what proves your module before Phase III's lanes start consuming your output.

## 5. What "done" looks like for Phase I / Phase II

- [ ] `interface_contract.md` written, reviewed by all four members, frozen
- [ ] `uart_rx`/`uart_tx` simulated and passing
- [ ] `crc32` verified against Python reference
- [ ] `deframer` handles multi-packet streams and truncation correctly
- [ ] `parser.v` + `model/pipeline.py` parsing function agree on 20+ test packets including malformed ones
- [ ] CI (`sim/Makefile` target for your modules) runs green on every push

## 6. Dependencies and handoffs

- **You block everyone.** Get the contract reviewed and frozen in the first few days, not at the end of Phase I.
- Once your packet bus is stable, Lane 2 owner and ChaCha/control owner can start building against it even before your `parser.v` RTL is fully synthesizable — they can develop against `model/pipeline.py`'s Python struct output.
- Coordinate with the control owner on the exact cycle-timing of the verdict interface (§3b) — this is the one place your work directly couples to theirs.

## 7. Common failure modes to watch for

- Leaving header field widths "TBD" in the contract and letting people guess — this is the #1 source of Phase VI integration pain.
- Deframer edge cases (empty packet, single-byte packet, back-to-back packets with no gap) not tested until integration, when they're expensive to debug.
- CRC failures and cryptographic auth failures (Poly1305, someone else's lane) getting confused in reason-code logging — make sure `reason_codes.vh` distinguishes `CRC_FAIL` from `BAD_TAG` clearly since they mean very different things operationally.

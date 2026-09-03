# Member D — Master Guide
## Track: ChaCha20-Poly1305 Streaming Cipher, Drop Engine, Session/Control Logic

You own the per-packet cryptography (the thing that actually runs millions of times per session, unlike the KEM which runs once) plus the control logic that ties both lanes' verdicts together into a single drop decision. Your ChaCha/Poly1305 work is independent of the ML-KEM lane and lower-risk than it — a good place to build confidence and testbench infrastructure early while the KEM team works through their harder bottom-up sequence.

---

## 1. Your scope, in one sentence

Encrypt and authenticate payload data at line rate once a session key exists, and merge both lanes' pass/fail verdicts into a single, accounted-for drop decision where nothing is discarded silently.

## 2. Files you own

```
rtl/crypto/chacha_poly/
├── chacha20.v            quarter-round core, streaming keystream generator
└── poly1305.v            MAC accumulator

rtl/control/
├── session_mgr.v         per-link state: IDLE / HANDSHAKING / ESTABLISHED / REJECTED
├── drop_engine.v         merges lane verdicts, reason-code counters
└── reason_codes.vh       (co-owned with Member A — you're the primary consumer)

model/
└── chacha_poly.py

sim/cocotb/
├── test_chacha_poly.py
└── test_drop_engine.py
```

## 3. Prerequisite

Read `docs/interface_contract.md` fully before starting — specifically the lane→drop-engine verdict format (`{fail, reason_code}`) and the session register file layout. The session register format matters doubly to you: you both *consume* it (reading the shared secret once Member C's KEM populates it) and *drive* `session_mgr.v`, which owns the state machine around it.

## 4. Build order

### Step 1 — `chacha20.v`
The quarter-round core and streaming keystream generator. This is well-specified (RFC 8439) and doesn't depend on anything else in the project — start here immediately, in parallel with the crypto-lane team's Keccak/NTT work, not after it.

Key property to hold onto: ChaCha20-Poly1305 is add-rotate-XOR only — no substitution boxes, no Galois-field multiplier — which is exactly why it was chosen over AES-GCM (roughly half the logic, easier timing closure at 100 MHz per the synopsis). Don't accidentally reintroduce complexity (e.g., a generic/parameterized cipher framework) that erases this advantage.

**Verify:** against RFC 8439's own test vectors first (published, unambiguous), then against `model/chacha_poly.py` for the streaming/pipelined behavior specifically, since the RFC vectors alone don't exercise sustained multi-block throughput.

### Step 2 — `poly1305.v`
The MAC accumulator, checked on every data packet — this is the mechanism that answers "was this payload altered in transit," distinct from and complementary to the FO transform in the KEM lane (which protects the handshake, not per-packet data — confirm this distinction with Member C so your reason codes don't collide).

**Verify:** RFC 8439 vectors, then integration with your own `chacha20.v` output (encrypt-then-MAC or the RFC's specified construction — implement exactly per spec, don't improvise the composition).

### Step 3 — `session_mgr.v`
Owns per-link session state: `IDLE → HANDSHAKING → ESTABLISHED → REJECTED`. This is the module that watches for Member C's KEM completing (successfully or via implicit rejection) and transitions state accordingly, and that ChaCha/Poly1305 read from to know whether a session key is valid to use.

Design carefully around implicit rejection (see Member C's notes) — a rejected handshake must **not** be distinguishable, from the outside, from a successful one at the protocol/timing level. If your state machine takes a visibly different number of cycles or asserts different external signals on REJECTED vs ESTABLISHED, you've broken the property implicit rejection exists to provide, even though the cryptographic core itself is correct. Coordinate directly with Member C on this — it's the one place your two modules' correctness properties are entangled rather than independent.

**Verify:** simulate handshake success, handshake failure (implicit reject), and confirm session_mgr's *externally observable* behavior (cycle count, signal timing) doesn't leak which case occurred.

### Step 4 — `drop_engine.v`
Start with a trivial stub in Phase III (just OR the two lanes' `fail` bits, no counting) so Member B's Lane 2 testbenches have something to report a verdict to without waiting on your full implementation. Flesh it out once `reason_codes.vh` is stable:

- One counter per reason code (BAD_TAG, MALFORMED, SIGNATURE, FLOOD, CRC_FAIL, etc.) — the synopsis's core mitigation requirement is that **every discard is counted, never silent** (§3, constraint table: "a silent drop is indistinguishable from an attack that was never detected").
- Sub-microsecond decision latency (synopsis §6.2: drop happens in the datapath, after parsing and before egress — not at the physical layer, since a packet can't be un-received at the pins).
- Wire counters to the host-visible interface (LED/OLED driver reads these, per `rtl/io/`) — coordinate with whoever's building the display driver on the exposure format (memory-mapped registers vs. shift-out).

**Verify:** feed synthetic verdict sequences from both lanes (including simultaneous same-cycle failures from both — decide and document a priority rule for reason-code logging in that case) and confirm counters increment correctly and no drop goes unlogged.

## 5. What "done" looks like for Phase III / Phase VI

**Phase III (stub level):**
- [ ] `chacha20.v` passes RFC 8439 vectors
- [ ] `poly1305.v` passes RFC 8439 vectors
- [ ] `drop_engine.v` stub ORs lane fail-bits correctly, available for Lane 2 testing

**Phase VI (full integration):**
- [ ] `chacha_poly` combined module verified against `model/chacha_poly.py` on sustained multi-packet streams
- [ ] `session_mgr.v` correctly transitions on real KEM handshake completion (success and implicit-reject cases)
- [ ] Implicit-reject path confirmed *timing-indistinguishable* from success, jointly verified with Member C
- [ ] `drop_engine.v` fully implements per-reason-code counting, sub-microsecond latency confirmed in simulation
- [ ] Full pipeline sim (Phase VI exit criterion from the master plan): encrypted packet in → correct verdict out, both lanes exercised, nothing silently dropped

## 6. Dependencies and handoffs

- ChaCha20/Poly1305 development starts immediately (no dependency) — don't wait for the KEM to be ready before building and testing the symmetric cipher on synthetic/fixed keys.
- `session_mgr.v` has a hard dependency on Member C's session-key output format — pin this down early even if you're testing against a stub key in the meantime.
- `drop_engine.v` has a hard dependency on Member B's `{fail, reason_code}` output and Member A's `reason_codes.vh` — build your stub against the documented contract, not against Member B's actual RTL, so you're not blocked if their timeline shifts.

## 7. Common failure modes to watch for

- Waiting on the KEM lane before starting ChaCha/Poly1305 — there's no reason to; this is your biggest opportunity to bank progress early.
- Letting `session_mgr.v`'s handling of implicit rejection leak information through timing — this is subtle and easy to miss in simulation if you're not specifically testing for it.
- A drop_engine reason-code priority rule that's implicit rather than documented — when both lanes fail on the same packet, write down which reason code wins and why, since this affects how the final report's detection-accuracy numbers get interpreted.
- Treating Poly1305 failure and FO-transform failure as the same kind of event — they operate at different layers (per-packet vs. per-session) and conflating them in logging will make Phase VIII's measurement section harder to write cleanly.

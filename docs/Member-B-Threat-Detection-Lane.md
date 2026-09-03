# Member B — Master Guide
## Track: Lane 2 — Threat Detection (CAM Signature Matcher, Count-Min Sketch, Protocol Validator)

You own the entire "is this hostile?" half of the design. This lane is architecturally independent of the ML-KEM/ChaCha crypto lane — you don't need session keys, encryption, or anything cryptographic to build or test your half. That independence is deliberate: you can start the day the interface contract is frozen and work in parallel with the crypto team without waiting on them.

---

## 1. Your scope, in one sentence

Given a parsed packet on the shared bus, decide in hardware whether it's a known attack signature, part of a volumetric flood/scan, or structurally malformed — and do it fast enough and with bounded-enough memory that signature count and traffic volume never affect your latency.

## 2. Files you own

```
rtl/detect/
├── cam_matcher.v
├── count_min_sketch.v
├── hash_functions.v
└── protocol_validator.v

model/
└── detect.py                  Python reference for all three detectors

sim/cocotb/
├── test_cam_matcher.py
├── test_count_min_sketch.py
└── test_protocol_validator.py

sim/vectors/
└── cicids2017_subset/         you'll curate this — trimmed pcaps for sim-speed testing
```

## 3. Prerequisite

Read `docs/interface_contract.md` (Member A's deliverable) before writing anything — specifically the packet bus struct and the `{fail, reason_code}` verdict interface format. Confirm the reason codes you need (`SIGNATURE`, `FLOOD`, `SCAN`, `MALFORMED`, etc.) exist in `rtl/control/reason_codes.vh`; if not, ask Member A to add them — don't invent your own encoding locally.

## 4. Build order

### Step 1 — `protocol_validator.v`
Build this first: it's pure combinational logic against the already-parsed header bus, no state, no memory — the easiest of your three modules and a good way to get your cocotb harness working before tackling the stateful ones.

Checks to implement:
- header length fields that don't match actual packet length
- invalid TCP flag combinations (e.g., SYN+FIN set simultaneously)
- reserved/invalid protocol numbers
- port 0 or other structurally invalid values

**Verify:** hand-craft ~15 malformed packets covering each check, confirm `model/detect.py`'s validator function and your RTL agree.

### Step 2 — `cam_matcher.v`
Content-addressable memory: given a packet's payload (or a relevant header fingerprint, per your signature design), resolve a match against a stored signature table in one clock cycle, regardless of how many signatures are stored.

Design decisions to make and document:
- Start with 16–32 signatures. Don't over-engineer table size before timing closure — expand later if you have logic budget to spare (synopsis's logic budget table gives Lane 2 ≈5,030 LUTs; CAM is part of that).
- Decide what you're matching against — full payload byte patterns (Snort/Suricata-style) is the most faithful to the "signature-based model" the synopsis cites, but a fixed-width fingerprint (e.g., first N payload bytes, or a hash of a suspicious substring) is far simpler to implement in one clock. Pick the simpler one first; document the tradeoff.
- Where do the actual signatures come from? Pull a representative subset from the CIC-IDS2017 dataset traffic you're using for testing, so your signature table and your test vectors are consistent.

**Verify:** load a known signature set, replay both matching and non-matching packets, confirm 1-cycle-latency match and zero false negatives on the exact signatures you loaded.

### Step 3 — `count_min_sketch.v` + `hash_functions.v`
This is your hardest module — fixed-memory volumetric anomaly detection (floods, scans, slow-rate exploits) using k independent hash functions into a BRAM-backed counter array.

Before writing RTL, do the math on paper (or in a short Python script) first:
- Pick k (number of hash rows) and w (width per row) based on the false-positive/over-estimate rate you're willing to report. The synopsis is explicit that CMS **over-estimates but never under-estimates** — that's your safety property, but you still need to know and report the bound.
- Standard CMS sizing: width `w = ceil(e / epsilon)`, depth `k = ceil(ln(1/delta))` for an (epsilon, delta) error guarantee. Compute concrete numbers for your BRAM budget (synopsis gives ≈11.5 of 140 36Kb BRAMs to the whole detect lane's memory — budget accordingly) and write them into your test plan before implementation.
- `hash_functions.v`: k independent, cheap hash functions (e.g., different multiply-XOR constants) over source IP / flow 5-tuple. Keep these simple — correctness of the CMS bound depends on independence, not cryptographic strength.

**Verify:** this is the one place you should measure empirically, not just trust the math. Replay the CIC-IDS2017 subset (real floods and scans) through both `model/detect.py`'s Python CMS and your RTL, confirm:
1. Bit-exact agreement between RTL and Python on counter values for identical input sequences.
2. The actual measured false-positive rate on this traffic matches or beats your analytical (epsilon, delta) bound — this becomes one of the "detection accuracy" numbers Objective 7 asks the whole project to report.

### Step 4 — curate `sim/vectors/cicids2017_subset/`
You're the natural owner of this since you consume it most heavily. Trim the full CIC-IDS2017 dataset down to a subset that (a) simulates fast enough for CI, (b) includes at least one clean example of each attack class you're detecting (port scan, SYN flood, slow-rate/low-volume attack, tampered/malformed packets), and (c) has ground-truth labels so your accuracy numbers are checkable, not eyeballed.

## 5. What "done" looks like for Phase III

- [ ] `protocol_validator.v` passes ~15 hand-crafted malformed-packet cases against `model/detect.py`
- [ ] `cam_matcher.v` matches known signatures in exactly 1 clock cycle, zero false negatives on loaded set
- [ ] `count_min_sketch.v` sizing documented with analytical (epsilon, delta) bound, verified bit-exact against Python reference
- [ ] Measured false-positive rate on real CIC-IDS2017 replay reported and compared against the analytical bound
- [ ] `sim/vectors/cicids2017_subset/` curated, labeled, and checked into the repo
- [ ] All three modules wired to emit `{fail, reason_code}` per the interface contract

## 6. Dependencies and handoffs

- You depend on Member A's interface contract and reason-code enum — get these confirmed before finalizing your verdict output format.
- You do **not** depend on the crypto lane at all. You can and should start immediately once the contract is frozen.
- The stub `drop_engine.v` (Member D's, Phase III) needs your `{fail, reason_code}` output early to test against — coordinate on timing so you're not blocked waiting for their stub, or vice versa. A trivial testbench-only stub on your side is fine if theirs isn't ready.

## 7. Common failure modes to watch for

- Sizing the CMS from intuition instead of the (epsilon, delta) formula — you'll end up either wasting BRAM or reporting an accuracy number you can't defend in the report.
- Signature set and test-vector set drifting out of sync (e.g., testing against attacks your CAM table was never loaded with) — keep both derived from the same CIC-IDS2017 subset.
- Conflating "malformed" (protocol_validator) with "malicious" (CAM/CMS) reason codes — they're different failure classes and the report should be able to break them apart.

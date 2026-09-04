# PQC-NIDS FPGA Project — Codebase Architecture & Execution Plan

**Project:** Inline FPGA-Based Post-Quantum Cryptographic Engine (ML-KEM) with Real-Time Threat Detection
**Target:** ZedBoard, Xilinx Zynq-7000 XC7Z020
**Team:** Shreyas Thakur, Sumit Gyawali, Ujjwal, Yuvraj

---

## 1. How to read this document

The synopsis defines *what* and *why*. This document defines *how the code is organized* and *in what order it gets built*, so four people can work without stepping on each other and every block can be verified in isolation before integration.

Core principle driving the structure: **every RTL module has a bit-exact Python twin, and nothing gets synthesized until its Python twin agrees with a published test vector or a hand-derived one.** This is what makes "zero unexplained mismatches" (Objective 6) achievable rather than aspirational.

---

## 2. Repository layout

```
pqc-nids-fpga/
├── rtl/
│   ├── top/                    top.v — instantiates everything, single clock domain
│   ├── ingress/
│   │   ├── uart_rx.v / uart_tx.v
│   │   ├── deframer.v          byte-stream -> packet framing (start/end delim + length)
│   │   ├── crc32.v
│   │   └── parser.v            Ethernet/IPv4/TCP/UDP header extraction -> struct bus
│   ├── crypto/
│   │   ├── sha3/
│   │   │   ├── keccak_f1600.v  the 1600-bit permutation core (shared by SHA3 + SHAKE)
│   │   │   └── shake_wrapper.v
│   │   ├── ntt/
│   │   │   ├── ntt_core.v      forward/inverse NTT, Cooley-Tukey butterfly
│   │   │   ├── butterfly.v
│   │   │   └── modmul.v        mod-q multiplier (q = 3329), uses DSP slices
│   │   ├── kem/
│   │   │   ├── mlkem_top.v     keygen / encaps / decaps state machine
│   │   │   ├── cbd_sampler.v   centered binomial distribution noise sampler
│   │   │   ├── compress.v / decompress.v
│   │   │   └── fo_transform.v  Fujisaki-Okamoto re-encrypt-and-compare + implicit rejection
│   │   └── chacha_poly/
│   │       ├── chacha20.v      quarter-round core, streaming keystream generator
│   │       └── poly1305.v      MAC accumulator
│   ├── detect/
│   │   ├── cam_matcher.v       content-addressable memory, 1-cycle signature match
│   │   ├── count_min_sketch.v  fixed-size BRAM counters, k hash rows
│   │   ├── hash_functions.v    the k independent hash functions CMS needs
│   │   └── protocol_validator.v malformed header / length / flag checks
│   ├── control/
│   │   ├── session_mgr.v       per-link state: no session / handshaking / established
│   │   ├── drop_engine.v       merges lane 1 + lane 2 verdicts, reason-code counters
│   │   └── reason_codes.vh     shared enum: BAD_TAG, MALFORMED, SIGNATURE, FLOOD, ...
│   └── io/
│       ├── led_driver.v
│       └── oled_driver.v       128x32 status display
│
├── model/                      Python bit-exact reference — the oracle for everything above
│   ├── mlkem/
│   │   ├── ntt.py
│   │   ├── cbd.py
│   │   ├── pke.py               K-PKE (the encryption scheme under the KEM)
│   │   └── kem.py                keygen/encaps/decaps incl. FO transform, implicit rejection
│   ├── sha3.py                  Keccak reference (or wrap pycryptodome for cross-check only)
│   ├── chacha_poly.py
│   ├── detect.py                CAM / CMS / validator reference logic
│   └── pipeline.py              end-to-end: takes a raw packet, returns verdict + output bytes
│
├── sim/
│   ├── cocotb/                  one test dir per RTL module, mirrors rtl/ tree
│   │   ├── test_ntt.py
│   │   ├── test_mlkem_top.py
│   │   ├── test_chacha_poly.py
│   │   ├── test_cam_matcher.py
│   │   ├── test_count_min_sketch.py
│   │   └── test_drop_engine.py
│   ├── vectors/
│   │   ├── fips203_kat/         official ML-KEM-512 known-answer test vectors
│   │   └── cicids2017_subset/   attack replay pcaps, trimmed for sim speed
│   └── Makefile                 per-module cocotb+icarus/verilator invocation
│
├── test-network/
│   ├── send.py                  Device A: handshake + encrypted traffic generator
│   ├── recv.py                  Device B: verifies + prints [RX]/[DROP] lines
│   ├── attacker.py              replays CIC-IDS2017 scans/floods/tampered packets
│   └── uart_link.py             shared PySerial wrapper, 3 Mbaud framing
│
├── demo/
│   │
│   ├── run/                     ← files executed live on the day, in front of a judge
│   │   ├── demo_start.sh        opens all three terminal windows, starts send.py + recv.py
│   │   ├── demo_reset.sh        kills scripts, soft-resets FPGA session state, clears OLED, reruns
│   │   └── demo_load_bitstream.tcl  one-command Vivado burn: loads build/pqc_nids.bit via JTAG
│   │
│   ├── config/
│   │   ├── demo_config.py       single file: COM port assignments, baud rate, packet count,
│   │   │                        display refresh interval — edit once, picked up by all scripts
│   │   └── attack_sequence.json ordered list of attack types for attacker.py to replay;
│   │                             defines timing gaps so the demo narrative has breathing room
│   │
│   ├── display/
│   │   ├── oled_layout.py       defines what the 128×32 OLED shows and when it refreshes:
│   │   │                        session state, RX/DROP counters, last reason code, last src IP
│   │   └── led_map.py           maps reason codes to LED indices LD0–LD7 and blink patterns
│   │
│   ├── verify/
│   │   ├── pre_demo_checklist.py  automated go/no-go: pings FPGA over UART, checks bitstream
│   │   │                          is loaded, checks COM ports open, checks Python deps installed,
│   │   │                          prints PASS / FAIL per item — run this before the judge arrives
│   │   └── smoke_test.py          sends 10 clean packets + 5 known-attack packets, asserts
│   │                              all clean packets arrive at recv.py and all attacks are dropped;
│   │                              exits 0 = ready to demo, exits 1 = something is broken
│   │
│   ├── capture/
│   │   ├── session_log.py       timestamps and writes every [KEM]/[SEC]/[TX]/[RX]/[DROP]/[ALERT]
│   │   │                        event to demo_session_<timestamp>.log for post-demo report evidence
│   │   └── timing_capture.py    records hardware timestamps for handshake and per-packet events;
│   │                            feeds directly into the §6.3 timing table numbers in the report
│   │
│   └── README_DEMO.md           step-by-step judge-facing runbook: power sequence, which terminal
│                                 to open on which laptop, what each output line means, what to say
│                                 at each step — written so any team member can run the demo
│
├── constraints/
│   ├── zedboard_pmod.xdc        Pmod UART pin mapping (per synopsis note: NOT the onboard USB-UART)
│   └── timing.xdc               100 MHz single clock domain
│
├── scripts/
│   ├── build_bitstream.tcl      Vivado non-project-mode build (synth -> impl -> bitstream)
│   ├── run_all_sim.sh
│   └── measure_timing.py        parses Vivado reports into the numbers in §6.3 of synopsis
│
├── docs/
│   ├── interface_contract.md    packet formats, handshake protocol, register map (freeze this first)
│   └── verification_plan.md
│
└── .github/workflows/
    └── ci.yml                   lint -> Python unit tests -> cocotb sims -> KAT check, warnings=errors
```

---

## 3. The interface contract (build this before any RTL)

This is Phase I's real deliverable and it's the single highest-leverage document in the project — every module below depends on it being frozen early, and every integration bug you'll hit in Phase VI traces back to an ambiguity here.

**Internal packet bus** (between parser → lanes → drop engine): fixed-width struct, not a raw byte stream:
```
{ valid, sof, eof, data[7:0], eth_hdr, ip_hdr, tcp_udp_hdr, payload_len, session_id }
```
Both lanes read this same bus in the same cycle (Figure 1's "copied to both lanes").

**Lane → drop engine verdict interface:** each lane outputs `{fail, reason_code}` one cycle after it finishes evaluating a packet. Drop engine ORs the fail bits; reason code is whichever lane fired (define priority if both fire same cycle — e.g., security lane wins for logging clarity).

**Session register file:** per active session — session_id, 32-byte shared secret, ChaCha nonce counter, state (IDLE/HANDSHAKING/ESTABLISHED/REJECTED). This is what `session_mgr.v` owns and what `chacha_poly` and `mlkem_top` both read.

**Host-visible counters:** one counter per reason code in `reason_codes.vh`, memory-mapped or shifted out over a debug UART line for the OLED/LED driver and the CLI readout.

Freeze this file (`docs/interface_contract.md`) at the end of Phase I. Everyone builds against it independently after that.

---

## 4. Module architecture, by subsystem

### 4.1 Ingress (Phase I–II)
`uart_rx` → `deframer` (byte stream to packet boundaries) → `crc32` (drop on mismatch, this is separate from Poly1305 — it's link-layer integrity, not cryptographic) → `parser` (walks Ethernet/IPv4/TCP-UDP headers, populates the internal packet bus). This is the only serial part of the pipeline; everything downstream is parallel.

### 4.2 Lane 1 — Security (Phases IV–VI)
Build order matters here because ML-KEM is the schedule risk (synopsis §6.6 risk note):
1. `keccak_f1600` — the permutation core. Gets you SHA3-256/512 and SHAKE128/256 for free once done, since they're the same core with different padding/rate.
2. `ntt_core` + `modmul` — the arithmetic engine. Verify against `model/mlkem/ntt.py` on random polynomials before touching KEM logic at all.
3. `cbd_sampler` — noise sampling from Keccak output.
4. `mlkem_top` — wires the above into keygen/encaps/decaps state machines, then `fo_transform` for decapsulation's re-encrypt-and-compare.
5. `chacha_poly` — independent of the above, can be built in parallel by a second team member starting Phase VI. Lower risk, well-understood primitive.

Verification gate for this whole lane: **FIPS 203 KAT vectors must pass bit-exact before Phase VII starts.** Don't let timing closure work start on an unverified crypto core.

### 4.3 Lane 2 — Threat Detection (Phase III)
Independent of Lane 1 entirely — good candidate for the second pair of team members to own from day one while Lane 1 people are still on Keccak/NTT.
- `cam_matcher`: fixed-width signature table (start small — 16–32 signatures — expand once timing closes).
- `count_min_sketch`: pick k (hash rows) and width up front based on the false-positive rate you're willing to report (Objective 7 wants this as a measured number, so compute it analytically first, then confirm empirically against the CIC-IDS2017 replay).
- `protocol_validator`: pure combinational checks against the parsed header bus — malformed length fields, invalid flag combinations.

### 4.4 Control (Phase III, refined through Phase VI)
`drop_engine` is small but must be built early because both lanes' testbenches need something to report a verdict to. Build a stub version in Phase III (just OR the fail bits, no counters) and flesh out reason-code counting once `reason_codes.vh` is stable.

### 4.5 Verification harness (continuous, not a phase)
Every RTL module gets a cocotb testbench that drives it from the *same* Python model function used in `model/pipeline.py` — this is what guarantees the hardware and the "oracle" never drift apart silently. CI runs this on every push; warnings are errors (per synopsis §7.2), so nothing ambiguous merges.

---

## 5. Work division (4 people, minimizing cross-dependency)

| Owner | Track | Depends on |
|---|---|---|
| Person A | Ingress + parser + interface contract authoring | Nothing — start immediately |
| Person B | Lane 2 (detect/) entirely | Interface contract (packet bus format) |
| Person C | Keccak + NTT + CBD sampler | Interface contract (session register format) |
| Person D | ChaCha20-Poly1305 + drop engine + control | Interface contract; loosely coupled to C |

Person C's output (`mlkem_top`) is the critical path — everyone else should be able to demo their piece stand-alone (feeding it synthetic session keys) without waiting on the KEM engine finishing, which is exactly what the synopsis's fallback plan (§6.6) assumes.

---

## 6. Execution plan mapped to phases

| Phase | Weeks | Code deliverable | Exit criterion |
|---|---|---|---|
| I (done) | Aug 2026 | `interface_contract.md` frozen, `uart_rx/tx`, `deframer`, `crc32`, packet FIFO, `model/pipeline.py` skeleton, CI skeleton | Contract merged; CI runs (even if green-trivially) |
| II | Sep W1–2 | `parser.v` + `model/pipeline.py` header parsing | cocotb test: 20+ hand-crafted packets (valid + malformed) parse identically in RTL and Python |
| III | Sep W3–4 | `cam_matcher`, `count_min_sketch`, `protocol_validator`, stub `drop_engine` | Lane 2 fires correctly against a labeled CIC-IDS2017 subset; false-positive rate measured |
| IV | Oct W1–2 | `keccak_f1600`, `ntt_core`, `modmul`, `cbd_sampler` | Each passes against `model/` unit tests on random inputs, independent of full KEM |
| V | Oct W3–Nov W1 | `mlkem_top`, `fo_transform` | **FIPS 203 KAT vectors pass bit-exact, zero mismatches** |
| VI | Nov W2 | `chacha_poly`, `session_mgr`, full `drop_engine`, two lanes wired into `top.v` | Full pipeline sim: encrypted packet in → correct verdict out, both lanes exercised |
| VII | Nov W3–4 | `constraints/*.xdc`, Vivado build scripts | Timing closure at 100 MHz; utilization report matches or beats §7.3 budget |
| VIII | Dec W1–2 | `test-network/*.py`, bitstream on board, `demo/verify/smoke_test.py`, `demo/capture/timing_capture.py` | All six timing numbers in §6.3 reported from real hardware, not simulation; `smoke_test.py` exits 0 |
| IX | Dec W3 | `demo/run/`, `demo/config/`, `demo/display/`, `demo/capture/session_log.py`, `demo/README_DEMO.md` | Full demo sequence runs twice end-to-end without intervention; `pre_demo_checklist.py` exits all-PASS; any team member can operate it alone |

Each phase's exit criterion is a thing you can point to (a passing test, a report), not a vibe — that's what makes "In review" → "Complete" a real transition rather than a status update.

**On Phase IX specifically:** demo infra is a real engineering task, not decoration added the night before. The checklist script, the reset script, the session logger, and the runbook all exist to make the demo re-runnable, recoverable, and operable by whoever happens to be standing next to the board when the judge asks a second question. A demo that breaks on the second run and takes 10 minutes to recover loses marks the project earned through Phases I–VIII. Budget a full week for it.

---

## 7. Risk-driven build order (why this order, not a naive top-to-bottom read of the synopsis)

The synopsis already flags the lattice core as the schedule risk and says Phase IV comes before Phase V deliberately. This plan extends that logic one level further: **Lane 2 and ChaCha20-Poly1305 are built in parallel with Lane 1's hard sub-blocks**, not after them. That way, if the NTT/KEM work slips, you still have:
- a fully working detection lane,
- a working symmetric-crypto lane,
- a documented, testable fallback (software KEM on host, per synopsis §6.6),

which is a demonstrable project even in the worst case, and it's the same fallback the synopsis already commits to in writing — so there's no scope renegotiation needed if Phase V runs long.

---

## 8. Demo subsystem — how it connects to the rest of the repo

The `demo/` directory is not standalone — it depends on and calls into files across the repo. Understanding these connections prevents surprises during Phase IX:

```
demo/run/demo_start.sh
    └── calls test-network/send.py         (Device A terminal)
    └── calls test-network/recv.py         (Device B terminal)
    └── calls test-network/attacker.py     (Attack terminal, started manually mid-demo)

demo/config/demo_config.py
    └── imported by send.py, recv.py, attacker.py, uart_link.py
        (COM port names, baud rate, packet payloads, display refresh interval)

demo/config/attack_sequence.json
    └── read by attacker.py at runtime
        (ordered list: scan first, then flood, then tampered packet, then fake handshake)

demo/verify/smoke_test.py
    └── calls test-network/send.py and recv.py internally in a controlled sub-process
    └── asserts drop_engine counters over the UART debug line

demo/capture/session_log.py
    └── wraps around send.py and recv.py output streams, tee's to a timestamped log file
    └── log file becomes evidence in the final report's §7 (measured figures)

demo/capture/timing_capture.py
    └── reads hardware-side timestamps from the FPGA's debug counter output over UART
    └── formats them into the §6.3 table structure directly

demo/display/oled_layout.py + led_map.py
    └── these are the Python-side definitions that MUST match rtl/io/oled_driver.v
        and rtl/io/led_driver.v exactly — if the RTL display format changes, both
        sides update in the same commit; they cannot drift independently
```

**Ownership:** `demo/` is shared infrastructure — no single member owns it, everyone can break it. Treat it like `scripts/` and `ci.yml`: any change gets a PR, and whoever is doing Phase IX integration should be the person who knows the whole pipeline end-to-end, which by that point should be you (Member C, as technical lead).

---

## 9. First concrete next actions

1. Write and merge `docs/interface_contract.md` — packet bus struct, verdict interface, session register layout, reason-code enum. Everything else blocks on this.
2. Stand up `model/pipeline.py` as a pass-through stub (parses a packet, always returns PASS) so cocotb testbenches have something to import from day one.
3. Get GitHub Actions running end-to-end on a trivial module (e.g. `crc32.v`) so the CI path — Verilog lint → cocotb → pass/fail — is proven before anyone's blocked waiting on it.
4. Assign the four tracks in §5 and start Person A and Person B immediately; Person C starts on Keccak (no dependency on the contract's session-register section, only the general repo layout).
5. Create the `demo/` skeleton with empty files and `demo/config/demo_config.py` stubs — this costs 10 minutes now and means Phase IX doesn't start from blank files under time pressure.

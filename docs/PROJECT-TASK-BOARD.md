# PQC-NIDS Project Task Board

**Updated:** 11 Oct 2026 · branch `member-c/integration`
**Owner:** Aakash (sole engineer from here to submission)

---

## Where the project actually is

**Every module is built, and they are now wired together and working.**
`sim/cocotb/test_pqc_nids_top.py` drives serial bits into the real synthesis
target and verifies the full chain: startup KeyGen on the real `mlkem_top`, an
800-byte encapsulation key in over the link, Encaps, the 768-byte ciphertext
transmitted back in a correctly framed packet, **both sides deriving the same
shared secret**, then a clean encrypted packet forwarded, a signature in the
decrypted plaintext caught, and a tampered tag caught.

| | State |
|---|---|
| Top-level synthesis target | `rtl/top/pqc_nids_top.v`, 37 RTL files |
| Verilator `-Wall`, whole design as one unit | 0 warnings |
| `pytest sim/cocotb` | 41 module/seam suites, all passing |
| Preflight gate | passes (see `scripts/preflight.py`) |
| Synthesis / timing / bitstream | **never run — this is the gate** |
| Hardware bring-up | not started |
| Demo | **needs decisions before it can be built — see below** |

Everything from here is Phases VII–IX: synthesis, the board, and the demo. The
honest summary of risk is that **no resource or timing figure in this repository
has been produced by a synthesis tool yet**, so the first Vivado run is the step
that can still surprise us.

---

## Phase VII — synthesis and timing closure

Ordered. `S1` gates everything after it, so do not reorder.

| # | Task | Why it blocks | Notes |
|---|---|---|---|
| `S1` | **Verify the XDC pin assignments against the ZedBoard master XDC** | A wrong `IOSTANDARD` is a DRC failure, and a wrong pin drives nothing. Costs a whole build cycle to discover | `constraints/pqc_nids.xdc` carries the standard values and says plainly they are unverified. Check `clk` (Y9), `btn_rst` (P16), the 8 LEDs, and above all which Pmod header the USB-UART is physically in — the file assumes JA |
| `S2` | **Run `vivado -mode batch -source scripts/build_bitstream.tcl`** | The first real numbers in the project. Produces `build/reports/utilization.rpt`, `timing_summary.rpt` and `timing_worst_paths.rpt`, and exits non-zero if timing does not close | Expect it to take 20–40 minutes. The script already writes every report the final document needs |
| `S3` | **Fix whatever timing actually fails** | 100 MHz is the design's stated clock; the demo's latency claims rest on it | The review names two likely paths, both in `poly1305.v`: the 131×64 multiply at `:299` and the four chained ~130-bit carry chains in `S_REDUCE`. Standard fixes are the five-limb 26-bit decomposition and splitting `S_REDUCE` across two states. **Do not pre-emptively pipeline** — let `timing_worst_paths.rpt` name the paths. `hash_functions.v`'s nine cascaded constant multiplies are the other candidate |
| `S4` | **Check utilisation against the budget** | The synopsis budgets ≈8 DSP48E1 and ≈140 BRAM36 | `hash_functions.v` may map to ~34 DSPs if Vivado infers them; if so, pipeline it or force `use_dsp = no`. `poly1305` will take DSPs too. This is a real possibility, not a formality |
| `S5` | **Re-run the full cocotb suite after any S3/S4 change** | Pipelining changes latency, and several tests assert exact cycle counts | `pytest sim/cocotb` — about 27 minutes |

---

## Phase VIII — the board

| # | Task | Why it blocks | Notes |
|---|---|---|---|
| `H1` | **Flash the bitstream** | Nothing below can start | `vivado -mode batch -source demo/run/demo_load_bitstream.tcl`, which now has a real `build/pqc_nids.bit` to load |
| `H2` | **Prove the serial link in isolation** | If the UART does not work, every later symptom is misleading | After reset the board transmits a telemetry frame every 250 ms whether or not anything is talking to it. `python test-network/recv.py --port COMx` should immediately show counters at zero and a `down` session. This is the cheapest possible first hardware test |
| `H3` | **Prove the handshake on real silicon** | The one step simulation cannot fully stand in for | `python test-network/send.py --port COMx`. It prints `[KEM] handshake complete` and the derived secret. LD0 should go solid |
| `H4` | **Run `demo/verify/smoke_test.py`** | It is the go/no-go gate, and it drives every attack class itself | Checks the handshake, that both sides derived the same secret, clean forwarding, and each of the eight reason codes. Also checks `cnt_lane_timeout` and `cnt_stray_verdict` are zero, which is how you find an integration problem the simulation missed |
| `H5` | **Measure the real latencies for §6.3** | The report's timing table | Cycle counts are measured (`docs/Member C/Member-C-KEM-Cycle-Counts.md`); what is missing is the wall-clock confirmation at the achieved clock, plus the end-to-end handshake time, which `send.py` already prints |

---

## Phase IX — the demo

**This needs a design conversation before any of it is built.** The scripts
exist (`test-network/send.py`, `recv.py`, `attacker.py`, `demo/verify/smoke_test.py`)
and the board's side is finished, but the demo as sketched in
`demo/config/demo_config.py` assumes a topology the hardware does not have.

### The blocking conflict

`demo_config.py` names four serial ports — sender, receiver, attacker and a
separate FPGA debug readout. **The board has one UART in and one UART out.**
`rtl/top/pqc_nids_top.v` has a single `uart_rx_pin` and a single `uart_tx_pin`,
and the transmitter is already shared between the ciphertext reply and the
telemetry stream (`handshake_tx` has priority, `telemetry_tx` fills the gaps).

Two consequences:

1. **The sender and the attacker cannot both be wired to `uart_rx_pin`.** Two
   drivers on one line is an electrical conflict, not a software problem.
2. **Telemetry and the ciphertext reply arrive on the same host port.** `recv.py`
   currently assumes a dedicated debug port. The frames are trivially
   distinguishable — telemetry is 52 bytes starting `A5 5A` with a checksum,
   the reply is 816 bytes starting with its own length — but one process has to
   demultiplex them.

> **Decided 11 Oct (see `docs/DEMO-PLAN.md`):** D1 second UART + arbiter, D4 keep OLED, D2 separate scripts - which together require a third UART link for telemetry. The table below is the original option list.

### The decisions to make

| # | Decision | Options | My recommendation |
|---|---|---|---|
| `D1` | **How does the attacker reach the board?** | (a) one host, one port, `send.py` and `attacker.py` time-multiplexed as separate processes; (b) a second Pmod USB-UART plus a second `uart_rx` and an arbiter in RTL; (c) an external TTL mux | **(a) for the first working demo**, because it needs no new RTL and no new hardware. If there is time after `H4` passes, (b) is a stronger story — a genuinely separate third device — and the RTL is maybe 80 lines. Decide this before building the demo script, because it changes the narration |
| `D2` | **One host process or two?** | (a) one process that sends, demultiplexes the reply, and renders telemetry; (b) two processes sharing the port via a small broker | **(a)**. Merge `recv.py`'s renderer into `send.py`'s loop, or have `recv.py` take over the port and expose the handshake bytes. Sharing one serial port between two OS processes is a reliable way to lose bytes on the day |
| `D3` | **What does the audience actually look at?** | LEDs, the host console, or both | Both. LD0–LD7 are live and mapped (`rtl/io/led_driver.v`, in lockstep with `demo/display/led_map.py`). The console gives the reason codes and counts |
| `D4` | **Keep or drop the OLED?** | `demo/display/oled_layout.py` exists but there is **no OLED RTL and no OLED on the pin list** | **Drop it**, and delete the Python so the repo stops implying a feature that does not exist. The LEDs plus the console already cover the "nothing is silently lost" requirement |
| `D5` | **Demo sequence and timing** | — | Needs writing: order of attacks, how long each dwells so the audience sees the LED, what the narration says at each step, and what to do if a step fails live |
| `D6` | **What gets rehearsed, and how many times** | — | At minimum: a full clean run, and one deliberate failure you can recover from on camera |

### Then build it

| # | Task | Notes |
|---|---|---|
| `X1` | Resolve `D1`–`D4`, and if `D1` picks (b), build the second ingress path | Blocks everything else here |
| `X2` | Write the demo runner that implements `D5` | A single script that sequences the whole walkthrough, so the live run is one command rather than a person typing under pressure |
| `X3` | Wire `demo/capture/session_log.py` into it | It already timestamps `[KEM]`/`[SEC]`/`[TX]`/`[RX]`/`[DROP]`/`[ALERT]`, and `send.py`/`recv.py`/`attacker.py` already print in that format. The log is the evidence behind the report's figures |
| `X4` | Update `demo/verify/pre_demo_checklist.py` for the real topology | It still assumes the four-port layout |
| `X5` | Rehearse `D6` | — |

---

## Phase IX — the report

| # | Task | Notes |
|---|---|---|
| `R1` | Fill the §6.3 timing table from `S2`'s reports and `H5`'s measurements | Replace the `opcount.py` lower bounds, which are 3.7–4.0× optimistic. Measured cycle counts are in `docs/Member C/Member-C-KEM-Cycle-Counts.md` |
| `R2` | Fill the resource table from `build/reports/utilization.rpt` | Every figure currently in an RTL header is an estimate and labelled as one |
| `R3` | Write up the integration findings | `docs/INTEGRATION-READINESS-REVIEW.md` is the raw material: it records each defect's mechanism, how it was measured, and how it was closed. The honest version of this project's story is that per-module verification was excellent and cross-module verification did not exist until the seam tests were written |
| `R4` | State the entropy source honestly | `rtl/control/entropy_src.v` is a DRBG stirred with UART arrival jitter, **not a TRNG**. Its header says what it is and is not good for, and it has a seed-load port for the Zynq PS's hardware RNG. Do not call it a TRNG |
| `R5` | State the known limitations | `RC_SCAN` detects vertical port scans but misclassifies horizontal IP sweeps, because `dst_ip` never reaches the hash; the CMS does not count packets during its 2048-clock epoch sweep; the `dk` hash check (FIPS 203 §7.3) is model-only by design |

---

## The chain that gates everything

```
S1 (verify pins) -> S2 (synthesis) -> S3/S4 (fix timing and area) -> S5 (re-test)
                                   -> H1 (flash) -> H2 (link) -> H3 (handshake)
                                   -> H4 (smoke test)
D1..D4 (demo decisions) -> X1 -> X2 -> X3 -> X5 (rehearse)
S2, H5 -> R1, R2
```

`S2` is the single highest-value action left. Until it runs, the project's risk
is unmeasured: everything else is either verified in simulation or waiting on a
number only Vivado can produce.

`D1`–`D4` can be decided in parallel with `S1`/`S2` — they need a conversation,
not a toolchain.

---

## Project / shared — Phase I foundations, currently unowned

Nobody's guide claims these, which is why none of them exist. Assign them.

- [x] `P1` Stand up CI — lint → Python tests → cocotb → KAT, warnings as errors · `.github/workflows/ci.yml` · **Phase I exit**
- [x] `P2` `model/pipeline.py` pass-through stub so cocotb has something to import
- [x] `P4` Declare Phase I genuinely closed · **Phase I exit** · completed with contract freeze `A1`

---

## Member A — ingress, parser, interface contract · Phase I–II

> Guide: `docs/Member A/Member-A-Ingress-and-Interface-Contract.md`
> **You block everyone.** Eleven downstream tasks wait on `A1`.

- [x] `A2` Apply Member C's confirmations to §1, §3, §4, §5, §6 · adopted into contract v1.0.0
- [x] `A3` Replace `HANDSHAKE_REJECT` with `HANDSHAKE_KEY_INVALID`, add the no-verdict rule · adopted into contract v1.0.0
- [x] `A4` Decide handshake message direction — `packet_type` `2'b10` for ciphertext · Option A locked
- [x] `A5` Fix port numbers (handshake-init 51001 / handshake-resp 51002 / data 51010) · locked in §4
- [x] `A6` Review and adopt `rtl/control/reason_codes.vh` (drafted by C) · adopted and signed off
- [x] `A7` Strobe-based drop-engine sync (latency-agnostic by construction) + target latencies · locked in §6
- [x] `A1` **Freeze `interface_contract.md`** — v1.0.0 locked · **Phase I exit**
- [x] `A8` `uart_rx.v` / `uart_tx.v` at 3 Mbaud against 100 MHz · completed and verified
- [x] `A9` `crc32.v`, verified bit-for-bit against `zlib.crc32`
- [x] `A10` `deframer.v` — multi-packet, truncation, min/max length · completed and verified
- [x] `A12` `model/pipeline.py` header-parsing function (the parser's oracle) · unblocked by `A1` · unblocks `B6`, `A11`
- [x] `A11` `parser.v` — Ethernet → IPv4 → TCP/UDP onto the packet bus · **Phase II exit** · unblocked by `A12`
- [x] `A13` cocotb: 20+ packets incl. malformed, RTL ≡ Python · **Phase II exit** · verified bit-for-bit against model/pipeline.py

**Note on `A10`:** Member C requires the *complete* handshake payload before `eof` — a truncated
payload presented as complete is worse than a `FRAME_TIMEOUT`. This is now a hard requirement from a
consuming module, not a preference.

---

## Member B — Lane 2, threat detection · Phase III

> Guide: `docs/Member B/Member-B-Threat-Detection-Lane.md`
> `B7` and `B9` depend on nothing in the crypto lane. `B8` now does — see the v1.1.0 note at the
> top of this file. Four of your tasks are startable today.

- [x] `B2` Decide FLOOD/SCAN — separate codes `RC_FLOOD` (4'h5) and `RC_SCAN` (4'h6) adopted in reason_codes.vh & contract v1.0.0; distinction modeled in model/detect.py
- [x] `B3` Give A the `count_min_sketch.v` verdict latency · 2 cycles after eof, drop engine strobe-based in contract §6
- [x] `B5` CMS sizing on paper — dual-sketch (flow w=2048, host w=1024, k=4), 6.0/11.5 BRAM36 tiles (52.2%), analytical bound & noise floor verified in model/detect.py
- [x] `B10` Curate labeled `sim/vectors/cicids2017_subset/` · 4 traces (1,220 packets), labels.json oracle & SHA-256 manifest
- [x] `B1` Read and sign off the interface contract · signed off v1.1.0 (packet bus headers + §3.1 plaintext stream)
- [x] `B4` Confirm the handshake port sits inside the CMS monitored space · confirmed (ports 51001/51002 keyed by flow 5-tuple)
- [x] `B6` `model/detect.py` — validator, CAM and CMS reference + 800-flow collision test landed (commit 70ddb03)
- [x] `B7` `protocol_validator.v` — combinational header checks (Rules 1–6) complete
- [x] `B8` `cam_matcher.v` — 16–32 signatures, 1-cycle match, **reads plaintext stream (contract §3.1), not the packet bus** · 16 canonical threat signatures verified bit-exact vs model/detect.py & signature.pcap (4 cocotb tests pass)
- [x] `B9` `count_min_sketch.v` + `hash_functions.v` · dual-sketch BRAM pipeline verified bit-exact vs model/detect.py (8 cocotb tests pass)
- [x] `B11` Measure false-positive rate on replay vs analytical bound · **Phase III exit** · 0.0% FPR, empirical error strictly bounded by (eps, delta), documented in docs/Member B/cms_accuracy_report.md
- [x] `B12` All three detectors emit `{fail, reason_code}` per contract · **Phase III exit** · verified via `sim/cocotb/test_lane2_drop_engine.py` (5 cocotb tests pass against drop_engine.v)

**On `B4`:** a fixed handshake port is trivially floodable, and that's your lane, not C's. If your
sketch only keys on `(src_ip, dst_ip)` and not `(src_ip, dst_port)`, a flood aimed at the handshake
port is invisible to you. One-line confirmation, but it needs to be explicit.

---

## Member C — Lane 1, Keccak / NTT / ML-KEM-512 · Phase IV–V

> Guide: `docs/Member C/Member-C-ML-KEM-Crypto-Core.md`
> Python oracle complete and KAT-clean. Not blocked by anyone.

- [x] `C1` `model/mlkem/` Python reference — ntt, cbd, pke, kem
- [x] `C2` FIPS 203 KAT bit-exact — **80/80, zero skips** · `python model/mlkem/kat_test.py`
- [x] `C3` FIPS 203 §7.2/§7.3 input validation — ek canonicality, dk hash check
- [x] `C4` Operation counts + cycle estimates for the §6.3 table · `python model/mlkem/opcount.py`
- [x] `C5` Interface response to Member A
- [x] `C6` Contract freeze package + draft `rtl/control/reason_codes.vh`
- [x] `C7` Push and merge `member-c/python-oracle` into `main` — PR #1 merged, branch deleted
- [x] `C8` `keccak_f1600.v` + `shake_wrapper.v` — iterative 25-cycle Keccak-f[1600] and multi-mode 64-bit sponge wrapper · verified clean Verilator lint
- [x] `C9` `test_keccak_f1600.py` + `test_shake_wrapper.py` vs `model/sha3.py` (cocotb) · 100% green in CI
- [x] `C9b` FIPS 202 KAT through RTL (334 NIST CAVP vectors: SHA3-256, SHA3-512, SHAKE128, SHAKE256 ShortMsg/LongMsg/VariableOut) · **Phase IV exit**
- [x] `C10` `ntt_core.v` / `butterfly.v` / `modmul.v` within the ≈8 DSP budget (1 DSP48E1, 1 BU, 1,192 fwd / 1,195 inv cycles, 0 lint warnings)
- [x] `C10b` `poly_mul_acc.v` — pointwise multiplication (base_case_multiply mod X^2 - gamma) and accumulation for matrix-vector products (1 DSP48E1, 2,049 cycles measured, 0 lint warnings; pair interleaving recorded as known optimisation)
- [x] `C11` `test_ntt.py` + `test_modmul.py` + `test_poly_mul_acc.py` — bit-exact vs `model/mlkem/ntt.py` & `model/mlkem/pke.py` (cocotb) · **Phase IV exit**
- [x] `C12` `cbd_sampler.v`, verified incl. seed handling (dual-window ping-pong, eta1=3 & eta2=2, 259/261 cycles measured, bit-exact vs model/mlkem/pke.py & FIPS 203 KAT) · **Phase IV exit**
- [x] `C13` `compress.v` / `decompress.v` — streaming datapath for d in {1, 4, 10} (CSD shift-add, L=3/L=1 cycles, 0 DSP, bit-exact vs model/mlkem/pke.py) · **Phase IV exit**
- [x] `C13b` `byte_encode.v` / `byte_decode.v` — bit packing/unpacking for d in {1, 4, 10, 12} (u, v, message, and uncompressed coefficients/keys; 256 cycles/poly, valid/ready 64-bit word stream) · **Phase IV exit**
- [x] `C13c` `pack_8_to_64.v` — 8-bit ek/dk/ciphertext source -> 64-bit words · bridges byte-wide packet bus to `byte_decode.v`
- [x] `C13d` `sample_ntt.v` — SHAKE128 rejection sampler for matrix Â (FIPS 203 Alg. 7, 12-bit candidates mod q) · verified clean Verilator lint and cocotb bit-exact
- [x] `C13e` `poly_add_sub.v` — coefficient-wise modular add/sub mod q=3329 (autonomous 256-coeff sequencer, 259 cycles/poly, bit-exact mod 3329) · unblocks `C14`
- [x] `C14` `mlkem_top.v` — keygen / encaps / decaps state machines, packet-bus ingest, separate `ek_ram`, `rng_*` entropy handshake (PRs #17, #18, #19; 14 cocotb tests, verilator -Wall clean)
- [ ] `C15` `fo_transform.v` — structural signals, cryptographic stays silent · behaviour is implemented and verified inside `mlkem_top.v` (constant-time compare + select, no verdict); there is no separate `fo_transform.v`. Tick once the owner accepts that, or split the module out
- [x] `C16` FIPS 203 KAT through `mlkem_top.v` — zero unexplained mismatches · **PHASE V HARD GATE** · `test_mlkem_kat_full.py`: KeyGen 25/25, Encaps 25/25, ek check 10/10, Decaps 10/10 (incl. implicit rejection). The `dk` hash check (tgId 7) is model-only by design: the device never imports a `dk`
- [x] `C17` Joint Seam-2 indistinguishability test with D · **Phase VI exit** · `test_seam2_kem_session.py` drives real `mlkem_top.v` into real `session_mgr.v`; authentic vs rejected waveform identical per cycle; `scripts/mutation_check_seam2.py` proves it catches a timing leak and a verdict leak. Member D has not yet reviewed it
- [x] `C18` Log measured keygen/encaps/decaps cycle counts for §6.3 · KeyGen 17,640–17,669, Encaps 24,022–24,049, Decaps 33,786–33,814 cycles (pre-synthesis; see `docs/Member C/Member-C-KEM-Cycle-Counts.md`)

**Measured, for whoever needs the numbers** (`model/mlkem/opcount.py`):

| Operation | Keccak-f1600 | NTT | INTT | base-case mult | ≈ cycles | @100 MHz |
|---|---:|---:|---:|---:|---:|---:|
| KeyGen | 31 | 4 | 0 | 512 | 4,800 | 48 µs |
| Encaps | 30 | 2 | 3 | 768 | 6,000 | 60 µs |
| Decaps | 30 | 4 | 4 | 1,024 | 8,900 | 89 µs |

Lower bounds — no control/memory overhead. At 3 Mbaud, receiving the 768-byte ciphertext takes
≈2.56 ms, so **the handshake is UART-bound by roughly 30×**. The crypto lane is not the latency risk.

---

## Member D — ChaCha20-Poly1305, drop engine, control · Phase III–VI

> Guide: `docs/Member D/Member-D-ChaCha-Poly-and-Control.md`
> `chacha20`/`poly1305` depend on nothing — biggest chance to bank progress early.
> **New in v1.1.0:** `chacha20.v` must expose the §3.1 plaintext ports, and Member B's `B8` is
> blocked until you agree those port names with them. Agreeing the names is a five-minute
> conversation and doesn't require your RTL to exist — do it now, not when `D4` finishes.

- [x] `D3` Check proposed port numbers against test traffic, agree with A · blocks `A5` → blocks `A1`
- [x] `D4` `chacha20.v` — quarter-round core, RFC 8439 vectors, **plus the §3.1 plaintext output ports** · **Phase III exit** · **unblocks `B8`**
- [x] `D6` `model/chacha_poly.py` reference for streaming behaviour
- [x] `D7` `drop_engine.v` **stub** — just OR the fail bits · **Phase III exit** · **unblocks `B12`**
- [x] `D5` `poly1305.v` — MAC accumulator, RFC 8439 vectors · **Phase III exit** · ⛔ waiting on `D4`
- [x] `D2` Give A the `poly1305.v` verdict latency · blocks `A7` → blocks `A1` · ⛔ waiting on `D5`
- [x] `D1` Read and sign off the interface contract · ⛔ waiting on `A2`, `A3`, `A4`
- [x] `D8` `session_mgr.v` — write path blind to rejection · ⛔ waiting on `C6`, `A6`
- [x] `D10` Document the priority rule for same-cycle failures from both lanes · ⛔ waiting on `A7`
- [x] `D11` `chacha_poly` verified on sustained multi-packet streams · **Phase VI exit** · ⛔ waiting on `D5`, `D6`
- [x] `D9` `drop_engine.v` full — per-reason counters, sub-µs, nothing silent, **§6 telemetry exception (BAD_TAG suppresses the SIGNATURE count)** · **Phase VI exit** · ⛔ waiting on `A6`, `A7`, `B12`
- [ ] `D12` Wire counters to the host-visible LED/OLED interface · ⛔ waiting on `D9`

**Two hard requirements on `D8`, from Member C:**

1. `mlkem_top.v` writes the shared secret on the **same cycle** whether the handshake was genuine or
   implicitly rejected. `session_mgr.v` must not branch on which — it cannot be told. If your state
   machine has any conditional on the write path, it comes out.
2. `state = REJECTED (2'b11)` is reachable **only** from `HANDSHAKE_KEY_INVALID`. Wiring `REJECTED`
   to the FO transform reintroduces exactly the leak the §6 correction removes.

Signal list is specified in `Member-C-Contract-Freeze-Package.md` §5 — `kem_done`, `kem_session_id`,
`kem_shared_secret`, `kem_key_invalid`, plus the signals that deliberately do not exist.

---

## The chain that gates everything

```
D3 ─┐
    ├─→ A5 ─┐
B3 ─┼──────►├─→ A7 ─┐
D2 ─┘       │       ├─→ A1  (freeze contract)  ─┬─→ B1 → B7, B8, B9 → B12 → D9
A2, A3, A4 ─┴───────┘                          ├─→ D1
                                               ├─→ A10, A12 → A11 → A13
                                               └─→ P4  (Phase I closed)
```

Four small acts — `D3`, `B3`, `D2`, and A applying edits already written for them — collapse this
whole chain. None of them is a day's work.

---

*Task state is edited by hand in this file. Measured figures reproduce from the repo root with*
*`python model/mlkem/kat_test.py` and `python model/mlkem/opcount.py`.*

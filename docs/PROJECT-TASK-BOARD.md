# PQC-NIDS Project Task Board

**Repo:** `pqc-nids-fpga` — ML-KEM-512 inline crypto engine + threat detection, ZedBoard XC7Z020
**Derived from:** each member's master guide in `docs/Member A|B|C|D/` and the phase table in
`docs/PQC-NIDS-Architecture-and-Execution-Plan.md` §6.

**How to use this file.** Tick your own boxes and commit. Blocking is written as
`⛔ waiting on X1, X2` — if the tasks it names aren't ticked, you can't start. When you finish
something that unblocks someone, say so in the commit message so they see it.

**Status marks:** `[ ]` not started · `[~]` in progress · `[x]` done

---

## Where the project actually is — 12 Sep 2026

The phase plan puts us in **Phase II (Sep W1–2)**. Repo state:

| | Plan says | Repo says |
|---|---|---|
| Phase I | done | **CLOSED** — contract FROZEN v1.0.0 (`A1`), CI (`P1`), `pipeline.py` (`P2`), demo skeleton (`P3`) |
| Phase II | due now | in progress — `interface_contract.md` frozen, ingress RTL unblocked |
| Phase III | Sep W3–4 | unblocked — Member B and D unblocked by contract freeze |
| Phase IV–V | Oct–Nov | **Member C's Python oracle merged to main, KAT 80/80** |
| Phase IX | Dec W3 | `demo/` skeleton landed early — config, display and checklist run today |

`A1` — freezing the interface contract — is **DONE**. Phase I is formally closed (`P4`).
The contract is frozen at v1.0.0 with Member C's FIPS 203 corrections and Member D's
strobe-based latency-agnostic drop-engine synchronization.

All downstream tasks previously blocked by `A1` (`B1`, `D1`, `A10`, `A12`) are now unblocked.
Critical path is now active across all three lanes:
- Member A: `A8` (UART 3 Mbaud), `A9` (CRC32), `A10` (deframer), `A12` (`pipeline.py` parser oracle)
- Member B: `B1` sign-off, `B7` (`protocol_validator.v`), `B8` (`cam_matcher.v`), `B9` (`count_min_sketch.v`)
- Member D: `D1` sign-off, `D4` (`chacha20.v`), `D7` (`drop_engine.v` stub)

---

## Ready to start right now

Nothing is stopping any of these. If you own one, there is no reason it isn't moving today.

| Task | Owner | What |
|---|---|---|
| `A2` | A | Apply Member C's confirmations to §1, §3, §4, §5, §6 |
| `A3` | A | Replace `HANDSHAKE_REJECT` → `HANDSHAKE_KEY_INVALID`, add the no-verdict rule |
| `A4` | A | Decide handshake message direction (`packet_type` `2'b10` for ciphertext) |
| `A8` | A | `uart_rx.v` / `uart_tx.v` at 3 Mbaud |
| `A9` | A | `crc32.v` vs `zlib.crc32` |
| `B2` | B | FLOOD/SCAN — separate codes or one, tell A |
| `B3` | B | CMS verdict latency → A |
| `B5` | B | CMS sizing: k, w, (ε,δ) against ≈11.5 of 140 BRAMs |
| `B10` | B | Curate labeled `cicids2017_subset/` |
| `C8` | C | `keccak_f1600.v` — first RTL of the crypto lane |
| `C10` | C | `ntt_core.v` / `butterfly.v` / `modmul.v` |
| `D3` | D | Check port numbers against test traffic, agree with A |
| `D4` | D | `chacha20.v` + RFC 8439 vectors |
| `D6` | D | `model/chacha_poly.py` |
| `D7` | D | `drop_engine.v` stub — **unblocks B's testbenches** |

**`D7` is the highest-value one left here** — the drop-engine stub is an afternoon's work and it
unblocks `B12`. `C8`/`C10` are now unblocked too, since `C7` merged.

Landed since this board was written: `P1` (CI), `P2` (`model/pipeline.py`), `P3` (`demo/` skeleton),
`C7` (merge).

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
- [ ] `A8` `uart_rx.v` / `uart_tx.v` at 3 Mbaud against 100 MHz
- [ ] `A9` `crc32.v`, verified bit-for-bit against `zlib.crc32`
- [ ] `A10` `deframer.v` — multi-packet, truncation, min/max length · unblocked by `A1`
- [ ] `A12` `model/pipeline.py` header-parsing function (the parser's oracle) · unblocked by `A1`
- [ ] `A11` `parser.v` — Ethernet → IPv4 → TCP/UDP onto the packet bus · **Phase II exit** · ⛔ waiting on `A12`
- [ ] `A13` cocotb: 20+ packets incl. malformed, RTL ≡ Python · **Phase II exit** · ⛔ waiting on `A11`

**Note on `A10`:** Member C requires the *complete* handshake payload before `eof` — a truncated
payload presented as complete is worse than a `FRAME_TIMEOUT`. This is now a hard requirement from a
consuming module, not a preference.

---

## Member B — Lane 2, threat detection · Phase III

> Guide: `docs/Member B/Member-B-Threat-Detection-Lane.md`
> You depend on nothing in the crypto lane. Four of your tasks are startable today.

- [ ] `B2` Decide FLOOD/SCAN — separate codes or one `VOLUMETRIC` — and tell A · blocks `A7`
- [ ] `B3` Give A the `count_min_sketch.v` verdict latency · blocks `A7` → blocks `A1`
- [ ] `B5` CMS sizing on paper — k, w, (ε,δ) bound against ≈11.5 of 140 BRAMs
- [ ] `B10` Curate labeled `sim/vectors/cicids2017_subset/`
- [ ] `B1` Read and sign off the interface contract · ⛔ waiting on `A2`, `A3`, `A4`
- [ ] `B4` Confirm the handshake port sits inside the CMS monitored space · ⛔ waiting on `A5`
- [ ] `B6` `model/detect.py` — validator, CAM and CMS reference · ⛔ waiting on `A12`
- [ ] `B7` `protocol_validator.v` — combinational header checks · ⛔ waiting on `B1`, `B6`
- [ ] `B8` `cam_matcher.v` — 16–32 signatures, 1-cycle match · ⛔ waiting on `B1`, `B6`
- [ ] `B9` `count_min_sketch.v` + `hash_functions.v` · ⛔ waiting on `B5`, `B6`
- [ ] `B11` Measure false-positive rate on replay vs analytical bound · **Phase III exit** · ⛔ waiting on `B9`, `B10`
- [ ] `B12` All three detectors emit `{fail, reason_code}` per contract · **Phase III exit** · ⛔ waiting on `B7`, `B8`, `B9`, `D7`

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
- [ ] `C8` `keccak_f1600.v` + `shake_wrapper.v` — decide unrolled vs iterative rounds 
- [ ] `C9` `test_keccak.py` vs `model/sha3.py`, then FIPS 202 KAT through RTL · **Phase IV exit** · ⛔ waiting on `C8`
- [ ] `C10` `ntt_core.v` / `butterfly.v` / `modmul.v` within the ≈8 DSP budget 
- [ ] `C11` `test_ntt.py` — hundreds of random polys, forward∘inverse = identity · **Phase IV exit** · ⛔ waiting on `C10`
- [ ] `C12` `cbd_sampler.v`, verified incl. seed handling · **Phase IV exit** · ⛔ waiting on `C9`
- [ ] `C13` `compress.v` / `decompress.v` · ⛔ waiting on `C10`
- [ ] `C14` `mlkem_top.v` — keygen / encaps / decaps state machines · ⛔ waiting on `C11`, `C12`, `C13`, `A6`
- [ ] `C15` `fo_transform.v` — structural signals, cryptographic stays silent · ⛔ waiting on `C14`
- [ ] `C16` FIPS 203 KAT through `mlkem_top.v` — zero unexplained mismatches · **PHASE V HARD GATE** · ⛔ waiting on `C15`
- [ ] `C17` Joint Seam-2 indistinguishability test with D · **Phase VI exit** · ⛔ waiting on `C15`, `D8`
- [ ] `C18` Log measured keygen/encaps/decaps cycle counts for §6.3 · ⛔ waiting on `C16`

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

- [ ] `D3` Check proposed port numbers against test traffic, agree with A · blocks `A5` → blocks `A1`
- [ ] `D4` `chacha20.v` — quarter-round core, RFC 8439 vectors · **Phase III exit**
- [ ] `D6` `model/chacha_poly.py` reference for streaming behaviour
- [ ] `D7` `drop_engine.v` **stub** — just OR the fail bits · **Phase III exit** · **unblocks `B12`**
- [ ] `D5` `poly1305.v` — MAC accumulator, RFC 8439 vectors · **Phase III exit** · ⛔ waiting on `D4`
- [ ] `D2` Give A the `poly1305.v` verdict latency · blocks `A7` → blocks `A1` · ⛔ waiting on `D5`
- [ ] `D1` Read and sign off the interface contract · ⛔ waiting on `A2`, `A3`, `A4`
- [ ] `D8` `session_mgr.v` — write path blind to rejection · ⛔ waiting on `C6`, `A6`
- [ ] `D10` Document the priority rule for same-cycle failures from both lanes · ⛔ waiting on `A7`
- [ ] `D11` `chacha_poly` verified on sustained multi-packet streams · **Phase VI exit** · ⛔ waiting on `D5`, `D6`
- [ ] `D9` `drop_engine.v` full — per-reason counters, sub-µs, nothing silent · **Phase VI exit** · ⛔ waiting on `A6`, `A7`, `B12`
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

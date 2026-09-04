# PQC-NIDS Project Task Board

**Repo:** `pqc-nids-fpga` — ML-KEM-512 inline crypto engine + threat detection, ZedBoard XC7Z020
**Derived from:** each member's master guide in `docs/Member A|B|C|D/` and the phase table in
`docs/PQC-NIDS-Architecture-and-Execution-Plan.md` §6.

**How to use this file.** Tick your own boxes and commit. Blocking is written as
`⛔ waiting on X1, X2` — if the tasks it names aren't ticked, you can't start. When you finish
something that unblocks someone, say so in the commit message so they see it.

**Status marks:** `[ ]` not started · `[~]` in progress · `[x]` done

---

## Where the project actually is — 04 Sep 2026

The phase plan puts us in **Phase II (Sep W1–2)**. Repo state says otherwise:

| | Plan says | Repo says |
|---|---|---|
| Phase I | done | **not done** — contract is DRAFT, no CI, no `model/pipeline.py` |
| Phase II | due now | not started — no `parser.v` |
| Phase III | Sep W3–4 | not started |
| Phase IV–V | Oct–Nov | **Member C's Python oracle complete, KAT 80/80** |

Only Member C has pushed anything. `rtl/`, `sim/cocotb/`, `scripts/`, `constraints/`,
`test-network/` and `.github/workflows/` contain nothing but `.gitkeep`. `demo/` doesn't exist.

**The single highest-leverage item in the whole repo right now is `A1` — freezing the interface
contract.** Eleven tasks across B, C and D are waiting on it, directly or transitively. It has been
the blocker since Phase I and it is still the blocker.

**Member C is roughly six weeks ahead of the calendar and is the only track not blocked by anything.**
That is the opposite of the plan's assumption (§5: "Person C's output is the critical path"). The
critical path has moved to Member A.

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
| `C7` | C | Push + merge `member-c/python-oracle` |
| `D3` | D | Check port numbers against test traffic, agree with A |
| `D4` | D | `chacha20.v` + RFC 8439 vectors |
| `D6` | D | `model/chacha_poly.py` |
| `D7` | D | `drop_engine.v` stub — **unblocks B's testbenches** |
| `P1` | — | CI: lint → pytest → cocotb → KAT |
| `P2` | — | `model/pipeline.py` stub |
| `P3` | — | `demo/` skeleton |

**D7 and P2 are worth doing first among these** — each unblocks another person, and both are small.

---

## Project / shared — Phase I foundations, currently unowned

Nobody's guide claims these, which is why none of them exist. Assign them.

- [ ] `P1` Stand up CI — lint → Python tests → cocotb → KAT, warnings as errors · `.github/workflows/ci.yml` · **Phase I exit**
- [ ] `P2` `model/pipeline.py` pass-through stub so cocotb has something to import
- [ ] `P3` Create `demo/` skeleton with empty files and `demo_config.py` stubs
- [ ] `P4` Declare Phase I genuinely closed · **Phase I exit** · ⛔ waiting on `P1`, `A1`

---

## Member A — ingress, parser, interface contract · Phase I–II

> Guide: `docs/Member A/Member-A-Ingress-and-Interface-Contract.md`
> **You block everyone.** Eleven downstream tasks wait on `A1`.

- [ ] `A2` Apply Member C's confirmations to §1, §3, §4, §5, §6 · paste-ready in `Member-C-Contract-Freeze-Package.md` §1
- [ ] `A3` Replace `HANDSHAKE_REJECT` with `HANDSHAKE_KEY_INVALID`, add the no-verdict rule · freeze package §1 edits 1–2
- [ ] `A4` Decide handshake message direction — `packet_type` `2'b10` for ciphertext · freeze package §3
- [ ] `A5` Fix port numbers (handshake-init / handshake-resp / data) · freeze package §2 · ⛔ waiting on `D3`
- [ ] `A6` Review and adopt `rtl/control/reason_codes.vh` (drafted by C) · ⛔ waiting on `A3`
- [ ] `A7` Collect verdict latencies from B and D, decide drop-engine sync approach · ⛔ waiting on `B3`, `D2`
- [ ] `A1` **Freeze `interface_contract.md`** — all four sign off · **Phase I exit** · ⛔ waiting on `A2`, `A3`, `A4`, `A5`, `A7`
- [ ] `A8` `uart_rx.v` / `uart_tx.v` at 3 Mbaud against 100 MHz
- [ ] `A9` `crc32.v`, verified bit-for-bit against `zlib.crc32`
- [ ] `A10` `deframer.v` — multi-packet, truncation, min/max length · ⛔ waiting on `A1`
- [ ] `A12` `model/pipeline.py` header-parsing function (the parser's oracle) · ⛔ waiting on `A1`
- [ ] `A11` `parser.v` — Ethernet → IPv4 → TCP/UDP onto the packet bus · **Phase II exit** · ⛔ waiting on `A1`, `A12`
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
- [ ] `C7` Push and merge `member-c/python-oracle` into `main`
- [ ] `C8` `keccak_f1600.v` + `shake_wrapper.v` — decide unrolled vs iterative rounds · ⛔ waiting on `C7`
- [ ] `C9` `test_keccak.py` vs `model/sha3.py`, then FIPS 202 KAT through RTL · **Phase IV exit** · ⛔ waiting on `C8`
- [ ] `C10` `ntt_core.v` / `butterfly.v` / `modmul.v` within the ≈8 DSP budget · ⛔ waiting on `C7`
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

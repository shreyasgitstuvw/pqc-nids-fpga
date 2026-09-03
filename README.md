# pqc-nids-fpga

**Inline FPGA-Based Post-Quantum Cryptographic Engine (ML-KEM) with Real-Time Network Telemetry and Threat Detection**
Start here -> `docs/Environment Setup Guide.md`

This README is the front door to the repository. If you're not sure where a file belongs, who owns it, or how to build/simulate something, start here before asking — the answer is almost certainly below or in one of the linked docs.

---

## 1. What this project is, in two sentences

A single FPGA pipeline that runs two independent checks on every network packet in parallel: **Lane 1** establishes a quantum-resistant session key (ML-KEM-512) and encrypts/authenticates traffic (ChaCha20-Poly1305), while **Lane 2** independently checks the same packet for known attack signatures and volumetric anomalies (CAM + Count-Min Sketch). A shared drop engine discards anything failing either check, in hardware, before it reaches the host.

If you haven't read the project synopsis or the architecture/execution plan, read those first — this README assumes you already know the *what*; it's here to tell you the *where* and *who*.

## 2. Where to go for what

| You need... | Go to |
|---|---|
| The big picture / why the project is shaped this way | `Major_Project_Synopsis_PQC_NIDS.pdf` |
| Full repo architecture and phase-by-phase execution plan | `docs/PQC-NIDS-Architecture-and-Execution-Plan.md` |
| Your individual task list, build order, and done-criteria | `docs/members/Member-{A,B,C,D}-*.md` |
| Zero-background theory for your track | `docs/members/Member-{A,B,C,D}-Theory-Guide.md` |
| How your module's inputs/outputs connect to everyone else's | `docs/Master-Interface-Document.md` |
| The frozen packet/register/verdict formats everything is built against | `docs/interface_contract.md` **(read this before writing any RTL)** |
| How to build a bitstream | §6 below, `scripts/build_bitstream.tcl` |
| How to run simulations | §5 below, `sim/Makefile` |
| Git workflow, branch/PR rules | §7 below |

> Place the four member guides and four theory guides in `docs/members/`, and the interface/architecture docs directly under `docs/`, so this table's paths resolve. If your copies currently live elsewhere, move them there before the next commit — a README with dead links is worse than no README.

## 3. Repository map — what lives where, and who owns it

Ownership means: you're the primary author and the person others' PRs against this file get routed to for review. It does **not** mean you're the only person allowed to touch it — see §8 on cross-track edits.

```
pqc-nids-fpga/
├── rtl/
│   ├── top/
│   │   └── top.v                      OWNER: whoever integrates in Phase VI (typically Member D + Member A jointly)
│   │
│   ├── ingress/                       OWNER: Member A
│   │   ├── uart_rx.v / uart_tx.v
│   │   ├── deframer.v
│   │   ├── crc32.v
│   │   └── parser.v
│   │
│   ├── crypto/
│   │   ├── sha3/                      OWNER: Member C
│   │   │   ├── keccak_f1600.v
│   │   │   └── shake_wrapper.v
│   │   ├── ntt/                       OWNER: Member C
│   │   │   ├── ntt_core.v
│   │   │   ├── butterfly.v
│   │   │   └── modmul.v
│   │   ├── kem/                       OWNER: Member C
│   │   │   ├── mlkem_top.v
│   │   │   ├── cbd_sampler.v
│   │   │   ├── compress.v / decompress.v
│   │   │   └── fo_transform.v
│   │   └── chacha_poly/               OWNER: Member D
│   │       ├── chacha20.v
│   │       └── poly1305.v
│   │
│   ├── detect/                        OWNER: Member B
│   │   ├── cam_matcher.v
│   │   ├── count_min_sketch.v
│   │   ├── hash_functions.v
│   │   └── protocol_validator.v
│   │
│   ├── control/
│   │   ├── session_mgr.v              OWNER: Member D (co-reviewed by Member C — see §8, Seam 2)
│   │   ├── drop_engine.v              OWNER: Member D
│   │   └── reason_codes.vh            OWNER: Member A (shared file — see §8)
│   │
│   └── io/                            OWNER: whoever picks this up first — small, low-risk, unclaimed by default
│       ├── led_driver.v
│       └── oled_driver.v
│
├── model/                             Python bit-exact reference — the oracle every RTL module is checked against
│   ├── mlkem/                         OWNER: Member C
│   ├── sha3.py                        OWNER: Member C
│   ├── chacha_poly.py                 OWNER: Member D
│   ├── detect.py                      OWNER: Member B
│   └── pipeline.py                    OWNER: Member A (parsing portion) + shared end-to-end glue, co-owned by all
│
├── sim/
│   ├── cocotb/                        each test file OWNED by whoever owns the RTL it tests (mirrors rtl/ tree exactly)
│   ├── vectors/
│   │   ├── fips203_kat/               OWNER: Member C (do not hand-edit — official vectors, checked in verbatim)
│   │   └── cicids2017_subset/         OWNER: Member B (curated subset — see Member B's theory guide §7 note on labeling)
│   └── Makefile                       OWNER: whoever sets up CI first — shared build target for everyone
│
├── test-network/                      OWNER: shared — built collaboratively in Phase VIII, no single owner beforehand
│   ├── send.py
│   ├── recv.py
│   ├── attacker.py
│   └── uart_link.py
│
├── constraints/                       OWNER: whoever runs Phase VII timing closure — likely Member A (owns clock/UART pins) + Member C (owns the timing-critical NTT path)
│   ├── zedboard_pmod.xdc
│   └── timing.xdc
│
├── scripts/                           OWNER: shared infrastructure — treat as commons, PR-review any change
│   ├── build_bitstream.tcl
│   ├── run_all_sim.sh
│   └── measure_timing.py
│
├── docs/                              OWNER: whoever wrote the doc; interface_contract.md is Member A's but requires
│   │                                   sign-off from all four before any change is merged (see §8)
│   └── members/                       the four per-person task guides and theory guides
│
└── .github/workflows/
    └── ci.yml                         OWNER: shared — treat as commons
```

## 4. Quick-reference: "which file do I touch for X?"

| I want to... | File(s) |
|---|---|
| Change how a UART byte is sampled | `rtl/ingress/uart_rx.v` |
| Add a new header field to the packet bus | `rtl/ingress/parser.v` **and** `docs/interface_contract.md` — always both, in the same commit |
| Add a new reason code | `rtl/control/reason_codes.vh` — ask Member A, don't add it unilaterally (it's a shared enum) |
| Fix a wrong NTT butterfly stage | `rtl/crypto/ntt/butterfly.v` and re-check against `model/mlkem/ntt.py` |
| Change the ML-KEM parameter set | `rtl/crypto/kem/mlkem_top.v` — this is a big change, flag it to everyone, it likely breaks the FIPS 203 KAT gate temporarily |
| Add a new attack signature | `rtl/detect/cam_matcher.v`'s loaded table + `sim/vectors/cicids2017_subset/` |
| Retune the Count-Min Sketch size | `rtl/detect/count_min_sketch.v` — redo the (epsilon, delta) math in Member B's guide before changing constants |
| Change the ChaCha/Poly1305 composition order | Don't, unless you've re-read RFC 8439 — this is specified, not a style choice |
| Change how verdicts get merged / prioritized on simultaneous failure | `rtl/control/drop_engine.v` — this affects Member B's and Member D's reason-code semantics, coordinate before changing |
| Fix a Vivado timing violation | `constraints/timing.xdc` first; if that's not enough, it's a pipelining problem in whichever module is on the critical path — check the timing report to find out which |
| Add a CI check | `.github/workflows/ci.yml` — shared file, PR it like any other |

## 5. Running simulations

```bash
cd sim
make test_<module_name>          # e.g. make test_ntt, make test_cam_matcher
make test_all                    # runs every cocotb suite in sim/cocotb/
```

Every testbench compares RTL output against the corresponding `model/` Python function. If a test fails, **check `model/` first** — confirm your Python reference itself is correct (e.g., against a published test vector) before assuming the bug is in your RTL. It's easy to "fix" RTL to match a broken oracle.

`sim/vectors/fips203_kat/` and `sim/vectors/cicids2017_subset/` are the two external ground-truth vector sets in the repo — never hand-edit these, they're checked in as-is from their respective official/published sources.

## 6. Building a bitstream

```bash
cd scripts
vivado -mode batch -source build_bitstream.tcl
```

This runs Vivado non-project mode: synthesis → place-and-route → timing analysis → bitstream, using `constraints/zedboard_pmod.xdc` and `constraints/timing.xdc`. **Do not attempt this until all modules pass their individual simulations and the full-pipeline sim (per the Master Interface Document's integration checklist) passes** — a bitstream build that fails timing or functional intent is expensive to debug compared to catching the same issue in simulation.

After a successful build, run:
```bash
python scripts/measure_timing.py
```
to extract the utilization and timing numbers that go into the final report's §6.3-style table (handshake time, per-packet latency, detection latency, device utilization).

## 7. Git workflow

- **Branch naming:** `member-{a,b,c,d}/<short-description>`, e.g. `member-c/ntt-butterfly-fix`.
- **One module, one PR** where possible — don't bundle unrelated changes across owners' files in a single PR, it makes review slower for everyone.
- **Every PR touching RTL must include or update its cocotb test** — a PR that changes `rtl/` without a corresponding `sim/cocotb/` update should be rejected in review, no exceptions, since it breaks the "bit-exact against the model" guarantee the whole project relies on.
- **CI must be green before merge.** `.github/workflows/ci.yml` runs lint, Python unit tests, cocotb sims, and (where applicable) KAT checks, with warnings treated as errors. A red CI run is not "probably fine" — investigate before merging.
- **Commits that touch `docs/interface_contract.md`** need a second reviewer from a different track, minimum — this file is everyone's shared foundation and silent drift here is the single most expensive category of bug in this project (see Master Interface Document §2, Seam 1).

## 8. Cross-track files and how to handle them without stepping on each other

A few files are structurally shared and don't belong to one person. Handle each like this:

- **`docs/interface_contract.md`** — Member A authors and maintains it, but any change requires explicit sign-off from whichever other members' modules consume the changed section (packet bus changes → notify B, C, D; session register changes → notify C, D specifically). Post the diff, don't just merge silently.
- **`rtl/control/reason_codes.vh`** — Member A owns the file, but Members B and D are the primary requesters of new codes (detection lane and drop engine respectively). Request additions via PR comment or issue, don't hand-edit around each other.
- **`rtl/control/session_mgr.v`** — Member D implements it, but Member C must review any change touching how it reacts to handshake completion/rejection, since this is the file where the implicit-rejection indistinguishability property (Master Interface Document, Seam 2) actually lives or breaks. Treat this file's review as joint, not just Member D's call.
- **`rtl/control/drop_engine.v`** — Member D implements it, but the priority rule for simultaneous same-cycle failures from Lane 1 and Lane 2 affects Member B's reported detection-accuracy numbers. Any change to that priority logic should be flagged to Member B before merging.
- **`model/pipeline.py`** — the end-to-end glue file. Each member's parsing/crypto/detection function lives in its own file (`model/mlkem/`, `model/chacha_poly.py`, `model/detect.py`), but `pipeline.py` wires them together and is genuinely shared — small, additive changes only; if you need to restructure it, say so first.
- **`scripts/`, `sim/Makefile`, `.github/workflows/ci.yml`** — infrastructure commons. Anyone can propose a change, but treat these as "ask before restructuring, feel free to extend."

## 9. If you're stuck

1. Check the quick-reference table in §4 — most "which file" questions are answered there.
2. Check your own member guide (`docs/members/Member-<X>-*.md`) — build order, verification steps, and common failure modes for your track are all there.
3. Check the Master Interface Document if the question is about how your module's output is consumed elsewhere.
4. If it's a shared-file question (§8), post in the group channel before editing — these are the files where silent, uncoordinated changes cost the whole team the most time.
5. If none of the above resolves it, it's probably a genuine gap in the interface contract — raise it as an issue rather than guessing, since a guess here propagates to everyone downstream of you.

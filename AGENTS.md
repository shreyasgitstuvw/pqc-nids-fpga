# AGENTS.md — rules for any AI agent working in this repository

Antigravity reads this file automatically before it changes anything. Every
rule below exists because breaking it silently destroys work that is expensive
to recover.

---

## 1. What this project is

An FPGA-based network intrusion detection engine with an inline post-quantum
crypto core. Target: ZedBoard, Xilinx Zynq-7000 XC7Z020, 100 MHz, single clock
domain.

Two parallel lanes process every packet:

```
UART → deframer → CRC → parser ─┬─→ LANE 1  ML-KEM-512 handshake, ChaCha20-Poly1305 per packet
                                └─→ LANE 2  signature CAM, count-min sketch, protocol validator
                                            ↓
                                     drop_engine  →  verdict + reason code
```

The team is four electronics engineers, not career software developers. Write
for that audience: explain in hardware terms, prefer clarity over cleverness,
and never leave a "TODO" where a real implementation was asked for.

---

## 2. The one principle everything else follows from

**Every RTL module has a bit-exact Python twin, and nothing is trusted until
the twin and the hardware agree on a published test vector.**

```
model/mlkem/ntt.py   ←── must agree ──→   rtl/crypto/ntt/ntt_core.v
model/sha3.py        ←── must agree ──→   rtl/crypto/sha3/keccak_f1600.v
model/chacha_poly.py ←── must agree ──→   rtl/crypto/chacha_poly/*.v
model/detect.py      ←── must agree ──→   rtl/detect/*.v
model/pipeline.py    ←── must agree ──→   rtl/ingress/parser.v
```

So the Python model **is the specification**. When asked to write a Verilog
module, read its Python twin first and implement *that*, function by function.
Do not design from the standard document directly when a twin already exists —
the twin is what the vectors were checked against.

This also means you are never guessing whether your work is correct. There is
always a command that answers it. Run it.

---

## 3. Guardrails — violating any of these is a serious failure

**Never modify a test vector, a KAT file, or an assertion threshold to make a
test pass.** This is now enforced at the permission layer — writes under
`sim/vectors/`, `model/mlkem/` and `model/sha3.py` are denied outright — but the
rule stands regardless of whether the mechanism is in place on a given machine. If a test fails, the code is wrong. Files under `sim/vectors/`
are external ground truth from NIST and the RFCs; they are read-only. Changing
them to get green is the one action that destroys the entire premise of this
project, and it is not recoverable by review because the build still looks fine.
If you believe a vector is genuinely wrong, stop and say so — do not edit it.

**Never edit `model/mlkem/` or `model/sha3.py`.** They pass FIPS 203 KAT 80/80
and FIPS 202 vectors. They are frozen. If something there looks wrong, report
it; do not change it.

**Stay inside your lane's directories.** See §4. Do not edit another member's
files even if you can see an obvious bug — report it instead. Four people and
autonomous agents editing the same tree is how a shared repo gets corrupted.

**Never commit to `main`.** Work on `member-<x>/<topic>` branches and open a PR.
Pushes targeting `main` and all force-pushes are denied at the permission layer.
See the `git` skill for the full workflow.

**Never weaken CI.** Do not remove a job, relax `-Wall`, add `continue-on-error`,
or skip a test to get a green run.

**Do not invent interface fields.** Bit widths, packet-bus fields, reason codes
and port numbers come from `docs/Member A/interface_contract.md` and
`rtl/control/reason_codes.vh`. If something you need is missing, stop and ask
Member A to add it.

---

## 4. Directory ownership

| Path | Owner | Others may |
|---|---|---|
| `rtl/ingress/`, `model/pipeline.py` | Member A | read |
| `rtl/detect/`, `model/detect.py` | Member B | read |
| `rtl/crypto/sha3/`, `rtl/crypto/ntt/`, `rtl/crypto/kem/`, `model/mlkem/`, `model/sha3.py` | Member C | read |
| `rtl/crypto/chacha_poly/`, `rtl/control/`, `model/chacha_poly.py` | Member D | read |
| `docs/Member A/interface_contract.md`, `rtl/control/reason_codes.vh` | Member A (contract authority) | read, propose diffs |
| `sim/vectors/` | nobody — external ground truth | read only |
| `sim/cocotb/test_<module>.py` | whoever owns `<module>` | read |
| `docs/`, `demo/`, `.github/`, `scripts/` | shared | edit via PR |

---

## 5. Conventions

**Verilog.** Verilog-2001. One module per file, filename = module name. Single
clock `clk`, synchronous active-high reset `rst`. Registered outputs unless a
combinational path is explicitly required. No latches. No `initial` blocks in
synthesizable code. Must pass `verilator --lint-only -Wall` with zero warnings —
warnings are errors here.

**Python.** 3.11. Standard library only in `model/` — `pycryptodome` appears in
exactly one place (`model/sha3.py`'s self-test, as an independent oracle) and
must not spread. Every model module ends with a `if __name__ == "__main__":`
self-test that exits non-zero on failure.

**Testbenches.** cocotb, in `sim/cocotb/test_<module>.py`. A testbench drives
the RTL and compares against the Python twin **imported from `model/`** — never
against hard-coded expected values copied from a previous run, which just
freezes whatever bug existed that day.

---

## 6. Before you claim anything works

Run the gate and paste the real output. "It should work" is not a result.

```bash
python model/mlkem/kat_test.py        # FIPS 203, must print 80/80
python model/sha3.py                  # FIPS 202
python model/mlkem/ntt.py             # forward∘inverse identity
verilator --lint-only -Wall -Irtl/control rtl/**/*.v
make -C sim                           # cocotb, once testbenches exist
```

If you changed anything under `model/` or `rtl/`, all of it must still pass.
A change that breaks a previously-passing gate is a regression, not progress —
say so plainly rather than reporting partial success.

---

## 7. How to report back

State what you did, then the evidence, then what you did not do.

Good: *"Implemented `keccak_f1600.v`, iterative, 24 cycles per permutation.
`verilator --lint-only -Wall` clean. `test_keccak.py` passes all 5 FIPS 202
vectors against `model/sha3.py` — output pasted below. Did not implement
`shake_wrapper.v`; the padding logic needs a decision on rate parameterisation."*

Bad: *"Implemented the Keccak core and everything works."*

If you get stuck, stop and say where. A half-finished module that is honestly
labelled is more useful than a complete-looking one that was never run.

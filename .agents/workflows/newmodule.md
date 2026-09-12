# /newmodule — build one RTL module end to end

Usage: `/newmodule rtl/crypto/sha3/keccak_f1600.v`

Takes a module from nothing to a linted, simulated, PR-ready state. Stops twice
to ask you, because those are the two decisions an agent should not make alone.

## Stages

**1 — Locate the twin.**
Find the Python model this module implements (`rtl_from_model` skill has the
table). Read it completely. If no twin exists, STOP and say so: on this project
the model is written first, and a module without one has nothing to be checked
against.

**2 — Propose an architecture. → PAUSE FOR APPROVAL.**
Write a short plan, no code: the chosen structure (iterative vs unrolled, how
many pipeline stages), cycles per operation, estimated LUT / DSP / BRAM cost
against the budget (≈8 DSPs total, ≈11.5 of 140 BRAMs for detect, 100 MHz), the
interface signal list, and one alternative you rejected and why.

**Ask the user to approve before writing any Verilog.** This is the decision
that gets questioned in a viva and the one most expensive to unwind later.

**3 — Implement.**
Follow the `rtl_from_model` skill. Keep the twin's function names and structure
visible. Put the approved architecture decision in a header comment.

**4 — Lint until clean.**
```bash
verilator --lint-only -Wall -Irtl/control rtl/<path>/<module>.v
```
Zero warnings. Fix them in the Verilog — never by relaxing the flag.

**5 — Write the testbench.**
Follow `cocotb_bench`: published vectors, then hundreds of randomised
comparisons against the imported twin, then edge cases.

**6 — Run it.**
```bash
make -C sim MODULE=test_<module>
```
If it fails, the RTL is wrong. Fix the RTL. Never loosen the assertion, never
edit a vector.

**7 — Full gate. → PAUSE FOR REVIEW.**
Run the `verify` skill over the whole repo, to catch anything this work broke
elsewhere. **Show the user the results and stop.** Do not open a PR on your own.

**8 — Handoff.**
On approval, follow the `handoff` skill.

## Rules

- Stages 2 and 7 always pause. Do not run past them.
- Stay inside the owning member's directories.
- If you are stuck at any stage, stop and say where. Do not skip ahead.

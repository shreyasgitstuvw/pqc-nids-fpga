# Skill: rtl_from_model — write a Verilog module against its Python twin

The default way RTL gets written in this project. The Python model is the
specification; you are translating it to hardware, not redesigning it.

## Procedure

**1. Read the twin first, completely.**

| Writing | Read first |
|---|---|
| `rtl/crypto/sha3/keccak_f1600.v` | `model/sha3.py` |
| `rtl/crypto/ntt/ntt_core.v` | `model/mlkem/ntt.py` |
| `rtl/crypto/kem/cbd_sampler.v` | `model/mlkem/cbd.py`, `pke.py` `sample_poly_cbd` |
| `rtl/crypto/chacha_poly/*.v` | `model/chacha_poly.py` |
| `rtl/detect/*.v` | `model/detect.py` |
| `rtl/ingress/parser.v` | `model/pipeline.py` `parse_headers` |

Do not work from the standard document when a twin exists. The twin is what the
test vectors were checked against; the standard has choices in it the twin has
already made.

**2. State the architecture before writing.** In a comment at the top of the
file, say what you chose and why — iterative vs unrolled, how many cycles per
operation, where state lives, how many DSPs or BRAMs it costs. This is the thing
that gets questioned in a viva, and it is much easier to write now than to
reconstruct later.

Budgets: ≈8 DSP slices for the whole design, ≈11.5 of 140 36Kb BRAMs for the
detect lane, 100 MHz single clock.

**3. Translate function by function.** Keep the twin's structure visible. If the
Python has `theta / rho / pi / chi / iota`, the Verilog should too, named the
same. A reviewer must be able to hold both files side by side.

**4. Interface conventions.**

```verilog
module <name> (
    input  wire        clk,
    input  wire        rst,      // synchronous, active high
    input  wire        in_valid,
    input  wire [N:0]  in_data,
    output reg         out_valid,
    output reg  [M:0]  out_data,
    output reg         busy
);
```

Verilog-2001. One module per file, filename = module name. Registered outputs
unless a combinational path is required and stated. No latches, no `initial` in
synthesizable code.

**5. Lint before claiming anything.**

```bash
verilator --lint-only -Wall -Irtl/control rtl/<path>/<module>.v
```

Zero warnings. Not "only width warnings" — zero.

**6. Then write the testbench** (`cocotb_bench` skill) and run it. A module
that has never been simulated against its twin is not done, however clean it
lints.

## Rules

- Never change the Python twin to match your Verilog. The twin is verified
  against published vectors; your Verilog is not.
- If the twin is genuinely ambiguous, ask — do not pick and hope.
- Stay in your lane's directories.

# Skill: cocotb_bench — write a testbench that checks RTL against the model

A testbench compares hardware against the Python twin **imported live**. It
never compares against numbers pasted from a previous run — that just freezes
whatever bug existed on the day they were pasted.

## Procedure

**1. Import the twin.** Do not reimplement its logic in the testbench.

```python
import os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from model.mlkem.ntt import ntt, intt, Q        # the oracle
```

**2. Three layers of test, in this order.**

- **Published vectors.** FIPS 202 for Keccak, FIPS 203 for ML-KEM, RFC 8439 for
  ChaCha/Poly. External ground truth, non-negotiable.
- **Randomised agreement.** Hundreds of random inputs, RTL output compared to
  the twin's on each. This is what catches the bugs vectors miss.
- **Edge cases.** Zero, all-ones, maximum length, minimum length, back-to-back
  transactions with no gap, reset mid-operation.

**3. Shape.**

```python
import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge

@cocotb.test()
async def test_matches_model(dut):
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())   # 100 MHz
    dut.rst.value = 1
    await RisingEdge(dut.clk); await RisingEdge(dut.clk)
    dut.rst.value = 0

    for trial in range(200):
        stimulus = make_random_input()
        expected = model_function(stimulus)        # the twin
        got      = await drive_and_collect(dut, stimulus)
        assert got == expected, (
            f"trial {trial}: RTL {got} != model {expected}\n"
            f"  input was {stimulus}"
        )
```

**4. Assertion messages must be diagnosable.** Include the trial number, the
input, both values. `assert got == expected` alone tells whoever hits it in CI
nothing about how to reproduce it.

**5. Run it.**

```bash
make -C sim MODULE=test_<name>
```

## Special case — implicit rejection

`test_mlkem_top.py` must check that a rejected decapsulation is
*indistinguishable* from an accepted one, not merely that it returns a different
key. Assert equal cycle counts and identical signal shapes between the two
cases. A testbench that only checks the key value will pass on an implementation
that leaks through timing.

## Rules

- The twin is imported, never copied.
- Every test names the module it tests in its filename: `test_<module>.py`.
- If a test fails, that is a finding. Report it; do not loosen the assertion.

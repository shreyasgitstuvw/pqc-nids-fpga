#==========================================================================
# sim/cocotb/test_decompress.py
#
# Cocotb testbench for decompress.v (ML-KEM-512 Polynomial Decompression Core).
# Verified bit-exact vs model/mlkem/pke.py:decompress and model/compress_hw.py.
#
# Tests (named without test_ prefix for pytest runner compatibility):
#   1. exhaustive_sweep: all 2^D inputs in [0, 2^D - 1] for parameter D
#   2. tie_break_checks: exact tie-break rounding to 1665 at y = 2^(D-1)
#   3. latency_and_bubbles_check: out_valid stays low until L=1 cycle, no bubbles
#   4. cycle_count_assertion: 256 coefficients complete in exactly 256 + L = 257 cycles
#   5. mid_stream_reset: asserting rst mid-stream flushes all pipeline stages
#   6. random_polys_vs_model: 10 random 256-coeff polynomials bit-exact vs model
#==========================================================================

import os
import random
import sys
from pathlib import Path

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import FallingEdge, RisingEdge

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))

from model.mlkem.pke import decompress as model_decompress, Q
from model.compress_hw import decompress_hw

LATENCY_DECOMPRESS = 1


async def reset_dut(dut):
    """Synchronous active-high reset matching repo conventions."""
    dut.rst.value = 1
    dut.in_valid.value = 0
    dut.in_data.value = 0
    await FallingEdge(dut.clk)
    await FallingEdge(dut.clk)
    dut.rst.value = 0
    await FallingEdge(dut.clk)


@cocotb.test()
async def exhaustive_sweep(dut):
    """Verify all 2^D inputs y in [0, 2^D - 1] produce bit-exact results at L=1."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    d = int(dut.D.value)
    inputs = list(range(1 << d))
    outputs = []

    async def receiver():
        while len(outputs) < len(inputs):
            await FallingEdge(dut.clk)
            if int(dut.out_valid.value) == 1:
                outputs.append(int(dut.out_data.value))

    recv_task = cocotb.start_soon(receiver())

    for y in inputs:
        await FallingEdge(dut.clk)
        dut.in_valid.value = 1
        dut.in_data.value = y

    await FallingEdge(dut.clk)
    dut.in_valid.value = 0
    dut.in_data.value = 0

    await recv_task

    assert len(outputs) == len(inputs), f"Expected {len(inputs)} outputs, got {len(outputs)}"
    for y, got in zip(inputs, outputs):
        expected = decompress_hw(y, d)
        assert got == expected, f"Mismatch at D={d}, y={y}: got {got}, expected {expected}"


@cocotb.test()
async def tie_break_checks(dut):
    """Verify exact tie-break rounding to 1665 at y = 2^(D-1)."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    d = int(dut.D.value)
    y_tie = 1 << (d - 1)

    await FallingEdge(dut.clk)
    dut.in_valid.value = 1
    dut.in_data.value = y_tie
    await FallingEdge(dut.clk)
    dut.in_valid.value = 0

    assert int(dut.out_valid.value) == 1, "out_valid must assert at cycle L=1"
    got = int(dut.out_data.value)
    assert got == 1665, f"Tie-break failure for D={d}, y={y_tie}: expected 1665, got {got}"


@cocotb.test()
async def latency_and_bubbles_check(dut):
    """Verify out_valid stays low until exactly L=1 cycle, then streams bubble-free."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    # Initial state: out_valid must be 0
    assert int(dut.out_valid.value) == 0, "out_valid must be 0 before any input"

    # Cycle 0: drive input
    await FallingEdge(dut.clk)
    dut.in_valid.value = 1
    dut.in_data.value = 0

    # Cycle 1: out_valid must assert immediately at L=1
    await FallingEdge(dut.clk)
    dut.in_valid.value = 1
    dut.in_data.value = 1
    assert int(dut.out_valid.value) == 1, "out_valid must assert at cycle 1 (L=1)"

    # Cycle 2: out_valid continues
    await FallingEdge(dut.clk)
    dut.in_valid.value = 0
    assert int(dut.out_valid.value) == 1, "out_valid must stay 1 for second input"

    # Cycle 3: out_valid deasserts cleanly
    await FallingEdge(dut.clk)
    assert int(dut.out_valid.value) == 0, "out_valid must deassert when pipeline drains"


@cocotb.test()
async def cycle_count_assertion(dut):
    """Verify continuous 256-coefficient stream completes in exactly 256 + L = 257 cycles."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    d = int(dut.D.value)
    rng = random.Random(303)
    poly = [rng.randrange(1 << d) for _ in range(256)]

    total_cycles = 0

    await FallingEdge(dut.clk)
    dut.in_valid.value = 1
    dut.in_data.value = poly[0]

    for i in range(1, 256):
        await FallingEdge(dut.clk)
        total_cycles += 1
        dut.in_valid.value = 1
        dut.in_data.value = poly[i]

    await FallingEdge(dut.clk)
    total_cycles += 1
    dut.in_valid.value = 0
    dut.in_data.value = 0

    while int(dut.out_valid.value) == 1 or total_cycles < 256 + LATENCY_DECOMPRESS:
        await FallingEdge(dut.clk)
        total_cycles += 1
        if int(dut.out_valid.value) == 0 and total_cycles >= 256 + LATENCY_DECOMPRESS:
            break

    expected_cycles = 256 + LATENCY_DECOMPRESS
    assert total_cycles == expected_cycles, (
        f"Cycle count regression: expected {expected_cycles}, got {total_cycles}"
    )


@cocotb.test()
async def mid_stream_reset(dut):
    """Verify asserting rst mid-stream immediately clears all pipeline stages."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    # Stream 20 coefficients
    for i in range(20):
        await FallingEdge(dut.clk)
        dut.in_valid.value = 1
        dut.in_data.value = i % (1 << int(dut.D.value))

    # Assert reset mid-stream
    await FallingEdge(dut.clk)
    dut.rst.value = 1
    dut.in_valid.value = 0
    dut.in_data.value = 0

    # Wait 1 cycle in reset
    await FallingEdge(dut.clk)
    dut.rst.value = 0

    # For the next 10 cycles, out_valid must NEVER go high
    for cycle in range(10):
        await FallingEdge(dut.clk)
        assert int(dut.out_valid.value) == 0, (
            f"Stale out_valid asserted on cycle {cycle} after mid-stream reset!"
        )


@cocotb.test()
async def random_polys_vs_model(dut):
    """Stream 10 random 256-coefficient polynomials and compare against frozen model."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    d = int(dut.D.value)
    rng = random.Random(404)

    for poly_idx in range(10):
        poly = [rng.randrange(1 << d) for _ in range(256)]
        expected = [model_decompress(y, d) for y in poly]
        got = []

        async def poly_receiver():
            while len(got) < 256:
                await FallingEdge(dut.clk)
                if int(dut.out_valid.value) == 1:
                    got.append(int(dut.out_data.value))

        recv_task = cocotb.start_soon(poly_receiver())

        for y in poly:
            await FallingEdge(dut.clk)
            dut.in_valid.value = 1
            dut.in_data.value = y

        await FallingEdge(dut.clk)
        dut.in_valid.value = 0
        dut.in_data.value = 0

        await recv_task
        assert got == expected, f"Poly {poly_idx} mismatch for D={d}"


def test_runner():
    """pytest entry point using cocotb.runner across all D in {1, 4, 10}."""
    from cocotb.runner import get_runner

    rtl = REPO / "rtl"
    sim_name = os.getenv("SIM", "icarus")

    for d_val in [10, 4, 1]:
        runner = get_runner(sim_name)
        build_dir = REPO / "sim" / "sim_build" / f"decompress_d{d_val}"
        runner.build(
            sources=[
                rtl / "crypto" / "kem" / "decompress.v",
            ],
            includes=[rtl / "crypto" / "kem"],
            parameters={"D": d_val},
            hdl_toplevel="decompress",
            build_dir=build_dir,
            always=True,
        )
        runner.test(
            hdl_toplevel="decompress",
            test_module="test_decompress",
            build_dir=build_dir,
            test_dir=Path(__file__).resolve().parent,
        )


if __name__ == "__main__":
    test_runner()

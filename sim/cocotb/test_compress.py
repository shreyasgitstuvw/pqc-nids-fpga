#==========================================================================
# sim/cocotb/test_compress.py
#
# Cocotb testbench for compress.v (ML-KEM-512 Polynomial Compression Core).
# Verified bit-exact vs model/mlkem/pke.py:compress and model/compress_hw.py.
#
# Tests (named without test_ prefix for pytest runner compatibility):
#   1. exhaustive_sweep: all 3,329 inputs in [0, 3328] for parameter D
#   2. wrap_boundary_checks: exact transition at wrap boundaries
#   3. latency_and_bubbles_check: out_valid stays low until L=3 cycles, no bubbles
#   4. cycle_count_assertion: 256 coefficients complete in exactly 256 + L = 259 cycles
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

from model.mlkem.pke import compress as model_compress, Q
from model.compress_hw import compress_hw

LATENCY_COMPRESS = 3


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
    """Verify all 3,329 inputs x in [0, 3328] produce bit-exact results at L=3."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    d = int(dut.D.value)

    # Stream all 3,329 coefficients consecutively
    inputs = list(range(Q))
    outputs = []

    async def receiver():
        while len(outputs) < len(inputs):
            await FallingEdge(dut.clk)
            if int(dut.out_valid.value) == 1:
                outputs.append(int(dut.out_data.value))

    recv_task = cocotb.start_soon(receiver())

    for x in inputs:
        await FallingEdge(dut.clk)
        dut.in_valid.value = 1
        dut.in_data.value = x

    await FallingEdge(dut.clk)
    dut.in_valid.value = 0
    dut.in_data.value = 0

    await recv_task

    assert len(outputs) == len(inputs), f"Expected {len(inputs)} outputs, got {len(outputs)}"
    for x, got in zip(inputs, outputs):
        expected = compress_hw(x, d)
        assert got == expected, f"Mismatch at D={d}, x={x}: got {got}, expected {expected}"


@cocotb.test()
async def wrap_boundary_checks(dut):
    """Verify wrap-around boundary cases where unwrapped quotient reaches 2^D."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    d = int(dut.D.value)

    if d == 1:
        test_cases = [(2496, 1), (2497, 0), (3328, 0)]
    elif d == 4:
        test_cases = [(3224, 15), (3225, 0), (3328, 0)]
    else:  # d == 10
        test_cases = [(3327, 1023), (3328, 0)]

    for x_val, expected_val in test_cases:
        await FallingEdge(dut.clk)
        dut.in_valid.value = 1
        dut.in_data.value = x_val
        await FallingEdge(dut.clk)
        dut.in_valid.value = 0

        # Wait exactly L=3 cycles
        for _ in range(LATENCY_COMPRESS - 1):
            await FallingEdge(dut.clk)

        assert int(dut.out_valid.value) == 1, f"out_valid not asserted at cycle {LATENCY_COMPRESS}"
        got = int(dut.out_data.value)
        assert got == expected_val, (
            f"Wrap boundary failure for D={d}, x={x_val}: got {got}, expected {expected_val}"
        )


@cocotb.test()
async def latency_and_bubbles_check(dut):
    """Verify out_valid stays low until exactly L=3 cycles, then streams bubble-free."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    # Cycle 0: drive first input
    await FallingEdge(dut.clk)
    dut.in_valid.value = 1
    dut.in_data.value = 42

    # Check cycles 1 and 2: out_valid must be strictly 0
    await FallingEdge(dut.clk)
    dut.in_valid.value = 1
    dut.in_data.value = 43
    assert int(dut.out_valid.value) == 0, "out_valid asserted prematurely at cycle 1"

    await FallingEdge(dut.clk)
    dut.in_valid.value = 1
    dut.in_data.value = 44
    assert int(dut.out_valid.value) == 0, "out_valid asserted prematurely at cycle 2"

    # Cycle 3: out_valid must now be 1
    await FallingEdge(dut.clk)
    dut.in_valid.value = 0
    assert int(dut.out_valid.value) == 1, "out_valid must assert at cycle 3 (L=3)"

    # Cycles 4 and 5: out_valid must stay 1 for remaining 2 inputs without bubbles
    await FallingEdge(dut.clk)
    assert int(dut.out_valid.value) == 1, "Bubble observed at cycle 4"

    await FallingEdge(dut.clk)
    assert int(dut.out_valid.value) == 1, "Bubble observed at cycle 5"

    # Cycle 6: out_valid must fall back to 0
    await FallingEdge(dut.clk)
    assert int(dut.out_valid.value) == 0, "out_valid failed to deassert after stream end"


@cocotb.test()
async def cycle_count_assertion(dut):
    """Verify continuous 256-coefficient stream completes in exactly 256 + L = 259 cycles."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    rng = random.Random(101)
    poly = [rng.randrange(Q) for _ in range(256)]

    total_cycles = 0
    started = False
    finished = False

    await FallingEdge(dut.clk)
    dut.in_valid.value = 1
    dut.in_data.value = poly[0]
    started = True

    for i in range(1, 256):
        await FallingEdge(dut.clk)
        total_cycles += 1
        dut.in_valid.value = 1
        dut.in_data.value = poly[i]

    await FallingEdge(dut.clk)
    total_cycles += 1
    dut.in_valid.value = 0
    dut.in_data.value = 0

    while int(dut.out_valid.value) == 1 or total_cycles < 256 + LATENCY_COMPRESS:
        await FallingEdge(dut.clk)
        total_cycles += 1
        if int(dut.out_valid.value) == 0 and total_cycles >= 256 + LATENCY_COMPRESS:
            break

    expected_cycles = 256 + LATENCY_COMPRESS
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
        dut.in_data.value = i * 100

    # Assert reset mid-stream
    await FallingEdge(dut.clk)
    dut.rst.value = 1
    dut.in_valid.value = 0
    dut.in_data.value = 0

    # Wait 1 cycle in reset
    await FallingEdge(dut.clk)
    dut.rst.value = 0

    # For the next 10 cycles, out_valid must NEVER go high (pipeline must be flushed)
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
    rng = random.Random(202)

    for poly_idx in range(10):
        poly = [rng.randrange(Q) for _ in range(256)]
        expected = [model_compress(x, d) for x in poly]
        got = []

        async def poly_receiver():
            while len(got) < 256:
                await FallingEdge(dut.clk)
                if int(dut.out_valid.value) == 1:
                    got.append(int(dut.out_data.value))

        recv_task = cocotb.start_soon(poly_receiver())

        for x in poly:
            await FallingEdge(dut.clk)
            dut.in_valid.value = 1
            dut.in_data.value = x

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
        build_dir = REPO / "sim" / "sim_build" / f"compress_d{d_val}"
        runner.build(
            sources=[
                rtl / "crypto" / "kem" / "compress.v",
            ],
            includes=[rtl / "crypto" / "kem"],
            parameters={"D": d_val},
            hdl_toplevel="compress",
            build_dir=build_dir,
            always=True,
        )
        runner.test(
            hdl_toplevel="compress",
            test_module="test_compress",
            build_dir=build_dir,
            test_dir=Path(__file__).resolve().parent,
        )


if __name__ == "__main__":
    test_runner()

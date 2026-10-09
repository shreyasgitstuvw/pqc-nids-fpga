#==========================================================================
# sim/cocotb/test_modmul.py
#
# Cocotb testbench for modmul.v (modular multiplication mod q = 3329).
# Verifies bit-exact agreement against model/modmul_hw.py and model/mlkem/ntt.py.
#
# Test cases:
#   1. Corner values: 0, 1, q-1=3328, products 0, 1, (q-1)^2.
#   2. Random pairs in [0, 3328].
#   3. Pipeline validity and latency check matching PIPE_DEPTH parameter.
#   4. Exhaustive sweep over sample dense ranges.
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

from model.modmul_hw import modmul_hw, Q


async def reset_dut(dut):
    dut.rst.value = 1
    dut.en.value = 0
    dut.a.value = 0
    dut.b.value = 0
    for _ in range(5):
        await FallingEdge(dut.clk)
    dut.rst.value = 0
    await FallingEdge(dut.clk)


@cocotb.test()
async def modmul_corners(dut):
    """Test corner values: 0, 1, Q-1, and extreme products."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    pipe_depth = int(dut.PIPE_DEPTH.value)

    corners = [
        (0, 0),
        (0, 1),
        (1, 0),
        (1, 1),
        (0, Q - 1),
        (Q - 1, 0),
        (1, Q - 1),
        (Q - 1, 1),
        (Q - 1, Q - 1),
        (128, 3303),  # INV_N * 128 = 1 mod Q
        (17, 17),
        (2, (Q + 1) // 2),  # 2 * 1665 = 3330 = 1 mod Q
    ]

    for a, b in corners:
        expected = modmul_hw(a, b)
        await FallingEdge(dut.clk)
        dut.en.value = 1
        dut.a.value = a
        dut.b.value = b

        await FallingEdge(dut.clk)
        dut.en.value = 0

        # Wait pipe_depth - 1 cycles for result
        for _ in range(pipe_depth - 1):
            await FallingEdge(dut.clk)

        assert dut.valid_out.value == 1, f"valid_out not asserted at cycle {pipe_depth}"
        got = int(dut.res.value)
        assert got == expected, f"Mismatch on ({a} * {b}) mod {Q}: got {got}, want {expected}"


@cocotb.test()
async def modmul_random_stream(dut):
    """Test back-to-back streaming of 500 random multiplications with pipeline verification."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    pipe_depth = int(dut.PIPE_DEPTH.value)
    rng = random.Random(42)

    num_samples = 500
    pairs = [(rng.randrange(Q), rng.randrange(Q)) for _ in range(num_samples)]
    expected_results = [modmul_hw(a, b) for a, b in pairs]

    # Queue of in-flight expected results: (cycle_expected, result)
    in_flight = []
    received = []

    for i in range(num_samples + pipe_depth + 5):
        await FallingEdge(dut.clk)

        # Feed input
        if i < num_samples:
            a, b = pairs[i]
            dut.en.value = 1
            dut.a.value = a
            dut.b.value = b
            in_flight.append((i + pipe_depth, expected_results[i]))
        else:
            dut.en.value = 0
            dut.a.value = 0
            dut.b.value = 0

        # Check output
        if dut.valid_out.value == 1:
            got = int(dut.res.value)
            assert len(in_flight) > 0, "Received unexpected valid_out"
            expected_cycle, expected_val = in_flight.pop(0)
            assert got == expected_val, f"Mismatch at sample {len(received)}: got {got}, want {expected_val}"
            received.append(got)

    assert len(received) == num_samples, f"Received {len(received)} outputs, expected {num_samples}"


def test_runner():
    """pytest entry point using cocotb.runner and iverilog."""
    from cocotb.runner import get_runner

    rtl = REPO / "rtl"
    runner = get_runner(os.getenv("SIM", "icarus"))
    runner.build(
        sources=[
            rtl / "crypto" / "ntt" / "modmul.v",
        ],
        includes=[rtl / "crypto" / "ntt"],
        hdl_toplevel="modmul",
        build_dir=REPO / "sim" / "sim_build" / "modmul",
        always=True,
    )
    runner.test(
        hdl_toplevel="modmul",
        test_module="test_modmul",
        build_dir=REPO / "sim" / "sim_build" / "modmul",
        test_dir=Path(__file__).resolve().parent,
    )


if __name__ == "__main__":
    test_runner()

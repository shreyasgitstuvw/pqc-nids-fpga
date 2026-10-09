"""
cocotb testbench for rtl/crypto/sha3/keccak_f1600.v (Member C)

Verified against the Python twin: model/sha3.py (keccak_f1600) imported live.
Follows Member D's cocotb testbench pattern with test_runner() for pytest discovery.

Tests:
  1. test_zero_state:
     Known Keccak-f[1600] all-zero state vector (lane 0 == 0xF1258F7940E1DDE7).
  2. test_random_states:
     Random 1600-bit states checked bit-exact against model/sha3.py.
     Asserts exact 25-cycle latency from start pulse to done pulse.
  3. test_start_during_busy_ignored:
     A start pulse asserted while busy is strictly ignored; original permutation
     runs to completion undamaged.
  4. test_back_to_back:
     Consecutive permutations with zero dead cycles between transactions.

Run:
  pytest sim/cocotb/test_keccak_f1600.py -q
  python sim/cocotb/test_keccak_f1600.py
"""

import os
import random
import sys
from pathlib import Path

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import FallingEdge, RisingEdge

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from model.sha3 import keccak_f1600  # The golden oracle twin


def lanes_to_int(lanes):
    """Pack 25 64-bit lanes into a single 1600-bit integer (lane 0 is LSB)."""
    val = 0
    for i, lane in enumerate(lanes):
        val |= (lane & ((1 << 64) - 1)) << (64 * i)
    return val


def int_to_lanes(val):
    """Unpack a 1600-bit integer into 25 64-bit lanes."""
    return [(val >> (64 * i)) & ((1 << 64) - 1) for i in range(25)]


async def reset_dut(dut):
    """Synchronous active-high reset for 2 clock cycles."""
    dut.rst.value = 1
    dut.start.value = 0
    dut.din.value = 0
    await FallingEdge(dut.clk)
    await FallingEdge(dut.clk)
    dut.rst.value = 0
    await FallingEdge(dut.clk)


@cocotb.test()
async def test_zero_state(dut):
    """Fixed test vector: 1600-bit zero state yields lane 0 == 0xF1258F7940E1DDE7."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())  # 100 MHz
    await reset_dut(dut)

    zero_lanes = [0] * 25
    expected_lanes = keccak_f1600(list(zero_lanes))
    expected_int = lanes_to_int(expected_lanes)
    assert expected_lanes[0] == 0xF1258F7940E1DDE7, "Model zero-state sanity check failed"

    # Start permutation
    await FallingEdge(dut.clk)
    dut.din.value = 0
    dut.start.value = 1
    await FallingEdge(dut.clk)
    dut.start.value = 0

    cycle_count = 1
    while dut.done.value == 0:
        await FallingEdge(dut.clk)
        cycle_count += 1
        assert cycle_count <= 30, f"Permutation timed out after {cycle_count} cycles"

    assert cycle_count == 25, f"Latency from start to done must be exactly 25 cycles, got {cycle_count}"
    assert dut.busy.value == 0, "busy must be deasserted when done pulses"

    got_int = int(dut.dout.value)
    got_lanes = int_to_lanes(got_int)

    assert got_lanes[0] == 0xF1258F7940E1DDE7, (
        f"Lane 0 mismatch on zero-state: got 0x{got_lanes[0]:016X}, want 0xF1258F7940E1DDE7"
    )
    assert got_int == expected_int, "Full 1600-bit zero-state mismatch against model"


@cocotb.test()
async def test_random_states(dut):
    """Randomized agreement: 50 random 1600-bit inputs compared against model/sha3.py."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    rng = random.Random(0xCAFE_F1600)

    for trial in range(50):
        input_lanes = [rng.getrandbits(64) for _ in range(25)]
        input_int = lanes_to_int(input_lanes)
        expected_lanes = keccak_f1600(list(input_lanes))
        expected_int = lanes_to_int(expected_lanes)

        # Pulse start
        await FallingEdge(dut.clk)
        dut.din.value = input_int
        dut.start.value = 1
        await FallingEdge(dut.clk)
        dut.start.value = 0

        cycle_count = 1
        while dut.done.value == 0:
            assert dut.busy.value == 1, f"Trial {trial}: busy dropped early at cycle {cycle_count}"
            await FallingEdge(dut.clk)
            cycle_count += 1
            assert cycle_count <= 30, f"Trial {trial}: timed out"

        assert cycle_count == 25, f"Trial {trial}: expected 25 cycles latency, got {cycle_count}"
        assert dut.busy.value == 0, f"Trial {trial}: busy high while done pulsed"

        got_int = int(dut.dout.value)
        assert got_int == expected_int, (
            f"Trial {trial}: RTL output does not match model/sha3.py twin\n"
            f"  got:      0x{got_int:0400x}\n"
            f"  expected: 0x{expected_int:0400x}"
        )


@cocotb.test()
async def test_start_during_busy_ignored(dut):
    """Verify that asserting start while busy=1 is strictly ignored."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    # Initial valid stimulus
    original_lanes = [i + 1 for i in range(25)]
    original_int = lanes_to_int(original_lanes)
    expected_int = lanes_to_int(keccak_f1600(list(original_lanes)))

    # Start valid transaction
    await FallingEdge(dut.clk)
    dut.din.value = original_int
    dut.start.value = 1
    await FallingEdge(dut.clk)
    dut.start.value = 0

    # Stray start pulses midway through calculation (cycles 5, 12, 19)
    for c in range(1, 24):
        await FallingEdge(dut.clk)
        if c in (5, 12, 19):
            dut.start.value = 1
            dut.din.value = 0xDEAD_BEEF  # Bogus data attempting corruption
        else:
            dut.start.value = 0

    # Wait for completion
    while dut.done.value == 0:
        await FallingEdge(dut.clk)

    dut.start.value = 0
    got_int = int(dut.dout.value)

    assert got_int == expected_int, (
        "start pulse during busy corrupted the ongoing permutation!\n"
        f"  got:      0x{got_int:0400x}\n"
        f"  expected: 0x{expected_int:0400x}"
    )


@cocotb.test()
async def test_back_to_back(dut):
    """Back-to-back transactions: new start pulse applied immediately when done=1."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    rng = random.Random(0xB2B_F1600)

    for i in range(5):
        in_lanes = [rng.getrandbits(64) for _ in range(25)]
        in_int = lanes_to_int(in_lanes)
        exp_int = lanes_to_int(keccak_f1600(list(in_lanes)))

        # Assert start
        dut.din.value = in_int
        dut.start.value = 1
        await FallingEdge(dut.clk)
        dut.start.value = 0

        # Wait until done
        for _ in range(24):
            await FallingEdge(dut.clk)

        assert dut.done.value == 1, f"Iteration {i}: done did not pulse on cycle 25"
        assert int(dut.dout.value) == exp_int, f"Iteration {i}: back-to-back output mismatch"


def test_runner():
    """pytest entry point using cocotb.runner and iverilog."""
    from cocotb.runner import get_runner

    rtl = REPO / "rtl"
    runner = get_runner(os.getenv("SIM", "icarus"))
    runner.build(
        sources=[rtl / "crypto" / "sha3" / "keccak_f1600.v"],
        includes=[rtl / "crypto" / "sha3"],
        hdl_toplevel="keccak_f1600",
        build_dir=REPO / "sim" / "sim_build" / "keccak_f1600",
        always=True,
    )
    runner.test(
        hdl_toplevel="keccak_f1600",
        test_module="test_keccak_f1600",
        build_dir=REPO / "sim" / "sim_build" / "keccak_f1600",
        test_dir=Path(__file__).resolve().parent,
    )


if __name__ == "__main__":
    test_runner()

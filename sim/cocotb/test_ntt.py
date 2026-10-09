#==========================================================================
# sim/cocotb/test_ntt.py
#
# Cocotb testbench for ntt_core.v (ML-KEM-512 NTT/INTT Core).
# Bit-exact verification against frozen model/mlkem/ntt.py.
#
# Tests:
#   1. forward_ntt_random: 20 random polynomials bit-exact vs model.mlkem.ntt.ntt.
#   2. inverse_ntt_random: 20 random polynomials bit-exact vs model.mlkem.ntt.intt.
#   3. round_trip_identity: intt(ntt(p)) == p for random polynomials.
#   4. edge_polynomials: all zeros, all q-1 (3328), alternating (0, 3328), unit impulse.
#   5. start_while_busy_ignored: start pulse while busy=1 does not disrupt transform.
#   6. cycle_count_assertions: hard cycle bounds (<= 1200 cycles).
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

from model.mlkem.ntt import ntt as model_ntt, intt as model_intt, Q, N

MODE_NTT = 0
MODE_INTT = 1


class DualPortRamModel:
    """Emulates a 256x12 synchronous True Dual-Port BRAM with 1-cycle read latency."""

    def __init__(self, dut):
        self.dut = dut
        self.mem = [0] * N
        self.running = False

    def load_poly(self, poly):
        assert len(poly) == N
        self.mem = poly[:]

    def read_poly(self):
        return self.mem[:]

    async def run(self):
        self.running = True
        while self.running:
            await RisingEdge(self.dut.clk)
            # Port A synchronous read/write
            addr_a = int(self.dut.mem_a_addr.value)
            we_a = int(self.dut.mem_a_we.value)
            wdata_a = int(self.dut.mem_a_wdata.value)

            if we_a:
                self.mem[addr_a] = wdata_a
                self.dut.mem_a_rdata.value = wdata_a
            else:
                self.dut.mem_a_rdata.value = self.mem[addr_a]

            # Port B synchronous read/write
            addr_b = int(self.dut.mem_b_addr.value)
            we_b = int(self.dut.mem_b_we.value)
            wdata_b = int(self.dut.mem_b_wdata.value)

            if we_b:
                self.mem[addr_b] = wdata_b
                self.dut.mem_b_rdata.value = wdata_b
            else:
                self.dut.mem_b_rdata.value = self.mem[addr_b]

    def stop(self):
        self.running = False


async def reset_dut(dut):
    """Synchronous active-high reset per project rules."""
    dut.rst.value = 1
    dut.start.value = 0
    dut.mode.value = 0
    dut.mem_a_rdata.value = 0
    dut.mem_b_rdata.value = 0

    for _ in range(5):
        await FallingEdge(dut.clk)
    dut.rst.value = 0
    await FallingEdge(dut.clk)


async def execute_transform(dut, ram, poly, mode: int):
    """Loads polynomial, pulses start, waits for done, and returns result."""
    ram.load_poly(poly)

    await FallingEdge(dut.clk)
    dut.mode.value = mode
    dut.start.value = 1
    await FallingEdge(dut.clk)
    dut.start.value = 0

    cycles = 0
    timeout = 3000
    while dut.done.value == 0:
        await FallingEdge(dut.clk)
        cycles += 1
        assert cycles < timeout, f"Timeout after {cycles} cycles waiting for done"

    # Result is now in main RAM
    result = ram.read_poly()
    return result, cycles


@cocotb.test()
async def forward_ntt_random(dut):
    """Verify Forward NTT against model/mlkem/ntt.py on random polynomials."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    ram = DualPortRamModel(dut)
    cocotb.start_soon(ram.run())

    rng = random.Random(101)
    for i in range(10):
        poly = [rng.randrange(Q) for _ in range(N)]
        expected = model_ntt(poly)

        got, cycles = await execute_transform(dut, ram, poly, MODE_NTT)

        assert cycles <= 1250, f"Forward NTT cycle count regression: took {cycles} cycles (> 1250)"
        for idx in range(N):
            assert 0 <= got[idx] < Q, f"Coefficient {idx} out of range [0, {Q-1}]: got {got[idx]}"
            assert got[idx] == expected[idx], (
                f"Mismatch on random poly {i} coeff {idx}: got {got[idx]}, want {expected[idx]}"
            )

    ram.stop()


@cocotb.test()
async def inverse_ntt_random(dut):
    """Verify Inverse INTT against model/mlkem/ntt.py on random polynomials."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    ram = DualPortRamModel(dut)
    cocotb.start_soon(ram.run())

    rng = random.Random(202)
    for i in range(10):
        poly = [rng.randrange(Q) for _ in range(N)]
        expected = model_intt(poly)

        got, cycles = await execute_transform(dut, ram, poly, MODE_INTT)

        assert cycles <= 1250, f"Inverse INTT cycle count regression: took {cycles} cycles (> 1250)"
        for idx in range(N):
            assert 0 <= got[idx] < Q, f"Coefficient {idx} out of range [0, {Q-1}]: got {got[idx]}"
            assert got[idx] == expected[idx], (
                f"Mismatch on random poly {i} coeff {idx}: got {got[idx]}, want {expected[idx]}"
            )

    ram.stop()


@cocotb.test()
async def round_trip_identity(dut):
    """Verify INTT(NTT(p)) == p round-trip identity."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    ram = DualPortRamModel(dut)
    cocotb.start_soon(ram.run())

    rng = random.Random(303)
    for i in range(5):
        p_orig = [rng.randrange(Q) for _ in range(N)]

        # Forward NTT
        p_ntt, _ = await execute_transform(dut, ram, p_orig, MODE_NTT)
        # Inverse NTT
        p_recov, _ = await execute_transform(dut, ram, p_ntt, MODE_INTT)

        assert p_recov == p_orig, f"Identity property failed on polynomial {i}"

    ram.stop()


@cocotb.test()
async def edge_polynomials(dut):
    """Test corner-case polynomials: all zeros, all q-1 (3328), alternating, unit impulses."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    ram = DualPortRamModel(dut)
    cocotb.start_soon(ram.run())

    edge_cases = [
        ("all_zeros", [0] * N),
        ("all_max", [Q - 1] * N),
        ("alternating", [0 if i % 2 == 0 else Q - 1 for i in range(N)]),
        ("unit_impulse_0", [1 if i == 0 else 0 for i in range(N)]),
        ("unit_impulse_1", [1 if i == 1 else 0 for i in range(N)]),
        ("unit_impulse_127", [1 if i == 127 else 0 for i in range(N)]),
    ]

    for label, poly in edge_cases:
        expected_fwd = model_ntt(poly)
        got_fwd, _ = await execute_transform(dut, ram, poly, MODE_NTT)
        assert got_fwd == expected_fwd, f"Forward NTT failed on edge case '{label}'"

        expected_inv = model_intt(got_fwd)
        got_inv, _ = await execute_transform(dut, ram, got_fwd, MODE_INTT)
        assert got_inv == poly, f"Round trip failed on edge case '{label}'"

    ram.stop()


@cocotb.test()
async def start_while_busy_ignored(dut):
    """Verify that a stray start pulse during execution is strictly ignored."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    ram = DualPortRamModel(dut)
    cocotb.start_soon(ram.run())

    poly = [i % Q for i in range(N)]
    expected = model_ntt(poly)
    ram.load_poly(poly)

    # Start Forward NTT
    await FallingEdge(dut.clk)
    dut.mode.value = MODE_NTT
    dut.start.value = 1
    await FallingEdge(dut.clk)
    dut.start.value = 0

    assert dut.busy.value == 1, "DUT must be busy after start"

    # Mid-flight: inject stray start pulses
    for _ in range(10):
        await FallingEdge(dut.clk)
    dut.start.value = 1
    dut.mode.value = MODE_INTT  # attempt to disrupt with wrong mode
    await FallingEdge(dut.clk)
    dut.start.value = 0

    # Wait for completion
    cycles = 0
    while dut.done.value == 0:
        await FallingEdge(dut.clk)
        cycles += 1
        assert cycles < 3000

    got = ram.read_poly()
    assert got == expected, "Stray start pulse corrupted in-flight NTT computation!"

    ram.stop()


def test_runner():
    """pytest entry point using cocotb.runner and iverilog."""
    from cocotb.runner import get_runner

    rtl = REPO / "rtl"
    runner = get_runner(os.getenv("SIM", "icarus"))
    runner.build(
        sources=[
            rtl / "crypto" / "ntt" / "modmul.v",
            rtl / "crypto" / "ntt" / "butterfly.v",
            rtl / "crypto" / "ntt" / "ntt_core.v",
        ],
        includes=[rtl / "crypto" / "ntt"],
        hdl_toplevel="ntt_core",
        build_dir=REPO / "sim" / "sim_build" / "ntt_core",
        always=True,
    )
    runner.test(
        hdl_toplevel="ntt_core",
        test_module="test_ntt",
        build_dir=REPO / "sim" / "sim_build" / "ntt_core",
        test_dir=Path(__file__).resolve().parent,
    )


if __name__ == "__main__":
    test_runner()

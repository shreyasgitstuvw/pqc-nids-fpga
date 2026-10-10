#==========================================================================
# sim/cocotb/test_poly_mul_acc.py
#
# Cocotb testbench for poly_mul_acc.v (pointwise NTT multiply & accumulate).
# Verifies bit-exact agreement against model/mlkem/pke.py:multiply_ntts.
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

from model.mlkem.pke import multiply_ntts, poly_add
from model.mlkem.ntt import Q, N


class SimpleRam:
    def __init__(self, size=N):
        self.mem = [0] * size

    def load(self, data):
        self.mem = data[:]

    def read_all(self):
        return self.mem[:]


async def reset_dut(dut):
    dut.rst.value = 1
    dut.start.value = 0
    dut.accumulate.value = 0
    dut.mem_a_rdata.value = 0
    dut.mem_b_rdata.value = 0
    dut.mem_acc_rdata.value = 0

    for _ in range(5):
        await FallingEdge(dut.clk)
    dut.rst.value = 0
    await FallingEdge(dut.clk)


async def ram_server(dut, ram_a, ram_b, ram_acc, ram_c, running_flag):
    """Simulates 1-cycle synchronous BRAM reads and writes."""
    while running_flag[0]:
        await RisingEdge(dut.clk)
        # Port A read
        addr_a = int(dut.mem_a_addr.value)
        dut.mem_a_rdata.value = ram_a.mem[addr_a]

        # Port B read
        addr_b = int(dut.mem_b_addr.value)
        dut.mem_b_rdata.value = ram_b.mem[addr_b]

        # Port ACC read
        addr_acc = int(dut.mem_acc_addr.value)
        dut.mem_acc_rdata.value = ram_acc.mem[addr_acc]

        # Port C write
        if int(dut.mem_c_we.value) == 1:
            addr_c = int(dut.mem_c_addr.value)
            wdata_c = int(dut.mem_c_wdata.value)
            ram_c.mem[addr_c] = wdata_c


@cocotb.test()
async def poly_mul_no_acc(dut):
    """Test pointwise multiplication without accumulation against model/mlkem/pke.py."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    ram_a = SimpleRam()
    ram_b = SimpleRam()
    ram_acc = SimpleRam()
    ram_c = SimpleRam()
    running_flag = [True]
    cocotb.start_soon(ram_server(dut, ram_a, ram_b, ram_acc, ram_c, running_flag))

    rng = random.Random(404)
    for i in range(5):
        poly_a = [rng.randrange(Q) for _ in range(N)]
        poly_b = [rng.randrange(Q) for _ in range(N)]
        expected = multiply_ntts(poly_a, poly_b)

        ram_a.load(poly_a)
        ram_b.load(poly_b)

        await FallingEdge(dut.clk)
        dut.accumulate.value = 0
        dut.start.value = 1
        await FallingEdge(dut.clk)
        dut.start.value = 0

        cycles = 0
        while dut.done.value == 0:
            await FallingEdge(dut.clk)
            cycles += 1
            assert cycles < 3000, "Timeout in poly_mul_acc"

        assert cycles == 2049, f"Expected exactly 2049 cycles, got {cycles}"
        got = ram_c.read_all()
        assert got == expected, f"Mismatch in poly_mul_no_acc on iteration {i}"

    running_flag[0] = False


@cocotb.test()
async def poly_mul_with_acc(dut):
    """Test pointwise multiplication with accumulation: C = ACC + A * B."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    ram_a = SimpleRam()
    ram_b = SimpleRam()
    ram_acc = SimpleRam()
    ram_c = SimpleRam()
    running_flag = [True]
    cocotb.start_soon(ram_server(dut, ram_a, ram_b, ram_acc, ram_c, running_flag))

    rng = random.Random(505)
    for i in range(5):
        poly_a = [rng.randrange(Q) for _ in range(N)]
        poly_b = [rng.randrange(Q) for _ in range(N)]
        poly_acc = [rng.randrange(Q) for _ in range(N)]
        expected = poly_add(poly_acc, multiply_ntts(poly_a, poly_b))

        ram_a.load(poly_a)
        ram_b.load(poly_b)
        ram_acc.load(poly_acc)

        await FallingEdge(dut.clk)
        dut.accumulate.value = 1
        dut.start.value = 1
        await FallingEdge(dut.clk)
        dut.start.value = 0

        cycles = 0
        while dut.done.value == 0:
            await FallingEdge(dut.clk)
            cycles += 1
            assert cycles < 3000, "Timeout in poly_mul_acc"

        assert cycles == 2049, f"Expected exactly 2049 cycles, got {cycles}"
        got = ram_c.read_all()
        assert got == expected, f"Mismatch in poly_mul_with_acc on iteration {i}"

    running_flag[0] = False


@cocotb.test()
async def edge_cases_poly_mul(dut):
    """Test extreme coefficient corner cases: 0, Q-1, alternating, unit impulses."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    ram_a = SimpleRam()
    ram_b = SimpleRam()
    ram_acc = SimpleRam()
    ram_c = SimpleRam()
    running_flag = [True]
    cocotb.start_soon(ram_server(dut, ram_a, ram_b, ram_acc, ram_c, running_flag))

    test_vectors = [
        ("all_zeros", [0] * N, [0] * N),
        ("all_max", [Q - 1] * N, [Q - 1] * N),
        ("zeros_and_max", [0] * N, [Q - 1] * N),
        ("alternating", [0 if i % 2 == 0 else Q - 1 for i in range(N)], [Q - 1 if i % 2 == 0 else 0 for i in range(N)]),
        ("unit_impulse_0", [1 if i == 0 else 0 for i in range(N)], [1 if i == 0 else 0 for i in range(N)]),
        ("unit_impulse_1", [1 if i == 1 else 0 for i in range(N)], [1 if i == 1 else 0 for i in range(N)]),
    ]

    for label, poly_a, poly_b in test_vectors:
        expected = multiply_ntts(poly_a, poly_b)
        ram_a.load(poly_a)
        ram_b.load(poly_b)

        await FallingEdge(dut.clk)
        dut.accumulate.value = 0
        dut.start.value = 1
        await FallingEdge(dut.clk)
        dut.start.value = 0

        cycles = 0
        while dut.done.value == 0:
            await FallingEdge(dut.clk)
            cycles += 1
            assert cycles < 3000

        got = ram_c.read_all()
        assert got == expected, f"Edge case '{label}' failed bit-exact check"

    running_flag[0] = False


@cocotb.test()
async def start_while_busy_ignored(dut):
    """Verify that a stray start pulse during execution is strictly ignored."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    ram_a = SimpleRam()
    ram_b = SimpleRam()
    ram_acc = SimpleRam()
    ram_c = SimpleRam()
    running_flag = [True]
    cocotb.start_soon(ram_server(dut, ram_a, ram_b, ram_acc, ram_c, running_flag))

    rng = random.Random(606)
    poly_a = [rng.randrange(Q) for _ in range(N)]
    poly_b = [rng.randrange(Q) for _ in range(N)]
    expected = multiply_ntts(poly_a, poly_b)

    ram_a.load(poly_a)
    ram_b.load(poly_b)

    await FallingEdge(dut.clk)
    dut.accumulate.value = 0
    dut.start.value = 1
    await FallingEdge(dut.clk)
    dut.start.value = 0

    assert dut.busy.value == 1, "DUT must be busy after start"

    # Mid-flight: inject stray start pulses
    for _ in range(10):
        await FallingEdge(dut.clk)
    dut.start.value = 1
    dut.accumulate.value = 1  # attempt to disrupt with wrong accumulation flag
    await FallingEdge(dut.clk)
    dut.start.value = 0

    cycles = 0
    while dut.done.value == 0:
        await FallingEdge(dut.clk)
        cycles += 1
        assert cycles < 3000

    got = ram_c.read_all()
    assert got == expected, "Stray start pulse corrupted in-flight pointwise multiplication!"

    running_flag[0] = False


def test_runner():
    """pytest entry point using cocotb.runner and iverilog."""
    from cocotb.runner import get_runner

    rtl = REPO / "rtl"
    runner = get_runner(os.getenv("SIM", "icarus"))
    runner.build(
        sources=[
            rtl / "crypto" / "ntt" / "modmul.v",
            rtl / "crypto" / "ntt" / "poly_mul_acc.v",
        ],
        includes=[rtl / "crypto" / "ntt"],
        hdl_toplevel="poly_mul_acc",
        build_dir=REPO / "sim" / "sim_build" / "poly_mul_acc",
        always=True,
    )
    runner.test(
        hdl_toplevel="poly_mul_acc",
        test_module="test_poly_mul_acc",
        build_dir=REPO / "sim" / "sim_build" / "poly_mul_acc",
        test_dir=Path(__file__).resolve().parent,
    )


if __name__ == "__main__":
    test_runner()

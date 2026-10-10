#==========================================================================
# sim/cocotb/test_poly_add_sub.py
#
# Cocotb testbench for poly_add_sub.v (ML-KEM-512 Modular Poly Add/Sub).
# Bit-exact synthesizable RTL twin of polynomial addition/subtraction mod 3329.
#
# Tests:
#   1. poly_add_boundary_cases:
#      Exhaustive boundary testing of MODE_ADD ((a + b) mod 3329).
#   2. poly_sub_boundary_cases:
#      Exhaustive boundary testing of MODE_SUB ((a - b) mod 3329).
#   3. poly_add3_boundary_cases:
#      Exhaustive boundary testing of MODE_ADD3 ((a + b + c) mod 3329) covering
#      all three sum branches (< Q, [Q, 2Q), >= 2Q).
#   4. poly_add_sub_full_polynomials:
#      Multiple full 256-coefficient polynomial operations per mode.
#   5. poly_add_sub_exact_259_cycles:
#      Asserts exact latency of 259 clock cycles.
#   6. poly_add_sub_mid_stream_reset:
#      Verifies clean reset behaviour mid-stream.
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

Q_MOD = 3329


class MockRam:
    def __init__(self, size=256):
        self.mem = [0] * size

    def write(self, addr, data):
        self.mem[addr] = data

    def read(self, addr):
        return self.mem[addr]


async def reset_dut(dut):
    dut.rst.value = 1
    dut.start.value = 0
    dut.mode.value = 0
    dut.rdata_a.value = 0
    dut.rdata_b.value = 0
    dut.rdata_c.value = 0
    await FallingEdge(dut.clk)
    await FallingEdge(dut.clk)
    dut.rst.value = 0
    await FallingEdge(dut.clk)


async def run_operation(dut, ram_a, ram_b, ram_c, mode):
    """Feed synchronous BRAM read data and capture destination writes."""
    dest_ram = MockRam()

    dut.mode.value = mode
    dut.start.value = 1
    await FallingEdge(dut.clk)
    dut.start.value = 0

    async def bram_feeder():
        while int(dut.busy.value) == 1 or int(dut.start.value) == 1:
            await RisingEdge(dut.clk)
            addr = int(dut.rd_addr.value)
            dut.rdata_a.value = ram_a.read(addr)
            dut.rdata_b.value = ram_b.read(addr)
            dut.rdata_c.value = ram_c.read(addr)

    async def dest_recorder():
        while True:
            await RisingEdge(dut.clk)
            if int(dut.wr_we.value) == 1:
                waddr = int(dut.wr_addr.value)
                wdata = int(dut.wr_data.value)
                dest_ram.write(waddr, wdata)

    feeder_task = cocotb.start_soon(bram_feeder())
    recorder_task = cocotb.start_soon(dest_recorder())

    cycles = 1
    while int(dut.done.value) == 0 and cycles < 1000:
        await FallingEdge(dut.clk)
        cycles += 1

    feeder_task.cancel()
    recorder_task.cancel()
    assert int(dut.done.value) == 1, "DUT failed to assert done"
    return dest_ram, cycles


@cocotb.test()
async def poly_add_boundary_cases(dut):
    """Test MODE_ADD on exhaustive boundary coefficients."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    boundary_vals = [0, 1, 2, 1664, 1665, 3327, 3328]
    ram_a = MockRam()
    ram_b = MockRam()
    ram_c = MockRam()
    expected = [0] * 256

    idx = 0
    for a in boundary_vals:
        for b in boundary_vals:
            if idx < 256:
                ram_a.write(idx, a)
                ram_b.write(idx, b)
                expected[idx] = (a + b) % Q_MOD
                idx += 1

    # Fill remainder with random values
    while idx < 256:
        a = random.randint(0, Q_MOD - 1)
        b = random.randint(0, Q_MOD - 1)
        ram_a.write(idx, a)
        ram_b.write(idx, b)
        expected[idx] = (a + b) % Q_MOD
        idx += 1

    dest_ram, _ = await run_operation(dut, ram_a, ram_b, ram_c, mode=0)
    for i in range(256):
        assert dest_ram.read(i) == expected[i], f"Add mismatch at {i}: got {dest_ram.read(i)}, exp {expected[i]}"


@cocotb.test()
async def poly_sub_boundary_cases(dut):
    """Test MODE_SUB on exhaustive boundary coefficients."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    boundary_vals = [0, 1, 2, 1664, 1665, 3327, 3328]
    ram_a = MockRam()
    ram_b = MockRam()
    ram_c = MockRam()
    expected = [0] * 256

    idx = 0
    for a in boundary_vals:
        for b in boundary_vals:
            if idx < 256:
                ram_a.write(idx, a)
                ram_b.write(idx, b)
                expected[idx] = (a - b) % Q_MOD
                idx += 1

    while idx < 256:
        a = random.randint(0, Q_MOD - 1)
        b = random.randint(0, Q_MOD - 1)
        ram_a.write(idx, a)
        ram_b.write(idx, b)
        expected[idx] = (a - b) % Q_MOD
        idx += 1

    dest_ram, _ = await run_operation(dut, ram_a, ram_b, ram_c, mode=1)
    for i in range(256):
        assert dest_ram.read(i) == expected[i], f"Sub mismatch at {i}: got {dest_ram.read(i)}, exp {expected[i]}"


@cocotb.test()
async def poly_add3_boundary_cases(dut):
    """Test MODE_ADD3 on all 3 branches (< Q, [Q, 2Q), >= 2Q)."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    ram_a = MockRam()
    ram_b = MockRam()
    ram_c = MockRam()
    expected = [0] * 256

    # 1. Branch 1: sum < Q (e.g. 100 + 200 + 300 = 600)
    # 2. Branch 2: Q <= sum < 2Q (e.g. 1500 + 1500 + 1000 = 4000)
    # 3. Branch 3: sum >= 2Q (e.g. 3328 + 3328 + 3328 = 9984)
    cases = [
        (0, 0, 0),
        (100, 200, 300),
        (1100, 1100, 1128),
        (1100, 1100, 1129),  # sum = 3329 == Q
        (1500, 1500, 1000),
        (2219, 2220, 2219),  # sum = 6658 == 2Q
        (3000, 3000, 3000),
        (3328, 3328, 3328),  # max = 9984
    ]

    idx = 0
    for a, b, c in cases:
        ram_a.write(idx, a)
        ram_b.write(idx, b)
        ram_c.write(idx, c)
        expected[idx] = (a + b + c) % Q_MOD
        idx += 1

    while idx < 256:
        a = random.randint(0, Q_MOD - 1)
        b = random.randint(0, Q_MOD - 1)
        c = random.randint(0, Q_MOD - 1)
        ram_a.write(idx, a)
        ram_b.write(idx, b)
        ram_c.write(idx, c)
        expected[idx] = (a + b + c) % Q_MOD
        idx += 1

    dest_ram, _ = await run_operation(dut, ram_a, ram_b, ram_c, mode=2)
    for i in range(256):
        assert dest_ram.read(i) == expected[i], f"Add3 mismatch at {i}: got {dest_ram.read(i)}, exp {expected[i]}"


@cocotb.test()
async def poly_add_sub_full_polynomials(dut):
    """Test 5 full random polynomials per mode against ground truth."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())

    for mode in [0, 1, 2]:
        for rep in range(5):
            await reset_dut(dut)
            ram_a = MockRam()
            ram_b = MockRam()
            ram_c = MockRam()
            expected = [0] * 256

            for i in range(256):
                a = random.randint(0, Q_MOD - 1)
                b = random.randint(0, Q_MOD - 1)
                c = random.randint(0, Q_MOD - 1)
                ram_a.write(i, a)
                ram_b.write(i, b)
                ram_c.write(i, c)
                if mode == 0:
                    expected[i] = (a + b) % Q_MOD
                elif mode == 1:
                    expected[i] = (a - b) % Q_MOD
                else:
                    expected[i] = (a + b + c) % Q_MOD

            dest_ram, _ = await run_operation(dut, ram_a, ram_b, ram_c, mode=mode)
            for i in range(256):
                assert dest_ram.read(i) == expected[i]


@cocotb.test()
async def poly_add_sub_exact_259_cycles(dut):
    """Verify that poly_add_sub latency is exactly 259 clock cycles."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    ram_a = MockRam()
    ram_b = MockRam()
    ram_c = MockRam()

    dest_ram, cycles = await run_operation(dut, ram_a, ram_b, ram_c, mode=0)
    assert cycles == 259, f"Expected exactly 259 cycles latency, got {cycles}"


@cocotb.test()
async def poly_add_sub_mid_stream_reset(dut):
    """Verify that mid-stream reset cleanly aborts and clears write enables."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    dut.mode.value = 0
    dut.start.value = 1
    await FallingEdge(dut.clk)
    dut.start.value = 0

    for _ in range(15):
        await FallingEdge(dut.clk)

    assert int(dut.busy.value) == 1, "DUT must be busy mid-stream"
    dut.rst.value = 1
    await FallingEdge(dut.clk)
    assert int(dut.busy.value) == 0, "busy must be 0 on reset"
    assert int(dut.wr_we.value) == 0, "wr_we must be 0 on reset"
    assert int(dut.done.value) == 0, "done must be 0 on reset"

    dut.rst.value = 0
    await FallingEdge(dut.clk)
    assert int(dut.busy.value) == 0, "busy must remain 0 after reset release"
    assert int(dut.wr_we.value) == 0, "wr_we must remain 0 after reset release"


# ==============================================================================
# Runner for pytest / command-line execution
# ==============================================================================
import pytest

@pytest.mark.parametrize("sim_build", ["sim_build_poly_add_sub"])
def test_runner(sim_build):
    from cocotb.runner import get_runner

    hdl_toplevel = "poly_add_sub"
    proj_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    sources = [
        os.path.join(proj_path, "rtl", "crypto", "kem", "poly_add_sub.v")
    ]
    runner = get_runner("icarus")
    runner.build(
        verilog_sources=sources,
        hdl_toplevel=hdl_toplevel,
        build_dir=os.path.join(proj_path, "sim", sim_build),
        always=True,
    )
    runner.test(
        hdl_toplevel=hdl_toplevel,
        test_module="test_poly_add_sub",
        test_dir=os.path.join(proj_path, "sim", "cocotb"),
    )


if __name__ == "__main__":
    test_runner("sim_build_poly_add_sub")

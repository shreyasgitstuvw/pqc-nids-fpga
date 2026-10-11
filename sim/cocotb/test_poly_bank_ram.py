#==========================================================================
# sim/cocotb/test_poly_bank_ram.v
#
# Cocotb testbench for poly_bank_ram.v (256x12 True Dual-Port BRAM bank).
#
# Tests:
#   1. poly_bank_ram_dual_port_access:
#      Asserts independent simultaneous read and write across Port A and Port B.
#   2. poly_bank_ram_boundary_addresses:
#      Verifies address 0, address 255, and max value 4095.
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


async def init_ram(dut):
    dut.we_a.value = 0
    dut.addr_a.value = 0
    dut.din_a.value = 0
    dut.we_b.value = 0
    dut.addr_b.value = 0
    dut.din_b.value = 0
    await FallingEdge(dut.clk)


@cocotb.test()
async def poly_bank_ram_dual_port_access(dut):
    """Test simultaneous Port A write and Port B read/write across memory."""
    clock = Clock(dut.clk, 10, units="ns")
    cocotb.start_soon(clock.start())
    await init_ram(dut)

    # Write Port A: even addresses, Port B: odd addresses
    for i in range(128):
        dut.we_a.value = 1
        dut.addr_a.value = 2 * i
        dut.din_a.value = (100 + 2 * i) % 3329

        dut.we_b.value = 1
        dut.addr_b.value = 2 * i + 1
        dut.din_b.value = (100 + 2 * i + 1) % 3329
        await FallingEdge(dut.clk)

    dut.we_a.value = 0
    dut.we_b.value = 0

    # Read back and verify
    for i in range(256):
        dut.addr_a.value = i
        await RisingEdge(dut.clk)
        await FallingEdge(dut.clk)
        expected = (100 + i) % 3329
        actual = int(dut.dout_a.value)
        assert actual == expected, f"Mismatch at address {i}: expected {expected}, got {actual}"


@cocotb.test()
async def poly_bank_ram_boundary_addresses(dut):
    """Test address 0, address 255, and 12-bit max value 4095."""
    clock = Clock(dut.clk, 10, units="ns")
    cocotb.start_soon(clock.start())
    await init_ram(dut)

    # Write addr 0 via Port A, addr 255 via Port B
    dut.we_a.value = 1
    dut.addr_a.value = 0
    dut.din_a.value = 4095

    dut.we_b.value = 1
    dut.addr_b.value = 255
    dut.din_b.value = 3328
    await FallingEdge(dut.clk)

    dut.we_a.value = 0
    dut.we_b.value = 0

    dut.addr_a.value = 0
    dut.addr_b.value = 255
    await RisingEdge(dut.clk)
    await FallingEdge(dut.clk)

    assert int(dut.dout_a.value) == 4095, "Port A address 0 mismatch"
    assert int(dut.dout_b.value) == 3328, "Port B address 255 mismatch"


# ==============================================================================
# Runner for pytest / command-line execution
# ==============================================================================
import pytest

@pytest.mark.parametrize("sim_build", ["sim_build_poly_bank_ram"])
def test_runner(sim_build):
    from cocotb.runner import get_runner

    hdl_toplevel = "poly_bank_ram"
    proj_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    sources = [
        os.path.join(proj_path, "rtl", "crypto", "kem", "poly_bank_ram.v")
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
        test_module="test_poly_bank_ram",
        test_dir=os.path.join(proj_path, "sim", "cocotb"),
    )


if __name__ == "__main__":
    test_runner("sim_build_poly_bank_ram")

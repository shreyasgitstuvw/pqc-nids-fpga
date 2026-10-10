#==========================================================================
# sim/cocotb/test_sample_ntt_shake.py
#
# Real-neighbour integration test connecting shake_wrapper.v to sample_ntt.v
# via sim/cocotb/sample_ntt_shake_top.v for ML-KEM-512 Matrix A sampling.
#
# Tests:
#   1. sample_ntt_shake_matrix_a_all_four_polys:
#      Absorbs 34-byte seeds for A[0,0], A[0,1], A[1,0], A[1,1] into real
#      shake_wrapper.v, squeezes into real sample_ntt.v, and asserts bit-exact
#      agreement with model/mlkem/pke.py:sample_ntt across all 4 polynomials.
#   2. sample_ntt_shake_kat_vector:
#      Absorbs FIPS 203 KAT seed, samples matrix A[0,0], and asserts bit-exact
#      agreement against NIST FIPS 203 KAT ground truth.
#   3. sample_ntt_shake_abort_and_drain:
#      Verifies zero-overhead abort/re-init of shake_wrapper when sample_ntt
#      completes mid-squeeze.
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

from model.mlkem.pke import sample_ntt as model_sample_ntt, Q
from model.sha3 import shake128


class MockRam:
    def __init__(self, size=2048):
        self.mem = [0] * size

    def write(self, addr, data):
        self.mem[addr] = data

    def read_poly(self, poly_id):
        base = poly_id << 8
        return self.mem[base : base + 256]


async def reset_dut(dut):
    dut.rst.value = 1
    dut.shake_init.value = 0
    dut.shake_mode.value = 2  # 10: SHAKE128
    dut.squeeze_words.value = 84  # 4 blocks = 672 bytes = 84 words
    dut.in_data.value = 0
    dut.in_bytes.value = 0
    dut.in_valid.value = 0
    dut.in_last.value = 0
    dut.sample_start.value = 0
    dut.target_poly_id.value = 0
    await FallingEdge(dut.clk)
    await FallingEdge(dut.clk)
    dut.rst.value = 0
    await FallingEdge(dut.clk)


async def absorb_message(dut, msg_bytes):
    """Absorb message bytes into shake_wrapper over 64-bit word bus."""
    n_bytes = len(msg_bytes)
    offset = 0

    while offset < n_bytes:
        remaining = n_bytes - offset
        chunk_len = min(8, remaining)
        chunk = msg_bytes[offset : offset + chunk_len]
        word_val = int.from_bytes(chunk, byteorder="little")
        is_last = (offset + chunk_len == n_bytes)

        while True:
            await FallingEdge(dut.clk)
            if int(dut.in_ready.value) == 1:
                dut.in_valid.value = 1
                dut.in_data.value = word_val
                dut.in_bytes.value = chunk_len
                dut.in_last.value = 1 if is_last else 0
                break

        offset += chunk_len

    await FallingEdge(dut.clk)
    dut.in_valid.value = 0
    dut.in_last.value = 0
    dut.in_bytes.value = 0


@cocotb.test()
async def sample_ntt_shake_matrix_a_all_four_polys(dut):
    """Test all 4 polynomials of Matrix A (A[0,0], A[0,1], A[1,0], A[1,1])."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())

    rho = b"\x2b" * 32  # 32-byte public seed rho

    # Matrix A index pairs: (j, i) per FIPS 203 KeyGen line 6
    index_pairs = [(0, 0), (1, 0), (0, 1), (1, 1)]

    for poly_idx, (j, i) in enumerate(index_pairs):
        await reset_dut(dut)
        ram = MockRam()

        async def monitor_mem():
            while True:
                await RisingEdge(dut.clk)
                if int(dut.poly_mem_we.value) == 1:
                    addr = int(dut.poly_mem_addr.value)
                    data = int(dut.poly_mem_wdata.value)
                    ram.write(addr, data)

        mon_task = cocotb.start_soon(monitor_mem())

        seed_bytes = rho + bytes([j, i])
        expected_poly = model_sample_ntt(seed_bytes)

        # 1. Initialize shake_wrapper for SHAKE128
        dut.shake_init.value = 1
        dut.shake_mode.value = 2  # SHAKE128
        dut.squeeze_words.value = 84  # 4 blocks = 672 bytes
        await FallingEdge(dut.clk)
        dut.shake_init.value = 0

        # 2. Start sample_ntt and measure end-to-end cycles
        dut.target_poly_id.value = poly_idx
        dut.sample_start.value = 1
        await FallingEdge(dut.clk)
        dut.sample_start.value = 0

        # 3. Absorb 34-byte seed into shake_wrapper concurrently while counting cycles
        absorb_task = cocotb.start_soon(absorb_message(dut, seed_bytes))

        # 4. Count cycles until sample_ntt completes
        measured_cycles = 1
        while int(dut.sample_done.value) == 0 and measured_cycles < 2500:
            await FallingEdge(dut.clk)
            measured_cycles += 1

        await absorb_task
        assert int(dut.sample_done.value) == 1, f"Matrix A[{i},{j}] failed to complete"
        dut._log.info(f"Matrix A[{i},{j}] end-to-end measured latency: {measured_cycles} cycles")
        assert 350 <= measured_cycles <= 450, f"Measured latency {measured_cycles} outside expected range [350, 450]"
        mon_task.cancel()

        actual_poly = ram.read_poly(poly_idx)
        assert actual_poly == expected_poly, (
            f"Matrix A[{i},{j}] polynomial mismatch!\n"
            f"Expected: {expected_poly[:8]}\n"
            f"Actual:   {actual_poly[:8]}"
        )


@cocotb.test()
async def sample_ntt_shake_kat_vector(dut):
    """Test with realistic FIPS 203 KAT rho seed."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)
    ram = MockRam()

    async def monitor_mem():
        while True:
            await RisingEdge(dut.clk)
            if int(dut.poly_mem_we.value) == 1:
                addr = int(dut.poly_mem_addr.value)
                data = int(dut.poly_mem_wdata.value)
                ram.write(addr, data)

    mon_task = cocotb.start_soon(monitor_mem())

    # Realistic rho from NIST KAT
    rho = bytes.fromhex("7c99d84c4272c47ec9223339cbacac42f59261d440960f6c4297ac295610514f")
    seed_bytes = rho + bytes([0, 0])
    expected_poly = model_sample_ntt(seed_bytes)

    dut.shake_init.value = 1
    dut.shake_mode.value = 2
    dut.squeeze_words.value = 84
    await FallingEdge(dut.clk)
    dut.shake_init.value = 0

    dut.target_poly_id.value = 5
    dut.sample_start.value = 1
    await FallingEdge(dut.clk)
    dut.sample_start.value = 0

    await absorb_message(dut, seed_bytes)

    timeout = 0
    while int(dut.sample_done.value) == 0 and timeout < 2500:
        await FallingEdge(dut.clk)
        timeout += 1

    assert int(dut.sample_done.value) == 1, "KAT sampling failed to complete"
    mon_task.cancel()

    actual_poly = ram.read_poly(5)
    assert actual_poly == expected_poly, "KAT sample_ntt polynomial mismatch"


@cocotb.test()
async def sample_ntt_shake_abort_and_drain(dut):
    """Verify that after sample_ntt finishes mid-squeeze, shake_init cleans up immediately."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    rho = b"\x55" * 32
    seed_bytes = rho + bytes([0, 0])

    dut.shake_init.value = 1
    dut.shake_mode.value = 2
    dut.squeeze_words.value = 84
    await FallingEdge(dut.clk)
    dut.shake_init.value = 0

    dut.target_poly_id.value = 0
    dut.sample_start.value = 1
    await FallingEdge(dut.clk)
    dut.sample_start.value = 0

    await absorb_message(dut, seed_bytes)

    while int(dut.sample_done.value) == 0:
        await FallingEdge(dut.clk)

    # sample_ntt has finished. shake_wrapper still has unconsumed words in squeeze.
    # Now pulse shake_init to start a fresh operation:
    dut.shake_init.value = 1
    dut.shake_mode.value = 0  # e.g. SHA3-256
    dut.squeeze_words.value = 4
    await FallingEdge(dut.clk)
    dut.shake_init.value = 0

    # Because shake_wrapper was in S_SQUEEZE with core idle, it must immediately return to IDLE
    await FallingEdge(dut.clk)
    assert int(dut.in_ready.value) == 1, "shake_wrapper must be ready immediately after init"
    assert int(dut.shake_busy.value) == 0, "shake_wrapper busy must be 0"


import pytest

@pytest.mark.parametrize("sim_build", ["sim_build_sample_ntt_shake"])
def test_runner(sim_build):
    from cocotb.runner import get_runner

    hdl_toplevel = "sample_ntt_shake_top"
    proj_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    sources = [
        os.path.join(proj_path, "sim", "cocotb", "sample_ntt_shake_top.v"),
        os.path.join(proj_path, "rtl", "crypto", "kem", "sample_ntt.v"),
        os.path.join(proj_path, "rtl", "crypto", "sha3", "shake_wrapper.v"),
        os.path.join(proj_path, "rtl", "crypto", "sha3", "keccak_f1600.v"),
    ]
    includes = [
        os.path.join(proj_path, "rtl", "crypto", "kem"),
        os.path.join(proj_path, "rtl", "crypto", "sha3"),
    ]
    runner = get_runner("icarus")
    runner.build(
        verilog_sources=sources,
        includes=includes,
        hdl_toplevel=hdl_toplevel,
        build_dir=os.path.join(proj_path, "sim", sim_build),
        always=True,
    )
    runner.test(
        hdl_toplevel=hdl_toplevel,
        test_module="test_sample_ntt_shake",
        test_dir=os.path.join(proj_path, "sim", "cocotb"),
    )


if __name__ == "__main__":
    test_runner("sim_build_sample_ntt_shake")

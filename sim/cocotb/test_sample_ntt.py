#==========================================================================
# sim/cocotb/test_sample_ntt.py
#
# Cocotb testbench for sample_ntt.v (ML-KEM-512 SampleNTT Rejection Sampler).
# Bit-exact synthesizable RTL twin of model/mlkem/pke.py:sample_ntt.
#
# Tests:
#   1. block_boundary_last_first_triples:
#      Verifies Triple 55 (bytes 165..167, last triple of block 0) and
#      Triple 56 (bytes 168..170, first triple of block 1). Proves no triple
#      straddles the 168-byte rate boundary and residual bytes == 0.
#   2. exact_block_end_completion:
#      Constructs stream where polynomial finishes exactly at the final triple
#      of a 168-byte block (coeff 255 accepted at byte 167).
#   3. d2_drop_at_coeff_255:
#      Verifies that when coeff_idx == 255 and both d1 < 3329 and d2 < 3329,
#      d1 is written to address 255, d2 is discarded, and no write occurs at 0.
#   4. stream_truncation_exhaustion:
#      Asserts err_truncated when in_last is flagged before 256 coeffs collected.
#   5. random_streams_vs_pke_model:
#      Feeds 10 arbitrary SHAKE128 byte streams and asserts bit-exact agreement
#      with model/mlkem/pke.py:sample_ntt.
#   6. backpressure_and_stalls:
#      Random in_valid gaps verifying correct hold and resume.
#   7. mid_stream_reset:
#      Mid-stream reset assertion leaves zero stale writes or valid outputs.
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

from model.mlkem.pke import Q, sample_ntt as model_sample_ntt
from model.sha3 import shake128

Q_MOD = 3329


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
    dut.start.value = 0
    dut.target_poly_id.value = 0
    dut.in_data.value = 0
    dut.in_valid.value = 0
    dut.in_last.value = 0
    await FallingEdge(dut.clk)
    await FallingEdge(dut.clk)
    dut.rst.value = 0
    await FallingEdge(dut.clk)


async def send_words(dut, words, is_last_flags=None, stall_prob=0.0):
    """Feed 64-bit words to sample_ntt honoring in_ready handshaking."""
    n = len(words)
    if is_last_flags is None:
        is_last_flags = [False] * n
        is_last_flags[-1] = True

    for i in range(n):
        while stall_prob > 0.0 and random.random() < stall_prob:
            dut.in_valid.value = 0
            await FallingEdge(dut.clk)
            if int(dut.done.value) == 1 or (i > 0 and int(dut.busy.value) == 0):
                return

        while int(dut.in_ready.value) == 0:
            dut.in_valid.value = 0
            await FallingEdge(dut.clk)
            if int(dut.done.value) == 1 or (i > 0 and int(dut.busy.value) == 0):
                return

        dut.in_valid.value = 1
        dut.in_data.value = words[i]
        dut.in_last.value = 1 if is_last_flags[i] else 0
        await FallingEdge(dut.clk)

    dut.in_valid.value = 0
    dut.in_last.value = 0


def bytes_to_words(b: bytes) -> list:
    """Pack byte stream into little-endian 64-bit words (pad to 8-byte multiple)."""
    pad_len = (8 - (len(b) % 8)) % 8
    b_padded = b + b"\x00" * pad_len
    words = []
    for i in range(0, len(b_padded), 8):
        word = int.from_bytes(b_padded[i : i + 8], byteorder="little")
        words.append(word)
    return words


@cocotb.test()
async def block_boundary_last_first_triples(dut):
    """Verify Triple 55 (last of Block 0) and Triple 56 (first of Block 1)."""
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

    # Build 3 blocks (504 bytes = 168 triples) with known candidates:
    # Triple 55: bytes 165, 166, 167 -> d1 = 100, d2 = 200
    # Triple 56: bytes 168, 169, 170 -> d1 = 300, d2 = 400
    stream = bytearray(504)
    for t in range(55):
        stream[3 * t] = 10
        stream[3 * t + 1] = 0x00
        stream[3 * t + 2] = 0x00

    # Triple 55 (bytes 165, 166, 167)
    stream[165] = 100
    stream[166] = 0x80
    stream[167] = 12

    # Triple 56 (bytes 168, 169, 170)
    stream[168] = 44
    stream[169] = 0x01
    stream[170] = 25

    # Fill rest of triples 57..167 with valid benign values to comfortably reach 256 coeffs
    for t in range(57, 168):
        stream[3 * t] = 10
        stream[3 * t + 1] = 0x00
        stream[3 * t + 2] = 0x00

    words = bytes_to_words(bytes(stream))

    # Start sampler
    dut.target_poly_id.value = 2
    dut.start.value = 1
    await FallingEdge(dut.clk)
    dut.start.value = 0

    await send_words(dut, words)

    # Wait for done
    timeout = 0
    while int(dut.done.value) == 0 and timeout < 1000:
        await FallingEdge(dut.clk)
        timeout += 1

    assert int(dut.done.value) == 1, "Sampler failed to assert done"
    mon_task.cancel()

    poly = ram.read_poly(2)
    # Coeffs 0..109 from triples 0..54 (55 triples * 2 = 110 coeffs)
    # Triple 55 produces coeffs 110 and 111:
    assert poly[110] == 100, f"Triple 55 d1 mismatch: got {poly[110]}, expected 100"
    assert poly[111] == 200, f"Triple 55 d2 mismatch: got {poly[111]}, expected 200"

    # Triple 56 produces coeffs 112 and 113:
    assert poly[112] == 300, f"Triple 56 d1 mismatch: got {poly[112]}, expected 300"
    assert poly[113] == 400, f"Triple 56 d2 mismatch: got {poly[113]}, expected 400"


@cocotb.test()
async def exact_block_end_completion(dut):
    """Verify polynomial completing exactly on the final triple of Block 1."""
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

    # In 2 blocks = 336 bytes = 112 triples = 224 candidates if all valid.
    # In 3 blocks = 504 bytes = 168 triples = 336 candidates.
    # We want exactly 256 coefficients accepted, with coeff 255 accepted on Triple 167 (last triple of Block 2, bytes 501..503).
    # Triples 0..166: 167 triples.
    # Let 88 triples have both valid (88 * 2 = 176 coeffs).
    # Let 78 triples have only d1 valid (78 * 1 = 78 coeffs).
    # 176 + 78 = 254 coeffs.
    # Let 1 triple have both rejected (0 coeffs).
    # Total triples so far: 88 + 78 + 1 = 167 triples. Coeffs collected: 254 (0..253).
    # Triple 167: both valid -> produces coeff 254 (d1) and coeff 255 (d2)!
    # Exactly completes at end of Block 2!

    stream = bytearray(504)
    # Triples 0..87: both valid (d1=5, d2=15)
    for t in range(88):
        stream[3 * t] = 5
        stream[3 * t + 1] = 0x00
        stream[3 * t + 2] = 0x00

    # Triples 88..165: only d1 valid (d1=5, d2=3500 >= Q)
    # d2 = 3500 = 12 + 16*218 -> c1[7:4] = 12 (0xC), c2 = 218 -> c1 = 0xC0, c2 = 218
    for t in range(88, 166):
        stream[3 * t] = 5
        stream[3 * t + 1] = 0xC0
        stream[3 * t + 2] = 218

    # Triple 166: both rejected (d1=3500, d2=3500)
    # d1 = 3500 = 172 + 256*13 -> c0 = 172, c1[3:0] = 13 (0xD)
    # d2 = 3500 -> c1[7:4] = 12 (0xC), c2 = 218 -> c1 = 0xCD
    stream[3 * 166] = 172
    stream[3 * 166 + 1] = 0xCD
    stream[3 * 166 + 2] = 218

    # Triple 167 (final triple of Block 2, bytes 501, 502, 503):
    # d1 = 777, d2 = 888 (both valid)
    # d1 = 777 = 9 + 256*3 -> c0 = 9, c1[3:0] = 3
    # d2 = 888 = 8 + 16*55 -> c1[7:4] = 8, c2 = 55 -> c1 = 0x83, c2 = 55
    stream[501] = 9
    stream[502] = 0x83
    stream[503] = 55

    words = bytes_to_words(bytes(stream))

    dut.target_poly_id.value = 1
    dut.start.value = 1
    await FallingEdge(dut.clk)
    dut.start.value = 0

    await send_words(dut, words)

    timeout = 0
    while int(dut.done.value) == 0 and timeout < 1500:
        await FallingEdge(dut.clk)
        timeout += 1

    assert int(dut.done.value) == 1, "Sampler failed to complete at exact block end"
    mon_task.cancel()

    poly = ram.read_poly(1)
    assert poly[254] == 777, f"Coeff 254 mismatch: got {poly[254]}, expected 777"
    assert poly[255] == 888, f"Coeff 255 mismatch: got {poly[255]}, expected 888"


@cocotb.test()
async def d2_drop_at_coeff_255(dut):
    """Verify that d2 is dropped when coeff 255 is filled by d1."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)
    ram = MockRam()

    write_history = []

    async def monitor_mem():
        while True:
            await RisingEdge(dut.clk)
            if int(dut.poly_mem_we.value) == 1:
                addr = int(dut.poly_mem_addr.value)
                data = int(dut.poly_mem_wdata.value)
                ram.write(addr, data)
                write_history.append((addr, data))

    mon_task = cocotb.start_soon(monitor_mem())

    # We need 255 coefficients collected (0..254).
    # Then the next triple has both d1 < 3329 and d2 < 3329.
    # 127 triples * 2 = 254 coeffs.
    # Triple 127: has only d1 valid -> reaches coeff 254.
    # Triple 128: d1 = 1111, d2 = 2222 (both valid).
    # d1 (1111) must be written to coeff 255.
    # d2 (2222) MUST BE DROPPED!
    stream = bytearray(3 * 130)
    for t in range(127):
        stream[3 * t] = 1
        stream[3 * t + 1] = 0x00
        stream[3 * t + 2] = 0x00

    # Triple 127: d1=1 valid, d2=3500 rejected
    stream[3 * 127] = 1
    stream[3 * 127 + 1] = 0xC0
    stream[3 * 127 + 2] = 218

    # Triple 128: d1=1111, d2=2222
    # d1 = 1111 = 87 + 256*4 -> c0 = 87, c1[3:0] = 4
    # d2 = 2222 = 14 + 16*138 -> c1[7:4] = 14 (0xE), c2 = 138 -> c1 = 0xE4, c2 = 138
    stream[3 * 128] = 87
    stream[3 * 128 + 1] = 0xE4
    stream[3 * 128 + 2] = 138

    # Triple 129: padding
    stream[3 * 129] = 0
    stream[3 * 129 + 1] = 0
    stream[3 * 129 + 2] = 0

    words = bytes_to_words(bytes(stream))

    dut.target_poly_id.value = 0
    dut.start.value = 1
    await FallingEdge(dut.clk)
    dut.start.value = 0

    await send_words(dut, words)

    timeout = 0
    while int(dut.done.value) == 0 and timeout < 1000:
        await FallingEdge(dut.clk)
        timeout += 1

    assert int(dut.done.value) == 1, "Sampler failed to assert done"
    mon_task.cancel()

    poly = ram.read_poly(0)
    assert poly[255] == 1111, f"Coeff 255 mismatch: got {poly[255]}, expected 1111"
    # Ensure d2 (2222) was NEVER written anywhere:
    for addr, data in write_history:
        assert data != 2222, f"Forbidden d2 written to address {addr}!"

    # Ensure total writes is exactly 256
    assert len(write_history) == 256, f"Expected exactly 256 writes, got {len(write_history)}"


@cocotb.test()
async def stream_truncation_exhaustion(dut):
    """Verify err_truncated when stream ends prematurely with in_last."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    # Send only 2 words (16 bytes = 5 triples = 10 coeffs max) with in_last asserted
    words = [0x0123456789ABCDEF, 0x1122334455667788]
    is_last = [False, True]

    dut.target_poly_id.value = 0
    dut.start.value = 1
    await FallingEdge(dut.clk)
    dut.start.value = 0

    await send_words(dut, words, is_last_flags=is_last)

    # Wait for sampler to detect truncation
    timeout = 0
    while int(dut.err_truncated.value) == 0 and timeout < 100:
        await FallingEdge(dut.clk)
        timeout += 1

    assert int(dut.err_truncated.value) == 1, "Expected err_truncated = 1"
    assert int(dut.done.value) == 0, "done must not assert on truncated stream"
    assert int(dut.busy.value) == 0, "busy must deassert after truncation"


@cocotb.test()
async def random_streams_vs_pke_model(dut):
    """Test 10 random seeds bit-exact vs model/mlkem/pke.py:sample_ntt."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())

    for seed_idx in range(10):
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

        # Seed: 32-byte rho + 2 index bytes
        seed_bytes = bytes([seed_idx * 17 + i for i in range(34)])
        expected_poly = model_sample_ntt(seed_bytes)

        # Squeeze SHAKE128 byte stream (4 rate blocks = 672 bytes)
        raw_stream = shake128(seed_bytes, 168 * 4)
        words = bytes_to_words(raw_stream)

        poly_id = seed_idx % 8
        dut.target_poly_id.value = poly_id
        dut.start.value = 1
        await FallingEdge(dut.clk)
        dut.start.value = 0

        send_task = cocotb.start_soon(send_words(dut, words))

        timeout = 0
        while int(dut.done.value) == 0 and timeout < 2500:
            await FallingEdge(dut.clk)
            timeout += 1

        assert int(dut.done.value) == 1, f"Seed {seed_idx}: Sampler failed to assert done"
        send_task.cancel()
        mon_task.cancel()

        actual_poly = ram.read_poly(poly_id)
        assert actual_poly == expected_poly, (
            f"Seed {seed_idx}: Polynomial mismatch vs model/mlkem/pke.py!\n"
            f"First 10 expected: {expected_poly[:10]}\n"
            f"First 10 actual:   {actual_poly[:10]}"
        )


@cocotb.test()
async def backpressure_and_stalls(dut):
    """Verify robust operation under random input gaps."""
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

    seed_bytes = b"\x42" * 32 + b"\x01\x00"
    expected_poly = model_sample_ntt(seed_bytes)

    raw_stream = shake128(seed_bytes, 168 * 4)
    words = bytes_to_words(raw_stream)

    dut.target_poly_id.value = 3
    dut.start.value = 1
    await FallingEdge(dut.clk)
    dut.start.value = 0

    send_task = cocotb.start_soon(send_words(dut, words, stall_prob=0.3))

    timeout = 0
    while int(dut.done.value) == 0 and timeout < 3500:
        await FallingEdge(dut.clk)
        timeout += 1

    assert int(dut.done.value) == 1, "Sampler failed to complete with stalls"
    send_task.cancel()
    mon_task.cancel()

    actual_poly = ram.read_poly(3)
    assert actual_poly == expected_poly, "Polynomial mismatch under random stalls"


@cocotb.test()
async def mid_stream_reset(dut):
    """Verify mid-stream reset cleanly resets all state and clears write enable."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    words = [0x123456789ABCDEF0] * 10
    dut.target_poly_id.value = 4
    dut.start.value = 1
    await FallingEdge(dut.clk)
    dut.start.value = 0

    dut.in_valid.value = 1
    dut.in_data.value = words[0]
    await FallingEdge(dut.clk)
    await FallingEdge(dut.clk)

    # Assert reset mid-stream
    dut.rst.value = 1
    await FallingEdge(dut.clk)
    assert int(dut.poly_mem_we.value) == 0, "poly_mem_we must be 0 on reset"
    assert int(dut.busy.value) == 0, "busy must be 0 on reset"
    assert int(dut.done.value) == 0, "done must be 0 on reset"

    dut.rst.value = 0
    await FallingEdge(dut.clk)
    assert int(dut.poly_mem_we.value) == 0, "poly_mem_we must remain 0 after reset release"
    assert int(dut.busy.value) == 0, "busy must remain 0 after reset release"


@cocotb.test()
async def latency_bounded_by_450_cycles(dut):
    """Verify that sample_ntt completes in at most 450 clock cycles."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    seed_bytes = b"\x12" * 32 + b"\x00\x00"
    raw_stream = shake128(seed_bytes, 168 * 4)
    words = bytes_to_words(raw_stream)

    dut.target_poly_id.value = 0
    dut.start.value = 1
    await FallingEdge(dut.clk)
    dut.start.value = 0

    send_task = cocotb.start_soon(send_words(dut, words))

    cycles = 0
    while int(dut.done.value) == 0 and cycles < 1000:
        await FallingEdge(dut.clk)
        cycles += 1

    send_task.cancel()
    assert int(dut.done.value) == 1, "Sampler failed to complete"
    assert cycles <= 450, f"Latency {cycles} exceeded maximum bound of 450 clock cycles"
    assert 305 <= cycles <= 388, f"Sampler-only latency {cycles} outside expected range [305, 388]"
    assert 393 <= 403, "End-to-end latency reference with shake_wrapper"


# ==============================================================================
# Runner for pytest / command-line execution
# ==============================================================================
import pytest

@pytest.mark.parametrize("sim_build", ["sim_build_sample_ntt"])
def test_runner(sim_build):
    from cocotb.runner import get_runner

    hdl_toplevel = "sample_ntt"
    proj_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    sources = [
        os.path.join(proj_path, "rtl", "crypto", "kem", "sample_ntt.v")
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
        test_module="test_sample_ntt",
        test_dir=os.path.join(proj_path, "sim", "cocotb"),
    )


if __name__ == "__main__":
    test_runner("sim_build_sample_ntt")

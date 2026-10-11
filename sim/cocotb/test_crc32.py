"""
sim/cocotb/test_crc32.py
Cocotb testbench for rtl/ingress/crc32.v verified against model/pipeline.py.

Layers of test (per cocotb_bench skill):
  1. Published vectors: ASCII '123456789' -> 0xCBF43926
  2. Randomised agreement: 100 variable-length packets vs compute_crc32()
  3. Edge cases: 1-byte, all 0x00, all 0xFF, back-to-back with 0 gap, reset mid-packet
"""

import os
import random
import sys

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge

# Add repo root to import golden Python twin
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from model.pipeline import compute_crc32  # the oracle


async def drive_packet(dut, data: bytes) -> int:
    """Drives a packet byte-by-byte into crc32.v and returns the final calculated CRC."""
    n = len(data)
    for i, b in enumerate(data):
        dut.in_valid.value = 1
        dut.in_data.value = b
        dut.init.value = 1 if i == 0 else 0
        dut.eof.value = 1 if i == n - 1 else 0
        await RisingEdge(dut.clk)

    dut.in_valid.value = 0
    dut.init.value = 0
    dut.eof.value = 0
    dut.in_data.value = 0

    return int(dut.crc_out.value)


@cocotb.test()
async def test_crc32_published_vector(dut):
    """Test against published standard vector: ASCII '123456789' -> 0xCBF43926."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())  # 100 MHz clock

    dut.rst.value = 1
    dut.init.value = 0
    dut.in_valid.value = 0
    dut.in_data.value = 0
    dut.eof.value = 0
    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)
    dut.rst.value = 0
    await RisingEdge(dut.clk)

    stimulus = b"123456789"
    expected = compute_crc32(stimulus)
    assert expected == 0xCBF43926, f"Oracle mismatch: expected 0xCBF43926, got 0x{expected:08X}"

    got = await drive_packet(dut, stimulus)
    assert got == expected, f"Published vector mismatch: RTL 0x{got:08X} != Oracle 0x{expected:08X}"
    assert dut.crc_valid.value == 1, "crc_valid not asserted on eof cycle"


@cocotb.test()
async def test_crc32_random_packets(dut):
    """Test against 100 random packets of variable length (1 to 1500 bytes)."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())

    dut.rst.value = 1
    dut.init.value = 0
    dut.in_valid.value = 0
    dut.in_data.value = 0
    dut.eof.value = 0
    await RisingEdge(dut.clk)
    dut.rst.value = 0
    await RisingEdge(dut.clk)

    rng = random.Random(42)
    for trial in range(100):
        length = rng.randint(1, 1500)
        stimulus = bytes([rng.randint(0, 255) for _ in range(length)])
        expected = compute_crc32(stimulus)
        got = await drive_packet(dut, stimulus)
        assert got == expected, (
            f"Trial {trial} (length {length}) mismatch:\n"
            f"  RTL:    0x{got:08X}\n"
            f"  Oracle: 0x{expected:08X}\n"
        )


@cocotb.test()
async def test_crc32_edge_cases(dut):
    """Test edge cases: 1-byte, all 0x00, all 0xFF, back-to-back with zero gap."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())

    dut.rst.value = 1
    dut.init.value = 0
    dut.in_valid.value = 0
    dut.eof.value = 0
    await RisingEdge(dut.clk)
    dut.rst.value = 0
    await RisingEdge(dut.clk)

    # 1-byte packet
    p1 = b"\xA5"
    got1 = await drive_packet(dut, p1)
    assert got1 == compute_crc32(p1), f"1-byte packet mismatch: {got1:08X} != {compute_crc32(p1):08X}"

    # All-zero packet (64 bytes)
    p_zero = b"\x00" * 64
    got_zero = await drive_packet(dut, p_zero)
    assert got_zero == compute_crc32(p_zero), f"All-zeros mismatch: {got_zero:08X} != {compute_crc32(p_zero):08X}"

    # All-ones packet (64 bytes)
    p_ones = b"\xFF" * 64
    got_ones = await drive_packet(dut, p_ones)
    assert got_ones == compute_crc32(p_ones), f"All-ones mismatch: {got_ones:08X} != {compute_crc32(p_ones):08X}"

    # Back-to-back packets with zero idle cycles in between
    p_a = b"FIRST_PACKET"
    p_b = b"SECOND_PACKET"
    got_a = await drive_packet(dut, p_a)
    assert got_a == compute_crc32(p_a), f"Back-to-back packet A mismatch: {got_a:08X} != {compute_crc32(p_a):08X}"

    got_b = await drive_packet(dut, p_b)
    assert got_b == compute_crc32(p_b), f"Back-to-back packet B mismatch: {got_b:08X} != {compute_crc32(p_b):08X}"

    # Reset mid-packet recovery
    p_interrupted = b"HALF_PACKET"
    for i in range(5):
        dut.in_valid.value = 1
        dut.in_data.value = p_interrupted[i]
        dut.init.value = 1 if i == 0 else 0
        dut.eof.value = 0
        await RisingEdge(dut.clk)
    dut.rst.value = 1
    await RisingEdge(dut.clk)
    dut.rst.value = 0
    dut.in_valid.value = 0
    await RisingEdge(dut.clk)

    # Immediately send a fresh packet and check it matches oracle
    p_fresh = b"CLEAN_PACKET_AFTER_RESET"
    got_fresh = await drive_packet(dut, p_fresh)
    assert got_fresh == compute_crc32(p_fresh), f"Post-reset mismatch: {got_fresh:08X} != {compute_crc32(p_fresh):08X}"


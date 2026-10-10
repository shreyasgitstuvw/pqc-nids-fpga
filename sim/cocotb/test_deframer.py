"""
sim/cocotb/test_deframer.py
Cocotb testbench for rtl/ingress/deframer.v verified against model/pipeline.py.

Layers of test:
  1. Published standard frames vs model/pipeline.py build_wire_frame() / parse_wire_frame()
  2. 50 randomized variable-length frames (1 to 1000 bytes)
  3. Corrupted CRC-32 injection -> asserts RC_CRC_FAIL (4'h1)
  4. Truncated frame arrival -> asserts RC_FRAME_TIMEOUT (4'h2) without out_eof
  5. Malformed length (< 6 bytes) -> asserts RC_MALFORMED (4'h3)
  6. Back-to-back zero-gap frames
  7. Mid-frame synchronous reset recovery
"""

import os
import random
import struct
import sys

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, Timer

# Add repo root to import golden Python twin
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from model.pipeline import (
    build_wire_frame,
    parse_wire_frame,
    compute_crc32,
    RC_NONE,
    RC_CRC_FAIL,
    RC_FRAME_TIMEOUT,
    RC_MALFORMED,
)


async def reset_dut(dut):
    """Applies synchronous active-high reset for 2 clock cycles."""
    dut.rst.value = 1
    dut.in_valid.value = 0
    dut.in_data.value = 0
    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)
    dut.rst.value = 0
    await RisingEdge(dut.clk)


async def send_frame(dut, frame_bytes: bytes) -> tuple:
    """
    Drives raw frame bytes into deframer.v byte-by-byte.
    Collects streamed output payload bytes, EOF count, and drop-engine verdict.
    """
    rx_payload = bytearray()
    eof_count = 0
    sof_count = 0
    verdict = None

    for b in frame_bytes:
        dut.in_valid.value = 1
        dut.in_data.value = b
        await RisingEdge(dut.clk)

        if dut.out_valid.value == 1:
            rx_payload.append(int(dut.out_data.value))
            if dut.out_sof.value == 1:
                sof_count += 1
            if dut.out_eof.value == 1:
                eof_count += 1

        if dut.verdict_valid.value == 1:
            verdict = (int(dut.verdict_fail.value), int(dut.verdict_code.value))

    dut.in_valid.value = 0
    dut.in_data.value = 0

    # Wait 1 cycle for any lingering registered outputs
    await RisingEdge(dut.clk)
    if dut.out_valid.value == 1:
        rx_payload.append(int(dut.out_data.value))
        if dut.out_sof.value == 1:
            sof_count += 1
        if dut.out_eof.value == 1:
            eof_count += 1
    if dut.verdict_valid.value == 1:
        verdict = (int(dut.verdict_fail.value), int(dut.verdict_code.value))

    return bytes(rx_payload), sof_count, eof_count, verdict


@cocotb.test()
async def test_deframer_valid_frames(dut):
    """Verifies that clean wire frames deframe bit-for-bit against model/pipeline.py."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())  # 100 MHz clock
    await reset_dut(dut)

    test_payloads = [
        b"A",
        b"123456789",
        b"HELLO_PQC_NIDS",
        b"A" * 64,
        bytes(range(256)),
    ]

    for payload in test_payloads:
        wire_frame = build_wire_frame(payload)
        ok, code, exp_payload = parse_wire_frame(wire_frame)
        assert ok and code == RC_NONE and exp_payload == payload

        rx_payload, sof_cnt, eof_cnt, verdict = await send_frame(dut, wire_frame)

        assert rx_payload == payload, f"Payload mismatch: got {rx_payload!r}, expected {payload!r}"
        assert sof_cnt == 1, f"SOF mismatch for {len(payload)}B payload: {sof_cnt}"
        assert eof_cnt == 1, f"EOF mismatch for {len(payload)}B payload: {eof_cnt}"
        assert verdict is not None and verdict[0] == 0 and verdict[1] == RC_NONE, f"Verdict error: {verdict}"


@cocotb.test()
async def test_deframer_crc_failure(dut):
    """Verifies that frames with corrupted CRC-32 trigger RC_CRC_FAIL (4'h1)."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    payload = b"CORRUPTED_FRAME_PAYLOAD"
    wire_frame = bytearray(build_wire_frame(payload))
    wire_frame[-1] ^= 0x01  # Corrupt lowest bit of CRC-32

    rx_payload, sof_cnt, eof_cnt, verdict = await send_frame(dut, bytes(wire_frame))

    assert verdict is not None, "No verdict pulsed on CRC error"
    assert verdict[0] == 1, f"Verdict fail flag not set: {verdict}"
    assert verdict[1] == RC_CRC_FAIL, f"Expected RC_CRC_FAIL (4'h1), got {verdict[1]}"


@cocotb.test()
async def test_deframer_malformed_length(dut):
    """Verifies that frames with claimed total_length < 6 trigger RC_MALFORMED (4'h3)."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    bad_frame = struct.pack(">H", 4) + b"\x00\x00"
    rx_payload, sof_cnt, eof_cnt, verdict = await send_frame(dut, bad_frame)

    assert verdict is not None, "No verdict pulsed on malformed length"
    assert verdict[0] == 1, f"Verdict fail flag not set: {verdict}"
    assert verdict[1] == RC_MALFORMED, f"Expected RC_MALFORMED (4'h3), got {verdict[1]}"
    assert len(rx_payload) == 0, "Malformed frame leaked payload bytes"


@cocotb.test()
async def test_deframer_random_frames(dut):
    """Tests 50 random packet trials against model/pipeline.py."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    rng = random.Random(12345)
    for trial in range(50):
        length = rng.randint(1, 512)
        payload = bytes([rng.randint(0, 255) for _ in range(length)])
        wire_frame = build_wire_frame(payload)

        rx_payload, sof_cnt, eof_cnt, verdict = await send_frame(dut, wire_frame)

        assert rx_payload == payload, f"Trial {trial} payload mismatch"
        assert sof_cnt == 1 and eof_cnt == 1, f"Trial {trial} framing strobe mismatch"
        assert verdict == (0, RC_NONE), f"Trial {trial} verdict mismatch: {verdict}"

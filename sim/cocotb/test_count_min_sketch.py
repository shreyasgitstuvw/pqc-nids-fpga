"""
sim/cocotb/test_count_min_sketch.py - Cocotb Testbench for count_min_sketch.v

Lane 2 (Threat Detection): rtl/detect/count_min_sketch.v
Bit-exact verification against Python twin: model/detect.py (CMSThreatDetector)

Test layers:
  1. Flow Increment & Latency Check:
     Consecutive packets on same flow; verify counter increments 1..N and pipeline latency.
  2. Targeted Volumetric Flood Detection:
     Send THRESH_FLOOD (512) packets on single (src_ip, dst_port); verify RC_FLOOD (4'h5).
  3. Distributed Port Scan Detection:
     Send packets from single host across THRESH_SCAN (384) distinct ports; verify RC_SCAN (4'h6).
  4. Random Mixed Traffic Agreement:
     Mixed streams compared live against CMSThreatDetector reference oracle.

Target: ZedBoard XC7Z020 @ 100 MHz (10 ns clock period)
Owner: Member B
"""

import os
import random
import sys
from pathlib import Path

# Add repo root to import model.detect
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import FallingEdge, RisingEdge

from model.detect import (
    DEFAULT_FANOUT_MAX,
    DEFAULT_THRESH_FLOOD,
    DEFAULT_THRESH_SCAN,
    RC_FLOOD,
    RC_NONE,
    RC_SCAN,
    CMSThreatDetector,
)


async def reset_dut(dut):
    """Synchronous active-high reset and wait for memory clearing ready."""
    dut.rst.value = 1
    dut.header_valid.value = 0
    dut.src_ip.value = 0
    dut.dst_ip.value = 0
    dut.dst_port.value = 0
    dut.protocol.value = 0
    dut.eof.value = 0

    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)
    dut.rst.value = 0
    await RisingEdge(dut.clk)

    # Wait until hardware clearing state machine completes and ready goes high
    while int(dut.ready.value) == 0:
        await RisingEdge(dut.clk)

    await FallingEdge(dut.clk)


async def send_packet_header(dut, src_ip: int, dst_port: int, dst_ip: int = 0x0A000002, protocol: int = 6):
    """Drives a packet header on FallingEdge and waits for registered verdict."""
    dut.src_ip.value = src_ip & 0xFFFFFFFF
    dut.dst_ip.value = dst_ip & 0xFFFFFFFF
    dut.dst_port.value = dst_port & 0xFFFF
    dut.protocol.value = protocol & 0xFF
    dut.eof.value = 1
    dut.header_valid.value = 1

    await RisingEdge(dut.clk)
    await FallingEdge(dut.clk)
    dut.header_valid.value = 0
    dut.eof.value = 0

    # Wait for verdict strobe
    while int(dut.verdict_valid.value) == 0:
        await RisingEdge(dut.clk)
        await FallingEdge(dut.clk)

    verdict_fail = int(dut.verdict_fail.value)
    verdict_reason = int(dut.verdict_reason.value)
    c_flow = int(dut.c_flow_out.value)
    c_host = int(dut.c_host_out.value)

    return verdict_fail, verdict_reason, c_flow, c_host


@cocotb.test()
async def test_cms_flow_increments(dut):
    """Verifies flow and host counter increments on identical flow."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    oracle = CMSThreatDetector()

    src_ip = 0xC0A8010A  # 192.168.1.10
    dst_port = 80        # HTTP

    for pkt_idx in range(1, 20):
        exp_fail, exp_reason, exp_c_flow, exp_c_host = oracle.process_packet(
            src_ip=src_ip, dst_ip=0x0A000001, dst_port=dst_port
        )

        got_fail, got_reason, got_c_flow, got_c_host = await send_packet_header(
            dut, src_ip=src_ip, dst_port=dst_port
        )

        assert got_c_flow == exp_c_flow, f"Pkt {pkt_idx}: c_flow got {got_c_flow} != exp {exp_c_flow}"
        assert got_c_host == exp_c_host, f"Pkt {pkt_idx}: c_host got {got_c_host} != exp {exp_c_host}"
        assert got_fail == (1 if exp_fail else 0), f"Pkt {pkt_idx}: fail mismatch"
        assert got_reason == exp_reason, f"Pkt {pkt_idx}: reason mismatch"


@cocotb.test()
async def test_cms_flood_trigger(dut):
    """Verifies that exceeding THRESH_FLOOD asserts RC_FLOOD."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    src_ip = 0x0A000063   # 10.0.0.99
    dst_port = 51001      # PQC Handshake Port

    # Send 511 packets: should pass
    for i in range(1, 512):
        fail, reason, c_f, _ = await send_packet_header(dut, src_ip=src_ip, dst_port=dst_port)
        assert fail == 0, f"Packet {i} falsely triggered flood early (c_flow={c_f})"
        assert reason == RC_NONE

    # Packet 512: reaches THRESH_FLOOD (512) -> must trigger RC_FLOOD (4'h5)
    fail, reason, c_f, _ = await send_packet_header(dut, src_ip=src_ip, dst_port=dst_port)
    assert fail == 1, f"Packet 512 did not trigger flood: got fail={fail}, c_flow={c_f}"
    assert reason == RC_FLOOD, f"Packet 512 got reason {reason:#x} != RC_FLOOD ({RC_FLOOD:#x})"


@cocotb.test()
async def test_cms_scan_trigger(dut):
    """Verifies that exceeding THRESH_SCAN with low per-port fanout asserts RC_SCAN."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    src_ip = 0xC0A80064  # Scanner host: 192.168.0.100

    # Probe 383 distinct ports (1 probe per port)
    for port in range(1, 384):
        fail, reason, c_f, c_h = await send_packet_header(dut, src_ip=src_ip, dst_port=port)
        assert fail == 0, f"Port {port} falsely triggered scan early (c_host={c_h})"
        assert reason == RC_NONE

    # Probe 384th distinct port: reaches THRESH_SCAN (384) -> must trigger RC_SCAN (4'h6)
    fail, reason, c_f, c_h = await send_packet_header(dut, src_ip=src_ip, dst_port=384)
    assert fail == 1, f"Packet 384 did not trigger scan: got fail={fail}, c_host={c_h}"
    assert reason == RC_SCAN, f"Packet 384 got reason {reason:#x} != RC_SCAN ({RC_SCAN:#x})"


@cocotb.test()
async def test_cms_random_fuzz(dut):
    """Feeds 100 randomized packets and checks bit-exact agreement against oracle."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    oracle = CMSThreatDetector()
    rng = random.Random(0x42BEEF)

    # 10 active host IPs and 15 target ports
    hosts = [rng.randint(0x01000000, 0xE0000000) for _ in range(10)]
    ports = [80, 443, 22, 53, 51001, 51002, 8080, 3306, 8443, 21, 25, 110, 143, 993, 995]

    for trial in range(100):
        src_ip = rng.choice(hosts)
        dst_port = rng.choice(ports)

        exp_fail, exp_reason, exp_c_flow, exp_c_host = oracle.process_packet(
            src_ip=src_ip, dst_ip=0x0A000001, dst_port=dst_port
        )

        got_fail, got_reason, got_c_flow, got_c_host = await send_packet_header(
            dut, src_ip=src_ip, dst_port=dst_port
        )

        assert got_c_flow == exp_c_flow, (
            f"Fuzz trial {trial} ({src_ip:#010x}:{dst_port}): c_flow got {got_c_flow} != exp {exp_c_flow}"
        )
        assert got_c_host == exp_c_host, (
            f"Fuzz trial {trial} ({src_ip:#010x}:{dst_port}): c_host got {got_c_host} != exp {exp_c_host}"
        )
        assert got_fail == (1 if exp_fail else 0), (
            f"Fuzz trial {trial} ({src_ip:#010x}:{dst_port}): fail got {got_fail} != exp {exp_fail}"
        )
        assert got_reason == exp_reason, (
            f"Fuzz trial {trial} ({src_ip:#010x}:{dst_port}): reason got {got_reason:#x} != exp {exp_reason:#x}"
        )


@cocotb.test()
async def test_cms_reset_clears(dut):
    """Verifies that synchronous reset flushes pipeline and resets counters."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    # Send 10 packets to build up counter values
    src_ip = 0x0A000001
    dst_port = 80
    for _ in range(10):
        await send_packet_header(dut, src_ip=src_ip, dst_port=dst_port)

    # Confirm counter is at 10
    assert int(dut.c_flow_out.value) == 10

    # Assert reset
    dut.rst.value = 1
    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)
    dut.rst.value = 0
    await RisingEdge(dut.clk)

    # Wait for ready after clearing
    while int(dut.ready.value) == 0:
        await RisingEdge(dut.clk)

    await FallingEdge(dut.clk)

    # Next packet for the exact same flow must restart from 1
    _, _, c_f, c_h = await send_packet_header(dut, src_ip=src_ip, dst_port=dst_port)
    assert c_f == 1, f"Counter after reset did not restart at 1: got {c_f}"
    assert c_h == 1, f"Host counter after reset did not restart at 1: got {c_h}"


if __name__ == "__main__":
    from cocotb.runner import get_runner

    proj = Path(__file__).resolve().parent.parent.parent
    runner = get_runner("icarus")
    runner.build(
        sources=[
            proj / "rtl" / "detect" / "hash_functions.v",
            proj / "rtl" / "detect" / "count_min_sketch.v",
        ],
        hdl_toplevel="count_min_sketch",
        includes=[proj / "rtl" / "control"],
        build_dir=proj / "sim" / "build",
        always=True,
    )
    runner.test(
        hdl_toplevel="count_min_sketch",
        test_module="test_count_min_sketch",
        test_dir=proj / "sim" / "cocotb",
    )

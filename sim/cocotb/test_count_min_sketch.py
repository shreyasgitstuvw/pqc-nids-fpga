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
async def cms_flow_increments(dut):
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
async def cms_flood_trigger(dut):
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
async def cms_scan_trigger(dut):
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
async def cms_random_fuzz(dut):
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
async def cms_reset_clears(dut):
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



# ==============================================================================
# Regressions for the epoch-boundary defects found in
# docs/INTEGRATION-READINESS-REVIEW.md.
#
# Both tests force the boundary by writing epoch_pkt_count directly rather than
# sending 32768 packets. That is white-box, but the behaviour under test IS the
# boundary, and lowering EPOCH_N for the whole build would break the flood and
# scan tests above, which need hundreds of packets inside one epoch.
# ==============================================================================

@cocotb.test()
async def cms_every_packet_gets_a_verdict_across_the_epoch(dut):
    """During the 2048-cycle epoch sweep no verdict was emitted at all. `ready`
    is wired to nothing and the contract's packet bus has no backpressure, so
    packets kept arriving, and drop_engine requires the CMS lane to report
    before it will commit ANY packet type -- every packet presented in that
    window went unadjudicated. Measured before the fix: 4200 headers produced
    33 verdicts."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    presented = 0
    verdicts = []

    async def mon():
        while True:
            await FallingEdge(dut.clk)
            if int(dut.verdict_valid.value):
                verdicts.append((int(dut.verdict_fail.value),
                                 int(dut.c_flow_out.value)))

    task = cocotb.start_soon(mon())
    # Park the epoch counter just below its limit so the next packet trips the
    # boundary, then drive back-to-back headers straight through the sweep,
    # ignoring `ready` exactly as the contract's bus does.
    dut.epoch_pkt_count.value = int(dut.EPOCH_N.value) - 2
    await FallingEdge(dut.clk)
    for n in range(2600):
        dut.src_ip.value = 0x0A000001
        dut.dst_ip.value = 0x0A000002
        dut.dst_port.value = 80
        dut.protocol.value = 6
        dut.eof.value = 1
        dut.header_valid.value = 1
        await FallingEdge(dut.clk)
        presented += 1
    dut.header_valid.value = 0
    dut.eof.value = 0
    for _ in range(40):
        await FallingEdge(dut.clk)
    task.kill()

    assert len(verdicts) == presented, (
        f"{presented} headers presented but only {len(verdicts)} verdicts emitted "
        f"({presented - len(verdicts)} packets would stall drop_engine)")


@cocotb.test()
async def cms_no_stale_counts_at_the_epoch_boundary(dut):
    """The clear used to begin on the same cycle the epoch counter filled, and
    the clearing branch outranks the update branch, so packets already in the
    4-stage pipeline lost their writeback while their verdicts still fired --
    several consecutive verdicts reporting the same count. clear_req now defers
    the sweep until the pipeline has drained, so a counted packet's count is
    never discarded."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    # One flow, one packet at a time so every count is observable, with the
    # epoch boundary forced to land in the middle of the run.
    seen = []
    for n in range(12):
        if n == 5:
            dut.epoch_pkt_count.value = int(dut.EPOCH_N.value) - 2
            await FallingEdge(dut.clk)
        fail, reason, c_flow, c_host = await send_packet_header(dut, 0x0A000001, 80)
        seen.append(c_flow)
        # the sweep is 2048 clocks long (asserted in cms_epoch_sweep_length);
        # wait it out so the next packet is counted
        for _ in range(2100):
            await FallingEdge(dut.clk)

    # Counts must never repeat within a run of increasing values: a repeat is a
    # discarded writeback. A drop back to a low value is a legitimate epoch reset.
    for i in range(1, len(seen)):
        if seen[i] > seen[i - 1]:
            assert seen[i] == seen[i - 1] + 1, (
                f"count jumped {seen[i-1]} -> {seen[i]} at packet {i}: {seen}")
        elif seen[i] == seen[i - 1] and seen[i] != 0:
            raise AssertionError(
                f"count repeated at {seen[i]} (packet {i}), writeback discarded: {seen}")


@cocotb.test()
async def cms_epoch_sweep_length(dut):
    """The epoch sweep clears 2048 addresses, one per clock, so `clearing` is
    asserted for exactly 2048 cycles. That number appears in the module header
    and in the trade-off argument for not double-buffering the counters, so it
    is measured here rather than asserted from the source."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    # Park the counter at EPOCH_N - 1 so this very next packet trips the
    # boundary: the RTL compares epoch_pkt_count >= EPOCH_N - 1 on the update
    # cycle, so EPOCH_N - 2 would only advance the counter.
    dut.epoch_pkt_count.value = int(dut.EPOCH_N.value) - 1
    await FallingEdge(dut.clk)
    await send_packet_header(dut, 0x0A000001, 80)

    for _ in range(200):
        await FallingEdge(dut.clk)
        if int(dut.clearing.value) == 1:
            break
    assert int(dut.clearing.value) == 1, "the sweep never started"

    n = 0
    while int(dut.clearing.value) == 1 and n < 5000:
        await FallingEdge(dut.clk)
        n += 1
    assert n == 2048, f"clearing was asserted for {n} cycles, expected 2048"

def test_runner():
    """pytest entry point using cocotb.runner and iverilog."""
    import os
    from cocotb.runner import get_runner

    proj = Path(__file__).resolve().parent.parent.parent
    sim = os.getenv("SIM", "icarus")
    runner = get_runner(sim)
    runner.build(
        sources=[
            proj / "rtl" / "detect" / "hash_functions.v",
            proj / "rtl" / "detect" / "count_min_sketch.v",
        ],
        hdl_toplevel="count_min_sketch",
        includes=[proj / "rtl" / "control"],
        build_dir=proj / "sim" / "sim_build" / "count_min_sketch",
        always=True,
    )
    runner.test(
        hdl_toplevel="count_min_sketch",
        test_module="test_count_min_sketch",
        build_dir=proj / "sim" / "sim_build" / "count_min_sketch",
        test_dir=proj / "sim" / "cocotb",
    )


if __name__ == "__main__":
    test_runner()


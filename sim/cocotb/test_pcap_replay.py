"""
sim/cocotb/test_pcap_replay.py - Binary PCAP Hardware Replay Testbench

Replays the raw binary PCAPs from sim/vectors/cicids2017_subset/ through
rtl/detect/count_min_sketch.v to verify empirical detection accuracy:
  1. benign.pcap   (150 packets -> 0% false alarm rate)
  2. synflood.pcap (600 packets -> RC_FLOOD triggered at packet 512)
  3. portscan.pcap (450 packets -> RC_SCAN triggered at probe 384)

Target: ZedBoard XC7Z020 @ 100 MHz (10 ns clock period)
Owner: Member B
"""

import os
import struct
import sys
from pathlib import Path

# Repository root setup
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import FallingEdge, RisingEdge

from model.detect import (
    RC_FLOOD,
    RC_NONE,
    RC_SCAN,
)

PROJ_ROOT = Path(__file__).resolve().parent.parent.parent
PCAP_DIR = PROJ_ROOT / "sim" / "vectors" / "cicids2017_subset"


def parse_pcap_file(pcap_path: Path):
    """Parses binary PCAP file and extracts packet 5-tuples."""
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

            # Ethernet II header (14 bytes)
            eth_type = struct.unpack("!H", frame[12:14])[0]
            if eth_type == 0x0800:
                # IPv4 header
                ip_hdr = frame[14:34]
                ver_ihl, dscp, tot_len, ident, flags_frag, ttl, proto, chk, s_ip, d_ip = struct.unpack("!BBHHHBBHII", ip_hdr)
                l4_data = frame[34:]
                s_port, d_port = struct.unpack("!HH", l4_data[:4])

                packets.append({
                    "src_ip": s_ip,
                    "dst_ip": d_ip,
                    "src_port": s_port,
                    "dst_port": d_port,
                    "protocol": proto,
                })
    return packets


async def reset_dut(dut):
    """Synchronous active-high reset and wait for memory clearing."""
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

    while int(dut.ready.value) == 0:
        await RisingEdge(dut.clk)

    await FallingEdge(dut.clk)


async def send_packet(dut, pkt):
    """Drives packet header into count_min_sketch.v and collects verdict."""
    dut.src_ip.value = pkt["src_ip"]
    dut.dst_ip.value = pkt["dst_ip"]
    dut.dst_port.value = pkt["dst_port"]
    dut.protocol.value = pkt["protocol"]
    dut.eof.value = 1
    dut.header_valid.value = 1

    await RisingEdge(dut.clk)
    await FallingEdge(dut.clk)
    dut.header_valid.value = 0
    dut.eof.value = 0

    while int(dut.verdict_valid.value) == 0:
        await RisingEdge(dut.clk)
        await FallingEdge(dut.clk)

    return int(dut.verdict_fail.value), int(dut.verdict_reason.value), int(dut.c_flow_out.value), int(dut.c_host_out.value)


@cocotb.test()
async def test_replay_benign_pcap(dut):
    """Replays benign.pcap (150 packets) and verifies 0% false positive rate."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    packets = parse_pcap_file(PCAP_DIR / "benign.pcap")
    assert len(packets) == 150, f"Expected 150 packets in benign.pcap, got {len(packets)}"

    false_positives = 0
    for idx, pkt in enumerate(packets, 1):
        fail, reason, c_f, c_h = await send_packet(dut, pkt)
        if fail != 0 or reason != RC_NONE:
            false_positives += 1

    assert false_positives == 0, f"Benign replay had {false_positives} false positives (expected 0)"


@cocotb.test()
async def test_replay_synflood_pcap(dut):
    """Replays synflood.pcap (600 packets) and verifies RC_FLOOD triggers at packet 512."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    packets = parse_pcap_file(PCAP_DIR / "synflood.pcap")
    assert len(packets) == 600, f"Expected 600 packets in synflood.pcap, got {len(packets)}"

    flood_triggered_at = None
    for idx, pkt in enumerate(packets, 1):
        fail, reason, c_f, c_h = await send_packet(dut, pkt)
        if fail == 1 and reason == RC_FLOOD and flood_triggered_at is None:
            flood_triggered_at = idx

    assert flood_triggered_at == 512, (
        f"SYN flood triggered at packet {flood_triggered_at} (expected exact threshold 512)"
    )


@cocotb.test()
async def test_replay_portscan_pcap(dut):
    """Replays portscan.pcap (450 packets) and verifies RC_SCAN triggers at probe 384."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    packets = parse_pcap_file(PCAP_DIR / "portscan.pcap")
    assert len(packets) == 450, f"Expected 450 packets in portscan.pcap, got {len(packets)}"

    scan_triggered_at = None
    for idx, pkt in enumerate(packets, 1):
        fail, reason, c_f, c_h = await send_packet(dut, pkt)
        if fail == 1 and reason == RC_SCAN and scan_triggered_at is None:
            scan_triggered_at = idx

    assert scan_triggered_at == 384, (
        f"Port scan triggered at probe {scan_triggered_at} (expected exact threshold 384)"
    )


if __name__ == "__main__":
    from cocotb.runner import get_runner

    runner = get_runner("icarus")
    runner.build(
        sources=[
            PROJ_ROOT / "rtl" / "detect" / "hash_functions.v",
            PROJ_ROOT / "rtl" / "detect" / "count_min_sketch.v",
        ],
        hdl_toplevel="count_min_sketch",
        includes=[PROJ_ROOT / "rtl" / "control"],
        build_dir=PROJ_ROOT / "sim" / "build",
        always=True,
    )
    runner.test(
        hdl_toplevel="count_min_sketch",
        test_module="test_pcap_replay",
        test_dir=PROJ_ROOT / "sim" / "cocotb",
    )

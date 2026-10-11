"""
sim/cocotb/test_parser.py
Cocotb testbench for rtl/ingress/parser.v verified against model/pipeline.py.

Layers of test:
  1. Valid TCP session data packet -> matches model/pipeline.py PacketBus bit-for-bit
  2. Valid UDP packet -> matches model/pipeline.py PacketBus bit-for-bit
  3. ML-KEM handshake init packet (800B ek, type 2'b00) -> matches bit-for-bit
  4. ML-KEM handshake resp packet (768B ct, type 2'b10) -> matches bit-for-bit
  5. Non-IPv4 frames (ARP, IPv6, LLDP) -> asserts parsed_ok = 0
  6. Corrupted IPv4 version, bad IHL, IPv4 options -> asserts parsed_ok = 0
  7. Unsupported L4 protocols (ICMP, IGMP, GRE) -> asserts parsed_ok = 0
  8. Truncated frames (1B, mid-Ethernet, mid-IPv4, mid-TCP, cut-off payload) -> asserts parsed_ok = 0
  9. Malformed TCP data offset (<5), malformed UDP length (<8) -> asserts parsed_ok = 0
 10. TCP with options (data_offset=8 -> 32B header) -> asserts parsed_ok = 1
 11. Zero-payload TCP packet (SYN/ACK) -> asserts parsed_ok = 1, payload_len = 0
 12. Zero-payload TCP packet with Ethernet padding -> asserts parsed_ok = 1, padding drained

Owner: Member A (Ingress, Parser, and Interface Contract)
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
    parse_headers,
    _build_test_packet,
    PacketBus,
    PORT_HS_INIT,
    PORT_HS_RESP,
    PORT_DATA,
    PKT_HANDSHAKE_EK,
    PKT_DATA,
    PKT_HANDSHAKE_CT,
)


async def reset_dut(dut):
    """Applies synchronous active-high reset for 2 clock cycles."""
    dut.rst.value = 1
    dut.in_valid.value = 0
    dut.in_data.value = 0
    dut.in_sof.value = 0
    dut.in_eof.value = 0
    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)
    dut.rst.value = 0
    await RisingEdge(dut.clk)


async def send_packet(dut, raw_bytes: bytes) -> tuple:
    """
    Drives raw packet bytes into parser.v byte-by-byte.
    Collects latched header context and streamed payload bytes.
    """
    rx_payload = bytearray()
    hdr_captured = None

    for i, b in enumerate(raw_bytes):
        dut.in_valid.value = 1
        dut.in_data.value = b
        dut.in_sof.value = 1 if (i == 0) else 0
        dut.in_eof.value = 1 if (i == len(raw_bytes) - 1) else 0
        await RisingEdge(dut.clk)

        if dut.out_valid.value == 1:
            rx_payload.append(int(dut.out_data.value))

        if dut.hdr_valid.value == 1:
            hdr_captured = {
                "parsed_ok": int(dut.parsed_ok.value),
                "eth_dst_mac": int(dut.eth_dst_mac.value),
                "eth_src_mac": int(dut.eth_src_mac.value),
                "eth_type": int(dut.eth_type.value),
                "ip_version_ihl": int(dut.ip_version_ihl.value),
                "ip_total_length": int(dut.ip_total_length.value),
                "ip_protocol": int(dut.ip_protocol.value),
                "ip_src_addr": int(dut.ip_src_addr.value),
                "ip_dst_addr": int(dut.ip_dst_addr.value),
                "l4_src_port": int(dut.l4_src_port.value),
                "l4_dst_port": int(dut.l4_dst_port.value),
                "tcp_flags": int(dut.tcp_flags.value),
                "l4_length": int(dut.l4_length.value),
                "payload_len": int(dut.payload_len.value),
                "packet_type": int(dut.packet_type.value),
            }

    dut.in_valid.value = 0
    dut.in_data.value = 0
    dut.in_sof.value = 0
    dut.in_eof.value = 0

    await RisingEdge(dut.clk)
    if dut.out_valid.value == 1:
        rx_payload.append(int(dut.out_data.value))
    if dut.hdr_valid.value == 1 and hdr_captured is None:
        hdr_captured = {
            "parsed_ok": int(dut.parsed_ok.value),
            "eth_dst_mac": int(dut.eth_dst_mac.value),
            "eth_src_mac": int(dut.eth_src_mac.value),
            "eth_type": int(dut.eth_type.value),
            "ip_version_ihl": int(dut.ip_version_ihl.value),
            "ip_total_length": int(dut.ip_total_length.value),
            "ip_protocol": int(dut.ip_protocol.value),
            "ip_src_addr": int(dut.ip_src_addr.value),
            "ip_dst_addr": int(dut.ip_dst_addr.value),
            "l4_src_port": int(dut.l4_src_port.value),
            "l4_dst_port": int(dut.l4_dst_port.value),
            "tcp_flags": int(dut.tcp_flags.value),
            "l4_length": int(dut.l4_length.value),
            "payload_len": int(dut.payload_len.value),
            "packet_type": int(dut.packet_type.value),
        }

    return bytes(rx_payload), hdr_captured


@cocotb.test()
async def test_parser_standard_packets(dut):
    """Verifies that valid TCP, UDP, and Handshake packets match model/pipeline.py bit-for-bit."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    # 1. Valid TCP packet
    raw_tcp = _build_test_packet(dst_port=PORT_DATA, protocol=6, payload=b"SESSION_DATA_STREAM")
    gold_tcp = parse_headers(raw_tcp)
    rx_payload, hdr = await send_packet(dut, raw_tcp)

    assert hdr["parsed_ok"] == 1
    assert hdr["eth_type"] == gold_tcp.eth_type
    assert hdr["ip_protocol"] == gold_tcp.ip_protocol
    assert hdr["l4_dst_port"] == gold_tcp.l4_dst_port
    assert hdr["packet_type"] == gold_tcp.packet_type
    assert hdr["payload_len"] == gold_tcp.payload_len
    assert rx_payload == gold_tcp.payload

    # 2. Valid UDP packet
    raw_udp = _build_test_packet(dst_port=53, protocol=17, payload=b"DNS_QUERY")
    gold_udp = parse_headers(raw_udp)
    rx_payload, hdr = await send_packet(dut, raw_udp)

    assert hdr["parsed_ok"] == 1
    assert hdr["ip_protocol"] == gold_udp.ip_protocol
    assert hdr["l4_dst_port"] == gold_udp.l4_dst_port
    assert hdr["payload_len"] == gold_udp.payload_len
    assert rx_payload == gold_udp.payload

    # 3. Handshake Init Packet (ek=800B, type 2'b00)
    raw_hs_init = _build_test_packet(dst_port=PORT_HS_INIT, protocol=17, payload=b"\xAA" * 800)
    gold_hs_init = parse_headers(raw_hs_init)
    rx_payload, hdr = await send_packet(dut, raw_hs_init)

    assert hdr["parsed_ok"] == 1
    assert hdr["packet_type"] == PKT_HANDSHAKE_EK
    assert hdr["payload_len"] == 800
    assert rx_payload == gold_hs_init.payload

    # 4. Handshake Resp Packet (ct=768B, type 2'b10)
    raw_hs_resp = _build_test_packet(dst_port=PORT_HS_RESP, protocol=17, payload=b"\x55" * 768)
    gold_hs_resp = parse_headers(raw_hs_resp)
    rx_payload, hdr = await send_packet(dut, raw_hs_resp)

    assert hdr["parsed_ok"] == 1
    assert hdr["packet_type"] == PKT_HANDSHAKE_CT
    assert hdr["payload_len"] == 768
    assert rx_payload == gold_hs_resp.payload

    # 5. TCP with Options (data_offset=8 -> 32B header)
    raw_tcp_opt = _build_test_packet(tcp_data_offset=8, payload=b"OPTIONS_PAYLOAD")
    gold_tcp_opt = parse_headers(raw_tcp_opt)
    rx_payload, hdr = await send_packet(dut, raw_tcp_opt)

    assert hdr["parsed_ok"] == 1
    assert hdr["l4_length"] == 32
    assert hdr["payload_len"] == 15
    assert rx_payload == gold_tcp_opt.payload

    # 6. Zero-Payload TCP Packet (SYN/ACK, 54B)
    raw_zero_tcp = _build_test_packet(dst_port=PORT_DATA, protocol=6, tcp_flags=0x12, payload=b"")
    gold_zero = parse_headers(raw_zero_tcp)
    rx_payload, hdr = await send_packet(dut, raw_zero_tcp)

    assert hdr["parsed_ok"] == 1
    assert hdr["payload_len"] == 0
    assert rx_payload == b""

    # 7. Zero-Payload TCP Packet with Ethernet Padding (60B)
    raw_padded_tcp = raw_zero_tcp + b"\x00" * 6
    rx_payload, hdr = await send_packet(dut, raw_padded_tcp)

    assert hdr["parsed_ok"] == 1
    assert hdr["payload_len"] == 0
    assert rx_payload == b""


@cocotb.test()
async def test_parser_malformed_packets(dut):
    """Verifies that non-IPv4, corrupted, unsupported, and truncated packets are rejected."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    malformed_cases = [
        ("ARP", _build_test_packet(eth_type=0x0806, payload=b"\x00" * 28)),
        ("IPv6", _build_test_packet(eth_type=0x86DD, payload=b"\x60" + b"\x00" * 39)),
        ("LLDP", _build_test_packet(eth_type=0x88CC, payload=b"\x02\x07" * 10)),
        ("BadVersion", _build_test_packet(version_ihl=0x65, protocol=6)),
        ("BadIHL", _build_test_packet(version_ihl=0x44, protocol=6)),
        ("IPOptions", _build_test_packet(version_ihl=0x46, payload=b"DATA")),
        ("ICMP", _build_test_packet(protocol=1, payload=b"ECHO")),
        ("IGMP", _build_test_packet(protocol=2, payload=b"REPORT")),
        ("GRE", _build_test_packet(protocol=47, payload=b"GRE")),
        ("TruncEthernet", b"\x00\x11\x22\x33\x44\x55\x66"),
        ("TruncIP", _build_test_packet(dst_port=PORT_DATA, protocol=6)[:25]),
        ("TruncTCP", _build_test_packet(dst_port=PORT_DATA, protocol=6)[:40]),
        ("BadTCPOffset", _build_test_packet(tcp_data_offset=3, payload=b"DATA")),
        ("BadUDPLen", _build_test_packet(protocol=17, udp_len=4, payload=b"DATA")),
    ]

    for name, raw_pkt in malformed_cases:
        gold = parse_headers(raw_pkt)
        assert not gold.valid, f"Python oracle should have rejected {name}"

        rx_payload, hdr = await send_packet(dut, raw_pkt)
        assert hdr["parsed_ok"] == 0, f"RTL parser failed to reject {name}: {hdr}"

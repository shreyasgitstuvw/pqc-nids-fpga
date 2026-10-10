"""
model/pipeline.py
End-to-end Python reference: raw packet bytes in, packet bus + verdict out.

Bit-exact Python specification twin for:
  - rtl/ingress/parser.v       (parse_headers -> PacketBus)
  - rtl/ingress/crc32.v        (compute_crc32)
  - rtl/ingress/deframer.v     (parse_wire_frame)
  - rtl/detect/protocol_validator.v (classify structural checks)

Owner: Member A (Ingress, Parser, and Interface Contract)
Reference:
  - docs/Member A/interface_contract.md (§1, §2, §3, §3.1, §4, §6)
  - rtl/control/reason_codes.vh
  - AGENTS.md
"""

from dataclasses import dataclass, field
import struct
from typing import Tuple
import zlib

# =====================================================================
# Reason Codes (mirrors rtl/control/reason_codes.vh)
# =====================================================================
RC_NONE                  = 0x0  # No failure; packet passes
RC_CRC_FAIL              = 0x1  # Member A: link-layer CRC corruption
RC_FRAME_TIMEOUT         = 0x2  # Member A: truncated / stalled frame
RC_MALFORMED             = 0x3  # Member B: invalid header / protocol structure
RC_SIGNATURE             = 0x4  # Member B: signature CAM match
RC_FLOOD                 = 0x5  # Member B: count-min sketch rate anomaly
RC_SCAN                  = 0x6  # Member B: count-min sketch fan-out anomaly
RC_BAD_TAG               = 0x7  # Member D: poly1305 MAC tag failure
RC_HANDSHAKE_KEY_INVALID = 0x8  # Member C: structural key validation failure

REASON = {
    "NONE": RC_NONE,
    "CRC_FAIL": RC_CRC_FAIL,
    "FRAME_TIMEOUT": RC_FRAME_TIMEOUT,
    "MALFORMED": RC_MALFORMED,
    "SIGNATURE": RC_SIGNATURE,
    "FLOOD": RC_FLOOD,
    "SCAN": RC_SCAN,
    "BAD_TAG": RC_BAD_TAG,
    "HANDSHAKE_KEY_INVALID": RC_HANDSHAKE_KEY_INVALID,
}

REASON_NAME = {v: k for k, v in REASON.items()}

# =====================================================================
# Classification & Port Numbers (interface_contract.md §4)
# =====================================================================
PKT_HANDSHAKE_EK = 0b00  # Initiator -> Responder: Encapsulation Key (ek, 800 B)
PKT_DATA         = 0b01  # Established Session Data (ChaCha20-Poly1305)
PKT_HANDSHAKE_CT = 0b10  # Responder -> Initiator: Ciphertext (c, 768 B)
PKT_RESERVED     = 0b11  # Reserved

PORT_HS_INIT = 51001  # Handshake Init port -> PKT_HANDSHAKE_EK
PORT_HS_RESP = 51002  # Handshake Resp port -> PKT_HANDSHAKE_CT
PORT_DATA    = 51010  # Established session data port -> PKT_DATA


# =====================================================================
# Data Structures (interface_contract.md §3 & §6)
# =====================================================================
@dataclass
class PacketBus:
    """Python twin of packet_bus_t in interface_contract.md §3."""
    valid: bool = False
    sof: bool = False
    eof: bool = False
    data: bytes = b""

    # Ethernet Header (14 bytes)
    eth_dst_mac: int = 0      # 48 bits, big-endian
    eth_src_mac: int = 0      # 48 bits, big-endian
    eth_type: int = 0         # 16 bits, 0x0800 = IPv4

    # IPv4 Header (20 bytes when IHL=5)
    ip_version_ihl: int = 0   # 8 bits: version (4b) + IHL (4b); 0x45 expected
    ip_total_length: int = 0  # 16 bits: total length of IPv4 datagram
    ip_protocol: int = 0      # 8 bits: 6 = TCP, 17 = UDP
    ip_src_addr: int = 0      # 32 bits, big-endian IPv4 address
    ip_dst_addr: int = 0      # 32 bits, big-endian IPv4 address

    # TCP / UDP Header
    l4_src_port: int = 0      # 16 bits, big-endian source port
    l4_dst_port: int = 0      # 16 bits, big-endian destination port
    tcp_flags: int = 0        # 8 bits (TCP flags, 0x00 for UDP)
    l4_length: int = 0        # 16 bits: TCP header len in bytes or UDP length field

    # Classification & Session Metadata
    payload_len: int = 0      # 16 bits: payload length after headers
    session_id: int = 0       # 16 bits: session ID from lookup (0 = unassigned)
    packet_type: int = PKT_DATA  # 2 bits: PKT_* enum
    payload: bytes = field(default=b"", repr=False)


@dataclass
class Verdict:
    """Lane and drop engine verdict struct (interface_contract.md §6)."""
    fail: bool = False
    reason: str = "NONE"

    @property
    def code(self) -> int:
        return REASON.get(self.reason, RC_NONE)


# =====================================================================
# Physical Framing & CRC Helpers (interface_contract.md §1 & §2)
# =====================================================================
def compute_crc32(data: bytes) -> int:
    """IEEE 802.3 Ethernet CRC-32 (polynomial 0x04C11DB7 / reflected 0xEDB88320)."""
    return zlib.crc32(data) & 0xFFFFFFFF


def build_wire_frame(payload: bytes) -> bytes:
    """
    Encapsulates payload into wire framing per interface_contract.md §1:
      [2 bytes: total_length (big-endian)] [payload bytes] [4 bytes: CRC-32 (big-endian)]
    where total_length includes header (2), payload, and CRC (4).
    """
    total_len = 2 + len(payload) + 4
    crc = compute_crc32(payload)
    return struct.pack(">H", total_len) + payload + struct.pack(">I", crc)


def parse_wire_frame(frame: bytes) -> Tuple[bool, int, bytes]:
    """
    Validates framing and CRC-32 integrity (twin of deframer.v + crc32.v).

    Returns:
      (ok: bool, error_code: int, deframed_payload: bytes)
    """
    if len(frame) < 6:
        return False, RC_FRAME_TIMEOUT, b""

    total_len = struct.unpack(">H", frame[:2])[0]
    if len(frame) < total_len:
        return False, RC_FRAME_TIMEOUT, b""

    payload = frame[2:total_len - 4]
    expected_crc = struct.unpack(">I", frame[total_len - 4:total_len])[0]
    actual_crc = compute_crc32(payload)

    if actual_crc != expected_crc:
        return False, RC_CRC_FAIL, b""

    return True, RC_NONE, payload


# =====================================================================
# Ingress Header Parser (interface_contract.md §3 & §4)
# =====================================================================
def parse_headers(raw: bytes) -> PacketBus:
    """
    Parses a deframed Ethernet frame into the shared PacketBus struct.
    Twin of rtl/ingress/parser.v.

    Accepts raw Ethernet frame bytes (beginning with eth_dst_mac).
    Extracts Ethernet -> IPv4 -> TCP/UDP headers and performs Option A
    port-based classification.
    """
    bus = PacketBus()

    # 1. Ethernet Header (14 bytes)
    if len(raw) < 14:
        bus.valid = False
        bus.payload = raw
        bus.payload_len = len(raw)
        return bus

    bus.eth_dst_mac = int.from_bytes(raw[0:6], "big")
    bus.eth_src_mac = int.from_bytes(raw[6:12], "big")
    bus.eth_type = int.from_bytes(raw[12:14], "big")

    # Non-IPv4 EtherTypes cannot be parsed into IPv4/L4 fields
    if bus.eth_type != 0x0800:
        bus.valid = False
        bus.payload = raw[14:]
        bus.payload_len = len(bus.payload)
        bus.data = bus.payload
        return bus

    # 2. IPv4 Header (minimum 20 bytes when IHL=5)
    if len(raw) < 34:  # 14 Ethernet + 20 minimum IPv4
        bus.valid = False
        bus.payload = raw[14:]
        bus.payload_len = len(bus.payload)
        bus.data = bus.payload
        return bus

    bus.ip_version_ihl = raw[14]
    ihl = bus.ip_version_ihl & 0x0F
    ihl_bytes = ihl * 4

    bus.ip_total_length = int.from_bytes(raw[16:18], "big")
    bus.ip_protocol = raw[23]
    bus.ip_src_addr = int.from_bytes(raw[26:30], "big")
    bus.ip_dst_addr = int.from_bytes(raw[30:34], "big")

    # Reject IPv4 options (IHL != 5) or truncated header
    if ihl != 5 or len(raw) < 14 + ihl_bytes:
        bus.valid = False
        bus.payload = raw[14 + ihl_bytes:] if len(raw) >= 14 + ihl_bytes else b""
        bus.payload_len = len(bus.payload)
        bus.data = bus.payload
        return bus

    # 3. Transport Layer (L4)
    l4_offset = 14 + ihl_bytes

    if bus.ip_protocol == 6:  # TCP
        if len(raw) < l4_offset + 20:
            bus.valid = False
            bus.payload = raw[l4_offset:]
            bus.payload_len = len(bus.payload)
            bus.data = bus.payload
            return bus

        bus.l4_src_port = int.from_bytes(raw[l4_offset:l4_offset + 2], "big")
        bus.l4_dst_port = int.from_bytes(raw[l4_offset + 2:l4_offset + 4], "big")
        tcp_data_offset = (raw[l4_offset + 12] >> 4) & 0x0F
        bus.l4_length = tcp_data_offset * 4  # TCP header length in bytes
        bus.tcp_flags = raw[l4_offset + 13]
        payload_start = l4_offset + bus.l4_length

    elif bus.ip_protocol == 17:  # UDP
        if len(raw) < l4_offset + 8:
            bus.valid = False
            bus.payload = raw[l4_offset:]
            bus.payload_len = len(bus.payload)
            bus.data = bus.payload
            return bus

        bus.l4_src_port = int.from_bytes(raw[l4_offset:l4_offset + 2], "big")
        bus.l4_dst_port = int.from_bytes(raw[l4_offset + 2:l4_offset + 4], "big")
        bus.l4_length = int.from_bytes(raw[l4_offset + 4:l4_offset + 6], "big")
        bus.tcp_flags = 0x00
        payload_start = l4_offset + 8

    else:
        # Non-TCP/UDP protocol
        bus.valid = False
        bus.l4_src_port = 0
        bus.l4_dst_port = 0
        bus.tcp_flags = 0
        bus.l4_length = 0
        payload_start = l4_offset

    # 4. Payload Extraction & Bounds
    # Bounded by ip_total_length if valid, otherwise by buffer length
    if bus.ip_total_length > 0:
        ip_payload_end = 14 + bus.ip_total_length
        payload_end = min(len(raw), ip_payload_end)
    else:
        payload_end = len(raw)

    if payload_start <= len(raw) and payload_start <= payload_end:
        bus.payload = raw[payload_start:payload_end]
    else:
        bus.payload = b""

    bus.payload_len = len(bus.payload)
    bus.data = bus.payload

    # Truncation check against claimed IP total length
    if bus.ip_total_length > 0 and len(raw) < 14 + bus.ip_total_length:
        bus.valid = False
    elif bus.ip_protocol in (6, 17) and bus.eth_type == 0x0800 and (bus.ip_version_ihl == 0x45):
        bus.valid = True

    bus.sof = True
    bus.eof = True
    bus.session_id = 0  # Pre-lookup default

    # 5. Classification (Option A - Port-Based, contract §4)
    if bus.l4_dst_port == PORT_HS_INIT:
        bus.packet_type = PKT_HANDSHAKE_EK
    elif bus.l4_dst_port == PORT_HS_RESP:
        bus.packet_type = PKT_HANDSHAKE_CT
    else:
        bus.packet_type = PKT_DATA

    return bus


# =====================================================================
# Threat Lane Classification (interface_contract.md §6 & detect.py)
# =====================================================================
def classify(bus: PacketBus) -> Verdict:
    """
    Evaluates packet against protocol validator rules (protocol_validator.v).
    Returns a Verdict struct with fail status and reason code.
    """
    # 1. Structural Checks (RC_MALFORMED)
    if not bus.valid:
        return Verdict(fail=True, reason="MALFORMED")

    if bus.eth_type != 0x0800:
        return Verdict(fail=True, reason="MALFORMED")

    if bus.ip_version_ihl != 0x45:
        return Verdict(fail=True, reason="MALFORMED")

    if bus.ip_protocol not in (6, 17):
        return Verdict(fail=True, reason="MALFORMED")

    return Verdict(fail=False, reason="NONE")


def process(raw: bytes) -> Tuple[PacketBus, Verdict]:
    """
    Full pipeline oracle: raw deframed bytes -> (PacketBus, Verdict).
    Imported and called directly by cocotb testbenches.
    """
    bus = parse_headers(raw)
    verdict = classify(bus)
    return bus, verdict


# =====================================================================
# Self-Test Suite (AGENTS.md §5)
# =====================================================================
def _build_test_packet(
    dst_mac: int = 0x001122334455,
    src_mac: int = 0x66778899AABB,
    eth_type: int = 0x0800,
    version_ihl: int = 0x45,
    protocol: int = 6,
    src_ip: int = 0xC0A8010A,  # 192.168.1.10
    dst_ip: int = 0xC0A80114,  # 192.168.1.20
    src_port: int = 12345,
    dst_port: int = 51010,
    tcp_flags: int = 0x18,     # PSH, ACK
    payload: bytes = b"HELLO_PQC_NIDS",
) -> bytes:
    """Constructs a test Ethernet/IPv4 packet."""
    eth = struct.pack(">6s6sH", dst_mac.to_bytes(6, "big"), src_mac.to_bytes(6, "big"), eth_type)

    if eth_type != 0x0800:
        return eth + payload

    ihl_words = version_ihl & 0x0F
    ihl_bytes = ihl_words * 4
    ip_header_pad = b"\x00" * max(0, ihl_bytes - 20)

    if protocol == 6:
        l4_hdr_len = 20
        l4_hdr = struct.pack(">HHIIBBHHH", src_port, dst_port, 100, 200, (5 << 4), tcp_flags, 8192, 0, 0)
    elif protocol == 17:
        l4_hdr_len = 8
        udp_len = 8 + len(payload)
        l4_hdr = struct.pack(">HHHH", src_port, dst_port, udp_len, 0)
    else:
        l4_hdr_len = 0
        l4_hdr = b""

    total_ip_len = ihl_bytes + l4_hdr_len + len(payload)
    ip_hdr = struct.pack(
        ">BBHHHBBH4s4s",
        version_ihl,
        0,
        total_ip_len,
        54321,
        0x4000,
        64,
        protocol,
        0,
        src_ip.to_bytes(4, "big"),
        dst_ip.to_bytes(4, "big"),
    ) + ip_header_pad

    return eth + ip_hdr + l4_hdr + payload


def run_self_test() -> None:
    print("====================================================================")
    print("Ingress Pipeline (Lane 1/Ingress) -- Header Parser & Oracle Twin")
    print("====================================================================")

    # 1. Standard TCP Packet
    raw_tcp = _build_test_packet(dst_port=PORT_DATA, protocol=6, payload=b"SESSION_DATA_STREAM")
    bus, verdict = process(raw_tcp)
    assert bus.valid, "Valid TCP packet marked invalid"
    assert not verdict.fail, f"Valid TCP packet rejected: {verdict.reason}"
    assert bus.eth_type == 0x0800, f"Bad eth_type: 0x{bus.eth_type:04X}"
    assert bus.ip_protocol == 6, f"Bad protocol: {bus.ip_protocol}"
    assert bus.l4_dst_port == PORT_DATA, f"Bad dst port: {bus.l4_dst_port}"
    assert bus.packet_type == PKT_DATA, f"Bad packet type: {bus.packet_type}"
    assert bus.payload == b"SESSION_DATA_STREAM", f"Bad payload: {bus.payload}"
    assert bus.payload_len == len(b"SESSION_DATA_STREAM")
    print("  [1] Valid TCP Session Data Packet: PASS")

    # 2. Standard UDP Packet
    raw_udp = _build_test_packet(dst_port=53, protocol=17, payload=b"DNS_QUERY")
    bus, verdict = process(raw_udp)
    assert bus.valid, "Valid UDP packet marked invalid"
    assert not verdict.fail, "Valid UDP packet rejected"
    assert bus.ip_protocol == 17
    assert bus.l4_dst_port == 53
    assert bus.packet_type == PKT_DATA
    assert bus.payload == b"DNS_QUERY"
    print("  [2] Valid UDP Packet: PASS")

    # 3. Handshake Init Packet (PORT_HS_INIT: 51001, 800 B ek)
    ek_payload = b"\xAA" * 800
    raw_hs_init = _build_test_packet(dst_port=PORT_HS_INIT, protocol=17, payload=ek_payload)
    bus, verdict = process(raw_hs_init)
    assert bus.valid
    assert not verdict.fail
    assert bus.l4_dst_port == PORT_HS_INIT
    assert bus.packet_type == PKT_HANDSHAKE_EK, f"Expected PKT_HANDSHAKE_EK, got {bus.packet_type}"
    assert bus.payload_len == 800
    assert bus.payload == ek_payload
    print("  [3] ML-KEM Handshake Init Packet (ek=800B, type=2'b00): PASS")

    # 4. Handshake Resp Packet (PORT_HS_RESP: 51002, 768 B ct)
    ct_payload = b"\x55" * 768
    raw_hs_resp = _build_test_packet(dst_port=PORT_HS_RESP, protocol=17, payload=ct_payload)
    bus, verdict = process(raw_hs_resp)
    assert bus.valid
    assert not verdict.fail
    assert bus.l4_dst_port == PORT_HS_RESP
    assert bus.packet_type == PKT_HANDSHAKE_CT, f"Expected PKT_HANDSHAKE_CT, got {bus.packet_type}"
    assert bus.payload_len == 768
    assert bus.payload == ct_payload
    print("  [4] ML-KEM Handshake Resp Packet (ct=768B, type=2'b10): PASS")

    # 5. Non-IPv4 Frame (ARP: 0x0806) -> RC_MALFORMED
    raw_arp = _build_test_packet(eth_type=0x0806, payload=b"\x00" * 28)
    bus, verdict = process(raw_arp)
    assert not bus.valid
    assert verdict.fail
    assert verdict.reason == "MALFORMED", f"Expected MALFORMED, got {verdict.reason}"
    assert verdict.code == RC_MALFORMED
    print("  [5] Non-IPv4 Frame Rejection (ARP -> RC_MALFORMED): PASS")

    # 6. IPv4 Options Header (IHL=6) -> RC_MALFORMED
    raw_opt = _build_test_packet(version_ihl=0x46, payload=b"DATA")
    bus, verdict = process(raw_opt)
    assert not bus.valid
    assert verdict.fail
    assert verdict.reason == "MALFORMED"
    print("  [6] IPv4 Options Rejection (IHL=6 -> RC_MALFORMED): PASS")

    # 7. Unsupported L4 Protocol (ICMP=1) -> RC_MALFORMED
    raw_icmp = _build_test_packet(protocol=1, payload=b"ECHO_REQUEST")
    bus, verdict = process(raw_icmp)
    assert not bus.valid
    assert verdict.fail
    assert verdict.reason == "MALFORMED"
    print("  [7] Unsupported L4 Protocol Rejection (ICMP -> RC_MALFORMED): PASS")

    # 8. Truncated Frame (< 14 bytes) -> RC_MALFORMED
    short_pkt = b"\x00\x11\x22\x33\x44"
    bus, verdict = process(short_pkt)
    assert not bus.valid
    assert verdict.fail
    assert verdict.reason == "MALFORMED"
    print("  [8] Truncated Short Frame (<14B -> RC_MALFORMED): PASS")

    # 9. Wire Framing & CRC-32 Validation
    wire_frame = build_wire_frame(raw_tcp)
    ok, err_code, deframed = parse_wire_frame(wire_frame)
    assert ok, f"Valid wire frame deframing failed: error {err_code}"
    assert deframed == raw_tcp, "Deframed payload mismatch"

    # Corrupt CRC
    corrupted_crc_frame = wire_frame[:-2] + b"\xFF\xFF"
    ok, err_code, _ = parse_wire_frame(corrupted_crc_frame)
    assert not ok
    assert err_code == RC_CRC_FAIL, f"Expected RC_CRC_FAIL, got {err_code}"

    # Truncate wire frame
    truncated_wire = wire_frame[:20]
    ok, err_code, _ = parse_wire_frame(truncated_wire)
    assert not ok
    assert err_code == RC_FRAME_TIMEOUT, f"Expected RC_FRAME_TIMEOUT, got {err_code}"
    print("  [9] Wire Framing & CRC-32 Deframing Checks: PASS")

    print("\nALL pipeline.py checks passed successfully (0 failures).")


if __name__ == "__main__":
    run_self_test()

"""
model/pipeline.py
End-to-end Python reference: raw packet bytes in, verdict + output bytes out.

This is the oracle every cocotb testbench imports, so it exists as a stub from
day one rather than blocking testbench authoring (execution plan §9 item 2).

CURRENT STATE: pass-through. parse_headers() returns a struct with the right
SHAPE and all-zero values; classify() always returns PASS.

Fill in, in this order:
  Member A -> parse_headers()          real Ethernet/IPv4/TCP-UDP walk
  Member B -> model/detect.py          then wire into classify()
  Member D -> model/chacha_poly.py     then wire into process()
Member C's model/mlkem/ is already complete and KAT-verified.
"""

from dataclasses import dataclass, field

# Mirrors rtl/control/reason_codes.vh -- keep the values identical.
REASON = {
    "NONE": 0x0, "CRC_FAIL": 0x1, "FRAME_TIMEOUT": 0x2, "MALFORMED": 0x3,
    "SIGNATURE": 0x4, "FLOOD": 0x5, "SCAN": 0x6, "BAD_TAG": 0x7,
    "HANDSHAKE_KEY_INVALID": 0x8,
}

# packet_type, per interface_contract.md §4 (pending Member A's freeze).
PKT_HANDSHAKE_EK = 0b00
PKT_DATA         = 0b01
PKT_HANDSHAKE_CT = 0b10      # proposed: freeze package §3


@dataclass
class PacketBus:
    """Python twin of packet_bus_t in interface_contract.md §3.

    Field widths are in the contract; this mirrors its SHAPE so testbenches
    can be written against a stable struct before parser.v exists.
    """
    valid: bool = False
    sof: bool = False
    eof: bool = False
    data: bytes = b""

    eth_dst_mac: int = 0
    eth_src_mac: int = 0
    eth_type: int = 0

    ip_version_ihl: int = 0
    ip_total_length: int = 0
    ip_protocol: int = 0
    ip_src_addr: int = 0
    ip_dst_addr: int = 0

    l4_src_port: int = 0
    l4_dst_port: int = 0
    tcp_flags: int = 0
    l4_length: int = 0

    payload_len: int = 0
    session_id: int = 0
    packet_type: int = PKT_DATA
    payload: bytes = field(default=b"", repr=False)


@dataclass
class Verdict:
    fail: bool = False
    reason: str = "NONE"

    @property
    def code(self) -> int:
        return REASON[self.reason]


def parse_headers(raw: bytes) -> PacketBus:
    """STUB (Member A). Returns a correctly-shaped, all-zero bus."""
    return PacketBus(valid=True, sof=True, eof=True, payload_len=len(raw), payload=raw)


def classify(bus: PacketBus) -> Verdict:
    """STUB (Member B). Always passes."""
    return Verdict(fail=False, reason="NONE")


def process(raw: bytes):
    """Raw bytes -> (bus, verdict). The function cocotb testbenches call."""
    bus = parse_headers(raw)
    return bus, classify(bus)


if __name__ == "__main__":
    bus, verdict = process(b"\xde\xad\xbe\xef" * 8)
    print(f"payload_len={bus.payload_len}  fail={verdict.fail}  "
          f"reason={verdict.reason} (0x{verdict.code:X})")
    print("pipeline.py stub OK — parse_headers/classify await Members A and B.")

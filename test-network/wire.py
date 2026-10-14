"""
test-network/wire.py
Shared on-wire helpers for the live demo: framing, header building, the
ML-KEM handshake and the ChaCha20-Poly1305 data path.

Everything here mirrors the RTL exactly, and says which module it mirrors, so a
change on one side is obvious on the other:
  frame()        <-> rtl/ingress/deframer.v        (contract sections 1 and 2)
  eth_ip_udp()   <-> rtl/ingress/parser.v          (contract section 3)
  aad_for()      <-> rtl/crypto/chacha_poly/aead_framer.v (contract section 3.1)
  parse_telemetry() <-> rtl/io/telemetry_tx.v

The crypto comes from model/, which self-tests against the published FIPS 203
and RFC 8439 vectors, so the demo never carries a second implementation.
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from model.pipeline import compute_crc32                      # noqa: E402
from model.mlkem.kem import keygen_internal, decaps_internal   # noqa: E402
from model.chacha_poly import chacha20_poly1305_encrypt        # noqa: E402

PORT_HS_INIT, PORT_HS_RESP, PORT_DATA = 51001, 51002, 51010

FPGA_MAC = bytes.fromhex("aabbccddeeff")
HOST_MAC = bytes.fromhex("001122334455")
ATTACKER_MAC = bytes.fromhex("00dead00beef")

FPGA_IP = 0x0A0000FF
HOST_IP = 0x0A000001
ATTACKER_IP = 0x0A0000AB

TELEMETRY_FRAME_LEN = 52
TELEMETRY_FIELDS = ["crc_fail", "frame_timeout", "malformed", "signature",
                    "flood", "scan", "bad_tag", "handshake_key_invalid",
                    "total_drops", "total_passed", "lane_timeout",
                    "stray_verdict"]


def ip_checksum(hdr: bytes) -> int:
    total = 0
    for i in range(0, len(hdr), 2):
        total += int.from_bytes(hdr[i:i + 2], "big")
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def eth_ip_udp(payload: bytes, dst_port: int, src_port: int = 40000,
               src_ip: int = HOST_IP, dst_ip: int = FPGA_IP,
               src_mac: bytes = HOST_MAC, protocol: int = 17,
               tcp_flags: int = 0x10) -> bytes:
    """One Ethernet/IPv4/UDP (or TCP) frame, big-endian throughout, as
    parser.v decodes it. IHL is always 5: parser.v rejects options."""
    if protocol == 17:
        l4 = (src_port.to_bytes(2, "big") + dst_port.to_bytes(2, "big")
              + (8 + len(payload)).to_bytes(2, "big") + b"\x00\x00")
    else:
        # minimal 20-byte TCP header, data offset 5
        l4 = (src_port.to_bytes(2, "big") + dst_port.to_bytes(2, "big")
              + b"\x00\x00\x00\x01" + b"\x00\x00\x00\x00"
              + bytes([0x50, tcp_flags]) + b"\xff\xff\x00\x00\x00\x00")
    ip_len = 20 + len(l4) + len(payload)
    ip_no_csum = (b"\x45\x00" + ip_len.to_bytes(2, "big") + b"\x00\x01"
                  + b"\x00\x00" + bytes([64, protocol]) + b"\x00\x00"
                  + src_ip.to_bytes(4, "big") + dst_ip.to_bytes(4, "big"))
    ip = (ip_no_csum[:10] + ip_checksum(ip_no_csum).to_bytes(2, "big")
          + ip_no_csum[12:])
    return FPGA_MAC + src_mac + b"\x08\x00" + ip + l4 + payload


def frame(eth_payload: bytes, bad_crc: bool = False) -> bytes:
    """Contract sections 1 and 2: [2 B total_length BE][payload][4 B CRC-32 BE].
    total_length includes the prefix and the CRC; the CRC covers the payload."""
    total = 2 + len(eth_payload) + 4
    crc = compute_crc32(eth_payload)
    if bad_crc:
        crc ^= 0xFFFFFFFF
    return total.to_bytes(2, "big") + eth_payload + crc.to_bytes(4, "big")


def aad_for(src_ip: int, dst_ip: int, src_port: int, dst_port: int) -> bytes:
    """Must match aead_framer.v: src_ip || dst_ip || src_port || dst_port, each
    big-endian. Authenticating the 5-tuple binds a ciphertext to its session."""
    return (src_ip.to_bytes(4, "big") + dst_ip.to_bytes(4, "big")
            + src_port.to_bytes(2, "big") + dst_port.to_bytes(2, "big"))


class Session:
    """Host side of the handshake and the data path."""

    def __init__(self, src_ip: int = HOST_IP, src_port: int = 40000,
                 src_mac: bytes = HOST_MAC):
        self.src_ip, self.src_port, self.src_mac = src_ip, src_port, src_mac
        self.key = None
        self.nonce_ctr = 0
        self.ek, self.dk = None, None

    def handshake_init(self, d_seed: bytes = None, z_seed: bytes = None) -> bytes:
        """Generate a key pair and return the framed HS_INIT packet carrying ek."""
        d_seed = d_seed or os.urandom(32)
        z_seed = z_seed or os.urandom(32)
        self.ek, self.dk = keygen_internal(d_seed, z_seed)
        assert len(self.ek) == 800
        return frame(eth_ip_udp(self.ek, PORT_HS_INIT, self.src_port,
                                self.src_ip, src_mac=self.src_mac))

    def handshake_finish(self, reply_frame: bytes) -> bytes:
        """Take the board's 816-byte HS_RESP frame, verify it and derive the
        shared secret. Returns the secret."""
        if len(reply_frame) != 816:
            raise ValueError(f"reply is {len(reply_frame)} bytes, expected 816")
        declared = int.from_bytes(reply_frame[0:2], "big")
        if declared != 816:
            raise ValueError(f"reply length prefix says {declared}")
        payload, trailer = reply_frame[2:2 + 810], reply_frame[2 + 810:]
        if compute_crc32(payload) != int.from_bytes(trailer, "big"):
            raise ValueError("reply failed its CRC-32")
        if ip_checksum(payload[14:34]) != 0:
            raise ValueError("reply has a bad IPv4 header checksum")
        if int.from_bytes(payload[36:38], "big") != PORT_HS_RESP:
            raise ValueError("reply is not on PORT_HS_RESP")
        ct = payload[42:]
        if len(ct) != 768:
            raise ValueError(f"ciphertext is {len(ct)} bytes")
        self.key = decaps_internal(self.dk, ct)
        self.nonce_ctr = 0
        return self.key

    def data(self, plaintext: bytes, corrupt_tag: bool = False,
             wrong_src_ip: int = None) -> bytes:
        """Framed DATA packet. nonce advances per packet, matching the board's
        session nonce counter, which aead_framer.v steps via nonce_adv."""
        if self.key is None:
            raise RuntimeError("no session: run the handshake first")
        src_ip = self.src_ip if wrong_src_ip is None else wrong_src_ip
        aad = aad_for(self.src_ip, FPGA_IP, self.src_port, PORT_DATA)
        nonce = self.nonce_ctr.to_bytes(12, "little")
        ct, tag = chacha20_poly1305_encrypt(self.key, nonce, aad, plaintext)
        if corrupt_tag:
            tag = bytes([tag[0] ^ 0xFF]) + tag[1:]
        self.nonce_ctr += 1
        return frame(eth_ip_udp(ct + tag, PORT_DATA, self.src_port,
                                src_ip, src_mac=self.src_mac))


def parse_telemetry(buf: bytes):
    """Pull every complete telemetry frame out of a byte buffer.
    Returns (list_of_dicts, leftover_bytes). Mirrors rtl/io/telemetry_tx.v."""
    out, i = [], 0
    while i + TELEMETRY_FRAME_LEN <= len(buf):
        if buf[i] != 0xA5 or buf[i + 1] != 0x5A:
            i += 1
            continue
        f = buf[i:i + TELEMETRY_FRAME_LEN]
        if (sum(f) & 0xFF) != 0:
            i += 1          # checksum says this is not a frame boundary
            continue
        rec = {"session_established": bool(f[2] & 0x01),
               "fifo_overflow": bool(f[2] & 0x02),
               "kem_busy": bool(f[2] & 0x04)}
        for n, name in enumerate(TELEMETRY_FIELDS):
            off = 3 + 4 * n
            rec[name] = int.from_bytes(f[off:off + 4], "big")
        out.append(rec)
        i += TELEMETRY_FRAME_LEN
    return out, buf[i:]


def open_serial(port: str, baud: int = 3_000_000, timeout: float = 2.0):
    """Lazy import so the module is usable without pyserial for offline work."""
    import serial
    return serial.Serial(port=port, baudrate=baud, bytesize=8,
                         parity="N", stopbits=1, timeout=timeout)

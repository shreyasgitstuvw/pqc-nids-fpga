#!/usr/bin/env python3
"""
test-network/attacker.py
Third device. Sends the attacks the board is supposed to catch, none of which
need the session key, because the attacker does not have it.

    python test-network/attacker.py --port COM5 --attack scan
    python test-network/attacker.py --port COM5 --attack all

Attacks and the reason code each should produce:
  scan        many destination ports from one source     -> SCAN  (4'h6)
  flood       one flow, high rate                        -> FLOOD (4'h5)
  malformed   bad EtherType, IHL, protocol, TCP flags    -> MALFORMED (4'h3)
  crc         correct frame, corrupted CRC-32 trailer    -> CRC_FAIL (4'h1)
  truncated   length prefix promises more than is sent   -> FRAME_TIMEOUT (4'h2)
  forged      DATA packet with a made-up tag             -> BAD_TAG (4'h7)
  badkey      HS_INIT with a wrong-length ek             -> HANDSHAKE_KEY_INVALID (4'h8)

The signature attack is NOT here: a signature only exists in plaintext, so it
has to come from inside an authenticated session. Use
`python test-network/send.py --signature` for that one.
"""

import argparse
import sys
import time

import wire
sys.path.insert(0, wire.os.path.abspath(
    wire.os.path.join(wire.os.path.dirname(__file__), "..")))
from demo.config.demo_config import BAUD_RATE      # noqa: E402

A_IP, A_MAC = wire.ATTACKER_IP, wire.ATTACKER_MAC


def scan(ser, n=600):
    print(f"[TX] SCAN: {n} destination ports from one source")
    for port in range(1, n + 1):
        ser.write(wire.frame(wire.eth_ip_udp(
            b"", wire.PORT_DATA, src_port=port, src_ip=A_IP,
            src_mac=A_MAC, protocol=6, tcp_flags=0x02)))
    ser.flush()


def flood(ser, n=700):
    print(f"[TX] FLOOD: {n} packets on one flow as fast as the link allows")
    for i in range(n):
        ser.write(wire.frame(wire.eth_ip_udp(
            b"x" * 16, wire.PORT_DATA, src_port=1234, src_ip=A_IP,
            src_mac=A_MAC, protocol=6, tcp_flags=0x02)))
    ser.flush()


def malformed(ser):
    print("[TX] MALFORMED: bad EtherType, bad IHL, ICMP, and an illegal TCP flag set")
    # EtherType that is not IPv4 -- parser.v rejects it, protocol_validator
    # reports RC_MALFORMED.
    f = bytearray(wire.eth_ip_udp(b"z" * 8, wire.PORT_DATA, src_ip=A_IP,
                                  src_mac=A_MAC))
    f[12:14] = b"\x86\xdd"                       # IPv6
    ser.write(wire.frame(bytes(f)))
    # IHL = 6 (options present); contract section 3 rejects anything but 5.
    f = bytearray(wire.eth_ip_udp(b"z" * 8, wire.PORT_DATA, src_ip=A_IP,
                                  src_mac=A_MAC))
    f[14] = 0x46
    ser.write(wire.frame(bytes(f)))
    # ICMP: protocol not in {6, 17}
    ser.write(wire.frame(wire.eth_ip_udp(b"z" * 8, wire.PORT_DATA, src_ip=A_IP,
                                         src_mac=A_MAC, protocol=1)))
    # SYN+FIN together, which no legitimate stack sends
    ser.write(wire.frame(wire.eth_ip_udp(b"z" * 8, wire.PORT_DATA, src_ip=A_IP,
                                         src_mac=A_MAC, protocol=6,
                                         tcp_flags=0x03)))
    ser.flush()


def crc(ser, n=5):
    print(f"[TX] CRC_FAIL: {n} frames with a corrupted CRC-32 trailer")
    for i in range(n):
        ser.write(wire.frame(wire.eth_ip_udp(
            b"in transit corruption", wire.PORT_DATA, src_ip=A_IP,
            src_mac=A_MAC), bad_crc=True))
    ser.flush()


def truncated(ser):
    print("[TX] FRAME_TIMEOUT: a length prefix promising 400 bytes, then silence")
    body = wire.eth_ip_udp(b"q" * 64, wire.PORT_DATA, src_ip=A_IP, src_mac=A_MAC)
    ser.write((400).to_bytes(2, "big") + body[:40])
    ser.flush()
    # deframer.v times out after 50,000 cycles, which is 500 us at 100 MHz.
    time.sleep(0.05)


def forged(ser, n=3):
    print(f"[TX] BAD_TAG: {n} DATA packets with invented Poly1305 tags")
    for i in range(n):
        body = bytes([(i * 37 + j) & 0xFF for j in range(48)])
        ser.write(wire.frame(wire.eth_ip_udp(
            body, wire.PORT_DATA, src_ip=A_IP, src_mac=A_MAC)))
    ser.flush()


def badkey(ser):
    print("[TX] HANDSHAKE_KEY_INVALID: HS_INIT carrying 700 bytes instead of 800")
    ser.write(wire.frame(wire.eth_ip_udp(
        b"\xAA" * 700, wire.PORT_HS_INIT, src_ip=A_IP, src_mac=A_MAC)))
    ser.flush()


ATTACKS = {"scan": scan, "flood": flood, "malformed": malformed, "crc": crc,
           "truncated": truncated, "forged": forged, "badkey": badkey}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", required=True)
    ap.add_argument("--attack", default="all",
                    choices=sorted(ATTACKS) + ["all"])
    ap.add_argument("--pause", type=float, default=1.0,
                    help="seconds between attacks when running all of them")
    a = ap.parse_args()

    ser = wire.open_serial(a.port, BAUD_RATE)
    names = sorted(ATTACKS) if a.attack == "all" else [a.attack]
    for name in names:
        ATTACKS[name](ser)
        time.sleep(a.pause)
    print(f"[TX] done: {', '.join(names)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

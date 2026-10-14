#!/usr/bin/env python3
"""
test-network/recv.py
Live drop-engine counter display, read from the board's telemetry stream.

    python test-network/recv.py --port COM6

The board emits a 52-byte counter frame every 250 ms from rtl/io/telemetry_tx.v
(demo_config.DISPLAY_REFRESH_S). This decodes them and prints a one-line
refreshing table, plus a [DROP]/[ALERT] event line whenever a counter moves, in
the format demo/capture/session_log.py timestamps.
"""

import argparse
import sys
import time

import wire
sys.path.insert(0, wire.os.path.abspath(
    wire.os.path.join(wire.os.path.dirname(__file__), "..")))
from demo.config.demo_config import BAUD_RATE      # noqa: E402

# Which counters are attack detections worth an event line, and what to call them.
ALERTS = {"signature": "SIGNATURE", "flood": "FLOOD", "scan": "SCAN",
          "bad_tag": "BAD_TAG", "crc_fail": "CRC_FAIL",
          "frame_timeout": "FRAME_TIMEOUT", "malformed": "MALFORMED",
          "handshake_key_invalid": "HANDSHAKE_KEY_INVALID"}
# These two mean the design itself is unhappy, not that an attack was caught.
HEALTH = {"lane_timeout": "a packet was force-committed by the watchdog",
          "stray_verdict": "a lane reported with no packet open"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", required=True)
    ap.add_argument("--seconds", type=float, default=0.0,
                    help="stop after this long; 0 means run until interrupted")
    a = ap.parse_args()

    ser = wire.open_serial(a.port, BAUD_RATE, timeout=0.5)
    buf = b""
    prev = None
    t0 = time.time()
    print("[RX] waiting for telemetry frames (one every 250 ms)")

    try:
        while a.seconds == 0.0 or (time.time() - t0) < a.seconds:
            buf += ser.read(512)
            frames, buf = wire.parse_telemetry(buf)
            for f in frames:
                if prev is not None:
                    for k, name in ALERTS.items():
                        if f[k] > prev[k]:
                            print(f"[DROP] {name} +{f[k] - prev[k]} "
                                  f"(total {f[k]})")
                    for k, why in HEALTH.items():
                        if f[k] > prev[k]:
                            print(f"[ALERT] {k} +{f[k] - prev[k]}: {why}")
                prev = f
                sess = "UP  " if f["session_established"] else "down"
                print(f"\r[RX] session {sess} | passed {f['total_passed']:>6} "
                      f"dropped {f['total_drops']:>6} | "
                      f"sig {f['signature']:>4} flood {f['flood']:>4} "
                      f"scan {f['scan']:>4} tag {f['bad_tag']:>4} "
                      f"crc {f['crc_fail']:>4} mal {f['malformed']:>4} "
                      f"keyinv {f['handshake_key_invalid']:>3}",
                      end="", flush=True)
    except KeyboardInterrupt:
        pass

    print()
    if prev is None:
        print("[ALERT] no telemetry frames decoded. Check the port, the baud "
              "rate and that the bitstream is loaded.")
        return 1
    print(f"[RX] final: passed {prev['total_passed']}, "
          f"dropped {prev['total_drops']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

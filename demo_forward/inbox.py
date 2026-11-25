#!/usr/bin/env python3
"""
demo_forward/inbox.py -- Device B: shows what the FPGA delivered.
(PuTTY on the same COM port, 3000000 baud 8N1, shows the same text.)

    python demo_forward/inbox.py --port COM4
"""
import argparse, os, sys
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "test-network"))
sys.path.insert(0, ROOT)
import wire                                         # noqa: E402
from demo.config.demo_config import BAUD_RATE       # noqa: E402

ap = argparse.ArgumentParser(); ap.add_argument("--port", required=True)
a = ap.parse_args()
ser = wire.open_serial(a.port, BAUD_RATE, timeout=0.2)
print("Device B inbox. Only messages the FPGA decrypted AND approved appear here.\n")
buf = b""
try:
    while True:
        buf += ser.read(256)
        while b"\r\n" in buf:
            m, buf = buf.split(b"\r\n", 1)
            print("B< " + m.decode(errors="replace"))
except KeyboardInterrupt:
    pass

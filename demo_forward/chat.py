#!/usr/bin/env python3
"""
demo_forward/chat.py -- Device A: authenticated, encrypted chat through the FPGA.

    python demo_forward/chat.py --port COM3

Prints a secure-line banner after the ML-KEM handshake. Each typed line is
ChaCha20-Poly1305 encrypted with the session key (wire.Session.data) and sent
to the board. Device B sees it only if the board decrypts it, the tag verifies
and every detector passes.   /tamper = corrupt next packet's tag.  /quit exits.
"""
import argparse, hashlib, os, sys, time
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "test-network"))
sys.path.insert(0, ROOT)
import wire                                         # noqa: E402
from demo.config.demo_config import BAUD_RATE       # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", required=True)
    a = ap.parse_args()
    ser = wire.open_serial(a.port, BAUD_RATE)
    s = wire.Session()
    print("=== Secure line setup (post-quantum ML-KEM-512) ===")
    print("[1/3] Device A generated a key pair; sending public key to the FPGA")
    ser.write(s.handshake_init()); ser.flush()
    t0 = time.time(); buf = b""
    while len(buf) < 816 and time.time() - t0 < 5:
        buf += ser.read(816 - len(buf))
    if len(buf) < 816:
        print("[FAIL] FPGA did not answer. Check bitstream/port."); return 1
    try:
        key = s.handshake_finish(buf[:816])
    except ValueError as e:
        print(f"[FAIL] FPGA reply rejected: {e}"); return 1
    print(f"[2/3] FPGA encapsulated a secret; A decapsulated it ({time.time()-t0:.3f} s)")
    print(f"[3/3] SECURE LINE UP. Key fingerprint {hashlib.sha256(key).hexdigest()[:16]} (key never sent)")
    print("Type a message + Enter. /tamper corrupts the next one. /quit exits.\n")
    tamper = False
    while True:
        try:
            line = input("A> ")
        except (EOFError, KeyboardInterrupt):
            break
        if line == "/quit":
            break
        if line == "/tamper":
            tamper = True; print("(next message carries a corrupted tag)"); continue
        if not line:
            continue
        ser.write(s.data(line.encode(), corrupt_tag=tamper)); ser.flush()
        print("   sent TAMPERED -> FPGA should drop it" if tamper else "   sent (encrypted)")
        tamper = False
    return 0


if __name__ == "__main__":
    sys.exit(main())

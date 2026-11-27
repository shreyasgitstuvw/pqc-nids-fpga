#!/usr/bin/env python3
"""
demo_relay/peer.py -- Device A or Device B: a chat peer behind the FPGA gatekeeper.

    python demo_relay/peer.py --me A --port COM3
    python demo_relay/peer.py --me B --port COM5

Each peer does its OWN post-quantum (ML-KEM-512) handshake with the board over its OWN
serial link, then talks both ways through it. Messages cross the wire only as
ChaCha20-Poly1305 ciphertext, in both directions: the board decrypts and inspects
what you send, then RE-ENCRYPTS it under the other peer's key. Everything received
is shown twice, as the ciphertext that arrived and the plaintext this device decrypted
locally.   /ping  /tamper  /status  /quit
"""
import argparse, hashlib, os, sys, threading, time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "test-network"))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(__file__))
import wire                                         # noqa: E402
from demo.config.demo_config import BAUD_RATE       # noqa: E402
from relay_proto import EgressParser                # noqa: E402

os.system("")
G, R, D, X, BOLD = "\x1b[32m", "\x1b[31m", "\x1b[90m", "\x1b[0m", "\x1b[1m"
IDENT = {"A": dict(src_ip=0x0A000001, src_port=40000, src_mac=bytes.fromhex("001122334455")),
         "B": dict(src_ip=0x0A000002, src_port=40001, src_mac=bytes.fromhex("001122334466"))}
PING, PONG = b"\x01PING:", b"\x01PONG:"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--me", choices=["A", "B"], required=True)
    ap.add_argument("--port", required=True)
    a = ap.parse_args()
    me, other = a.me, ("B" if a.me == "A" else "A")
    ser = wire.open_serial(a.port, BAUD_RATE)
    s = wire.Session(**IDENT[me])
    print(f"{BOLD}=== Device {me}: secure line setup (post-quantum ML-KEM-512) ==={X}")
    print("[1/3] generated a key pair; sending the public key to the FPGA")
    ser.reset_input_buffer()
    ser.write(s.handshake_init()); ser.flush()
    t0, buf = time.time(), b""
    while len(buf) < 816 and time.time() - t0 < 6:
        buf += ser.read(816 - len(buf))
    if len(buf) < 816:
        print(f"{R}[FAIL] the FPGA did not answer. Check bitstream, port and wiring.{X}")
        return 1
    try:
        key = s.handshake_finish(buf[:816])
    except ValueError as e:
        print(f"{R}[FAIL] FPGA reply rejected: {e}{X}")
        return 1
    print(f"[2/3] the FPGA encapsulated a secret; I decapsulated it ({time.time()-t0:.2f} s)")
    print(f"{G}[3/3] SECURE LINE UP.{X} Key fingerprint {hashlib.sha256(key).hexdigest()[:16]} "
          "(the key never crossed the wire)")
    print(f"Test it: /ping. If Device {other} shows it, the line works end to end.")
    print("Commands: /ping  /tamper  /status  /quit\n")

    parser = EgressParser(key)
    lock = threading.Lock()
    state = {"ctr": 0, "got": 0}

    def send_text(raw: bytes, corrupt=False):
        pkt = s.data(raw, corrupt_tag=corrupt)
        state["ctr"] += 1
        return pkt

    def reader():
        while True:
            try:
                data = ser.read(ser.in_waiting or 1)
            except Exception:
                return
            for ctr, ct, pt in parser.feed(data):
                state["got"] += 1
                if pt.startswith(PING):
                    with lock:
                        ser.write(send_text(PONG + pt[len(PING):])); ser.flush()
                    print(f"\r{D}   [ping from {other} arrived and was answered]{X}\n{me}> ", end="", flush=True)
                    continue
                if pt.startswith(PONG):
                    rtt = (time.time() - float(pt[len(PONG):])) * 1000
                    print(f"\r{G}   SECURE LINE CONFIRMED: round trip to Device {other} and back "
                          f"through the FPGA in {rtt:.0f} ms{X}\n{me}> ", end="", flush=True)
                    continue
                print(f"\r{D}   [ciphertext on the wire] {ct[:24].hex()}...{X}\n"
                      f"{G}   [decrypted here, on {me}] {pt.decode(errors='replace')}{X}\n{me}> ",
                      end="", flush=True)

    threading.Thread(target=reader, daemon=True).start()
    tamper = False
    while True:
        try:
            line = input(f"{me}> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        if line == "/quit":
            break
        if line == "/status":
            print(f"   key held; {state['ctr']} sent, {state['got']} received, "
                  f"{parser.bad} bad frames discarded. Proof of the full path = /ping.")
            continue
        if line == "/tamper":
            tamper = True
            print("   (the next message carries a corrupted tag)")
            continue
        raw = line.encode()
        if line == "/ping":
            raw = PING + f"{time.time():.6f}".encode()
        with lock:
            ser.write(send_text(raw, tamper)); ser.flush()
        print(f"   {R}sent TAMPERED: the board should drop it{X}" if tamper
              else f"   {D}sent, encrypted{X}")
        tamper = False
    return 0


if __name__ == "__main__":
    sys.exit(main())

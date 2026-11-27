#!/usr/bin/env python3
"""
demo_sim/chat_sim.py -- a chat peer (simulation). Run it as Device A or Device B.

    python demo_sim/chat_sim.py --me A
    python demo_sim/chat_sim.py --me B

Both peers do their own handshake with the board, then talk both ways through it.
The board re-encrypts every relayed message for its destination, so no plaintext ever
crosses a wire. Each peer decrypts locally and shows both: the ciphertext that arrived,
and the plaintext it decrypted with its own key.
Commands:  /ping  /tamper  /status  /quit    (anything else is sent as a message)
"""
import argparse, hashlib, threading
from sim_common import *


def reader(link, me):
    from model.chacha_poly import chacha20_poly1305_decrypt
    while True:
        m = recv(link.sock)
        if m is None:
            break
        if m.get("t") == "egress":
            nonce = int(m["ctr"]).to_bytes(8, "little") + b"\x00\x00\x00\x80"
            ok, pt = chacha20_poly1305_decrypt(link.key, nonce, b"", bytes.fromhex(m["ct"]),
                                               bytes.fromhex(m["tag"]))
            if not ok:
                print(f"\r{R}   [frame failed authentication: discarded]{X}\n{me}> ", end="", flush=True)
                continue
            text = pt.decode(errors="replace")
            print(f"\r{D}   [ciphertext on the wire] {m['ct'][:48]}...{X}\n"
                  f"{G}   [decrypted here, on {me}] {text}{X}\n{me}> ", end="", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--me", choices=["A", "B"], default="A")
    me = ap.parse_args().me
    other = "B" if me == "A" else "A"
    link = Link(me)
    print(f"{BOLD}=== Device {me}: secure line setup (post-quantum ML-KEM-512) ==={X}  {D}[SIMULATION]{X}")
    print("[1/3] generated a key pair; sending public key to the board")
    key, _ = link.handshake()
    if not key:
        print(f"{R}[FAIL] no answer from the board{X}")
        return 1
    print("[2/3] board encapsulated a secret; I decapsulated it")
    print(f"{G}[3/3] SECURE LINE UP.{X} Key fingerprint {hashlib.sha256(key).hexdigest()[:16]} (the key never crossed the wire)")
    print(f"{D}Test it: /ping. If Device {other} shows it, the line works. {other} can answer the same way.{X}")
    print("Commands: /ping  /tamper  /status  /quit\n")
    threading.Thread(target=reader, args=(link, me), daemon=True).start()
    tamper, n = False, 0
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
            print(f"   my side: key held, {link.ctr} packets sent. Board: LD0 solid, session {me} ESTABLISHED.")
            print(f"   End-to-end proof is /ping arriving on Device {other}.")
            continue
        if line == "/tamper":
            tamper = True
            print("   (next message will carry a corrupted tag)")
            continue
        if line == "/ping":
            n += 1
            line = f"ping #{n} from {me}: secure line is live"
        p = link.send_data(line.encode(), corrupt=tamper)
        print(f"   {D}[ciphertext sent] {p['ct'][:48]}...  tag {p['tag'][:16]}...{X}")
        print(f"   {R}sent TAMPERED. The board should drop it.{X}" if tamper else "   sent (encrypted)")
        tamper = False
    return 0


if __name__ == "__main__":
    sys.exit(main())

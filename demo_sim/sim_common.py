"""
demo_sim/sim_common.py -- shared helpers for the rehearsal simulator.

SIMULATION ONLY. A Python process plays the ZedBoard so you can rehearse the demo
with no hardware. It uses the repo's real crypto (model/): ML-KEM-512 for the
handshake, ChaCha20-Poly1305 for messages, and the real CAM signature list for
the attack-pattern check. Detection thresholds are scaled down so the flood trips
in a second or two. Timings are NOT hardware timings.
"""
import json, os, socket, struct, sys, time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)
HOST, PORT = "127.0.0.1", 7000
os.system("")                      # turns on ANSI colours in Windows terminals
R, G, Y, B, D, X, BOLD = ("\x1b[31m", "\x1b[32m", "\x1b[33m", "\x1b[36m",
                          "\x1b[90m", "\x1b[0m", "\x1b[1m")


def send(sock, obj):
    data = json.dumps(obj).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)


def _rx(sock, n):
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except OSError:
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def recv(sock):
    hdr = _rx(sock, 4)
    if not hdr:
        return None
    body = _rx(sock, struct.unpack(">I", hdr)[0])
    return None if body is None else json.loads(body)


def connect(role):
    s = socket.socket()
    try:
        s.connect((HOST, PORT))
    except OSError:
        print(f"{R}Cannot reach the simulated board. Start board_sim.py first.{X}")
        sys.exit(1)
    send(s, {"t": "hello", "role": role})
    return s


def aad_for(src):
    return f"SIM|{src}".encode()


class Link:
    """Sender side (Device A or C): handshake plus the encrypted data path."""

    def __init__(self, ident):
        from model.chacha_poly import chacha20_poly1305_encrypt
        self._enc = chacha20_poly1305_encrypt
        self.id, self.sock = ident, connect(ident)
        self.key, self.ctr, self.last = None, 0, None

    def handshake(self, bad_key=False):
        from model.mlkem.kem import keygen_internal, decaps_internal
        t0 = time.time()
        ek, dk = keygen_internal(os.urandom(32), os.urandom(32))
        if bad_key:
            ek = ek[:700]
        send(self.sock, {"t": "hs_init", "ek": ek.hex()})
        self.sock.settimeout(3.0)
        try:
            msg = recv(self.sock)
        except OSError:
            msg = None
        self.sock.settimeout(None)
        if not msg or msg.get("t") != "hs_resp":
            return None, time.time() - t0
        self.key = decaps_internal(dk, bytes.fromhex(msg["ct"]))
        self.ctr = 0
        return self.key, time.time() - t0

    def packet(self, pt, corrupt=False, key=None):
        nonce = self.ctr.to_bytes(12, "little")
        ct, tag = self._enc(key or self.key, nonce, aad_for(self.id), pt)
        if corrupt:
            tag = bytes([tag[0] ^ 0xFF]) + tag[1:]
        self.ctr += 1
        return {"t": "data", "ct": ct.hex(), "tag": tag.hex()}

    def send_data(self, pt, corrupt=False, key=None):
        p = self.packet(pt, corrupt, key)
        self.last = p
        send(self.sock, p)
        return p

    def raw(self, kind):
        send(self.sock, {"t": "raw", "kind": kind})

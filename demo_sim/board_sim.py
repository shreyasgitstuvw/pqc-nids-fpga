#!/usr/bin/env python3
"""
demo_sim/board_sim.py -- the simulated ZedBoard (LED panel + gatekeeper logic).

    python demo_sim/board_sim.py            # panel only; Device B has its own terminal
    python demo_sim/board_sim.py --inbox    # panel also shows what Device B receives (3-terminal mode)

Behaves like the planned bitstream: LD0 means "a peer's handshake finished" (not the
automatic start-up key generation), decisions are store-and-forward (a message is only
relayed after every check has passed, RE-ENCRYPTED for its destination), and one winning reason per packet with the
priority CRC > TIMEOUT > MALFORMED > BAD_TAG > SIGNATURE > FLOOD. Identity is the LINK a
frame arrives on, never an address inside it, so claiming to be another peer achieves nothing.
"""
import argparse, socket, threading, time
from collections import deque
from sim_common import *

FLOOD_N, EPOCH_S, HOLD_S, DELIVER_DELAY = 150, 2.0, 1.8, 0.12
LEDS = ["session", "crc", "timeout", "malformed", "signature", "flood", "scan", "bad tag"]
REASON_LED = {"CRC_FAIL": 1, "FRAME_TIMEOUT": 2, "MALFORMED": 3, "SIGNATURE": 4,
              "FLOOD": 5, "SCAN": 6, "BAD_TAG": 7, "KEY_INVALID": 0}
FAST = {0, 4, 7}
lock = threading.Lock()
sessions, hold = {}, {}
counters = {"passed": 0, "dropped": 0, "relayed": 0, **{k: 0 for k in REASON_LED}}
events = deque(maxlen=11)
clients = {}
times = {}
args = None


def log(msg, color=""):
    events.append(f"{D}{time.strftime('%H:%M:%S')}{X} {color}{msg}{X}")


last = {"key": None, "n": 0}


def drop(src, reason, detail):
    with lock:
        counters["dropped"] += 1
        counters[reason] += 1
        hold[REASON_LED[reason]] = time.time() + HOLD_S
        key = (src, reason)
        if last["key"] == key and events:
            last["n"] += 1
            events[-1] = (f"{D}{time.strftime('%H:%M:%S')}{X} {R}DROP  {src}: {reason}  "
                          f"({detail})  x{last['n']}{X}")
        else:
            last["key"], last["n"] = key, 1
            log(f"DROP  {src}: {reason}  ({detail})", R)


def passed(src, detail):
    with lock:
        last["key"] = None
        counters["passed"] += 1
        log(f"PASS  {src}: {detail}", G)


ROUTE = {"A": "B", "B": "A", "C": "B"}     # who receives what each sender says


egress_ctr = {}


def deliver(src, text, ct):
    """Re-encrypt for the destination under ITS key. Plaintext never leaves the board."""
    from model.chacha_poly import chacha20_poly1305_encrypt
    time.sleep(DELIVER_DELAY)               # store-and-forward: held until verdict
    dest = ROUTE.get(src, "B")
    peer = clients.get(dest)
    ds = sessions.get(dest)
    if not ds:
        with lock:
            log(f"no secure line to {dest} yet: message not relayed (board never sends plaintext)", Y)
        return
    with lock:
        n = egress_ctr.get(dest, 0)
        egress_ctr[dest] = n + 1
    nonce = n.to_bytes(8, "little") + b"\x00\x00\x00\x80"
    ect, etag = chacha20_poly1305_encrypt(ds["key"], nonce, b"", text.encode())
    with lock:
        counters["relayed"] += 1
        log(f"RELAY {src} -> {dest}: re-encrypted under {dest}'s key ({len(ect)} B, ctr {n})", B)
    if peer:
        try:
            send(peer, {"t": "egress", "ctr": n, "ct": ect.hex(), "tag": etag.hex()})
        except OSError:
            pass


def handle_data(src, m):
    # IDENTITY IS THE LINK. `src` is the socket this frame arrived on, which stands in
    # for the physical cable. A claimed address inside the frame (m["as"]) is logged as
    # an attempt and then ignored: the board decides who you are by where you came from,
    # so it can never be talked into using someone else's slot or key.
    claimed = m.get("as")
    if claimed and claimed != src:
        with lock:
            log(f"{src} claims to be {claimed}; identity is the link, so it is still "
                f"{src}", Y)
    from model.chacha_poly import chacha20_poly1305_decrypt
    from model.detect import CAM_SIGNATURES
    s = sessions.get(src)
    if not s:
        return drop(src, "BAD_TAG", "no session for this sender")
    nonce = s["ctr"].to_bytes(12, "little")
    s["ctr"] += 1                           # board steps its nonce on every packet
    ok, pt = chacha20_poly1305_decrypt(s["key"], nonce, aad_for(src),
                                       bytes.fromhex(m["ct"]), bytes.fromhex(m["tag"]))
    if not ok:
        return drop(src, "BAD_TAG", "authentication tag does not verify")
    matched = None
    for sig in CAM_SIGNATURES:
        i = pt.find(sig["pattern"])
        if i >= 0:
            matched = (sig["name"], i)
            break
    now = time.time()
    q = times.setdefault(src, deque())
    q.append(now)
    while q and now - q[0] > EPOCH_S:
        q.popleft()
    if matched:
        return drop(src, "SIGNATURE", f"{matched[0]} found inside the decrypted payload at byte {matched[1]}")
    if len(q) > FLOOD_N:
        return drop(src, "FLOOD", f"{len(q)} packets in {EPOCH_S:.0f}s from one source")
    if not pt:
        return passed(src, "empty payload (nothing to deliver)")
    passed(src, f"authenticated, clean ({len(pt)} B)")
    threading.Thread(target=deliver, args=(src, pt.decode(errors="replace"), m["ct"]), daemon=True).start()


def handle_hs(src, m):
    from model.mlkem.kem import encaps_internal
    claimed = m.get("as")
    if claimed and claimed != src:
        with lock:
            log(f"{src} sent a handshake claiming to be {claimed}; filing it under "
                f"{src}'s own link", Y)
    ek = bytes.fromhex(m["ek"])
    if len(ek) != 800:
        with lock:
            counters["dropped"] += 1
            counters["KEY_INVALID"] += 1
            hold[0] = time.time() + HOLD_S
            sessions.pop(src, None)
            log(f"REJECT {src}: public key is {len(ek)} B, not 800. No session, no reply", R)
        return
    k, c = encaps_internal(ek, os.urandom(32))
    with lock:
        sessions[src] = {"key": k, "ctr": 0}
        egress_ctr[src] = 0
    passed(src, "handshake: board encapsulated, shared key stored")
    send(clients[src], {"t": "hs_resp", "ct": c.hex()})


RAW = {"crc": ("CRC_FAIL", "frame checksum wrong"),
       "truncated": ("FRAME_TIMEOUT", "frame stopped mid-way, deframer timed out"),
       "malformed": ("MALFORMED", "illegal header fields"),
       "scan": ("MALFORMED", "probes to ports that are not valid (scan detector never gets a vote today)")}


def client(conn):
    hello = recv(conn)
    if not hello:
        return
    role = hello["role"]
    clients[role] = conn
    with lock:
        log(f"link up: Device {role}", D)
    while True:
        m = recv(conn)
        if m is None:
            break
        try:
            if m["t"] == "hs_init":
                handle_hs(role, m)
            elif m["t"] == "data":
                handle_data(role, m)
            elif m["t"] == "raw":
                r, why = RAW[m["kind"]]
                drop(role, r, why)
        except Exception as e:                  # a bad packet must never kill the board
            with lock:
                log(f"internal error handling {role}: {e}", R)
    clients.pop(role, None)


def panel():
    while True:
        t, rows = time.time(), []
        with lock:
            lit = {}
            for i in range(8):
                on = False
                if i == 0 and hold.get(0, 0) > t:
                    on = int(t * 8) % 2 == 0
                elif i == 0:
                    on = bool(sessions)
                elif hold.get(i, 0) > t:
                    on = int(t * (8 if i in FAST else 2)) % 2 == 0
                lit[i] = on
            leds = []
            for i in range(8):
                dot = (f"{G if i == 0 else R}●{X}" if lit[i] else f"{D}○{X}")
                leds.append(f"LD{i} {dot} {LEDS[i]:<9}")
            c = counters
            sess = " ".join(f"{k}:{G}ESTABLISHED{X}" for k in sorted(sessions)) or f"{D}none{X}"
            out = ["\x1b[H\x1b[J",
                   f"{BOLD}ZEDBOARD (SIMULATED){X}  post-quantum gatekeeper\n",
                   "  ".join(leds[:4]), "  ".join(leds[4:]), "",
                   f"sessions: {sess}",
                   f"passed {G}{c['passed']}{X}  relayed {B}{c['relayed']}{X}  dropped {R}{c['dropped']}{X} | crc {c['CRC_FAIL']} "
                   f"timeout {c['FRAME_TIMEOUT']} malformed {c['MALFORMED']} sig {c['SIGNATURE']} "
                   f"flood {c['FLOOD']} scan {c['SCAN']} tag {c['BAD_TAG']} keyinv {c['KEY_INVALID']}", "",
                   *events]
        print("\n".join(out), flush=True)
        time.sleep(0.25)


def main():
    global args
    ap = argparse.ArgumentParser()
    ap.add_argument("--inbox", action="store_true")
    args = ap.parse_args()
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(8)
    log("board ready: automatic key generation done. LD0 stays dark until a peer handshakes", D)
    threading.Thread(target=panel, daemon=True).start()
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=client, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()

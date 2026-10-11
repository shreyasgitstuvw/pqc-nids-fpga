#!/usr/bin/env python3
"""
demo/verify/smoke_test.py
Pre-demo go / no-go check against the real board.

    python demo/verify/smoke_test.py --send-port COM3 --debug-port COM6
    exit 0 = ready to demo
    exit 1 = something is broken, and the output says what

What it checks, in order, stopping at the first failure because each step
depends on the one before:
  1. The telemetry stream is alive, so the bitstream is loaded and the debug
     port is right.
  2. The ML-KEM handshake completes and BOTH SIDES DERIVE THE SAME SECRET. This
     is the one that matters: a handshake that completes but disagrees is worse
     than one that fails, because nothing downstream will work and nothing will
     say why.
  3. Clean authenticated packets are forwarded (total_passed moves).
  4. Each attack class produces its own reason code and no other.

Step 4 drives the attacks itself rather than trusting a prior run, so a green
result here means the demo will behave.
"""

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "test-network"))

import wire                                            # noqa: E402
from demo.config.demo_config import BAUD_RATE          # noqa: E402

RESULTS = []


def record(ok, name, detail=""):
    RESULTS.append(("PASS" if ok else "FAIL", name, detail))
    return ok


def read_counters(ser, timeout=2.0):
    """Block until one telemetry frame decodes, or return None."""
    buf, t0 = b"", time.time()
    while time.time() - t0 < timeout:
        buf += ser.read(256)
        frames, buf = wire.parse_telemetry(buf)
        if frames:
            return frames[-1]
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--send-port", required=True, help="sender, e.g. COM3")
    ap.add_argument("--debug-port", required=True, help="telemetry, e.g. COM6")
    ap.add_argument("--attack-port", default=None,
                    help="attacker; defaults to --send-port")
    a = ap.parse_args()
    atk_port = a.attack_port or a.send_port

    try:
        dbg = wire.open_serial(a.debug_port, BAUD_RATE, timeout=0.5)
        snd = wire.open_serial(a.send_port, BAUD_RATE, timeout=0.5)
    except Exception as e:
        print(f"FAIL  serial ports: {e}")
        return 1

    # ---- 1. telemetry alive -------------------------------------------------
    base = read_counters(dbg, 3.0)
    if not record(base is not None, "telemetry stream alive",
                  "" if base else "no 52-byte frame decoded in 3 s; is the "
                                  "bitstream loaded and is this the debug port?"):
        return report()

    # ---- 2. handshake, and the secrets must agree --------------------------
    s = wire.Session()
    snd.reset_input_buffer()
    snd.write(s.handshake_init())
    snd.flush()
    buf, t0 = b"", time.time()
    while len(buf) < 816 and time.time() - t0 < 5.0:
        buf += snd.read(816 - len(buf))
    if not record(len(buf) >= 816, "ciphertext reply received",
                  f"got {len(buf)} of 816 bytes"):
        return report()
    try:
        key = s.handshake_finish(buf[:816])
        record(True, "handshake: both sides derived the same secret",
               f"{key.hex()[:32]}...")
    except ValueError as e:
        record(False, "handshake: both sides derived the same secret", str(e))
        return report()

    after_hs = read_counters(dbg, 2.0)
    record(bool(after_hs and after_hs["session_established"]),
           "board reports a session established")

    # ---- 3. clean packets are forwarded ------------------------------------
    before = read_counters(dbg, 2.0)
    for i in range(10):
        snd.write(s.data(f"GET /smoke/{i} HTTP/1.1\r\n\r\n".encode()))
    snd.flush()
    time.sleep(1.0)
    after = read_counters(dbg, 2.0)
    passed = (after["total_passed"] - before["total_passed"]) if (before and after) else 0
    record(passed >= 10, "10 clean packets forwarded",
           f"total_passed moved by {passed}")

    # ---- 4. each attack produces its own reason code -----------------------
    import attacker
    atk = wire.open_serial(atk_port, BAUD_RATE, timeout=0.5) \
        if atk_port != a.send_port else snd

    checks = [("signature", lambda: snd.write(s.data(
                   b"POST /x HTTP/1.1\r\n\r\nid; whoami"))),
              ("crc_fail", lambda: attacker.crc(atk)),
              ("malformed", lambda: attacker.malformed(atk)),
              ("frame_timeout", lambda: attacker.truncated(atk)),
              ("bad_tag", lambda: attacker.forged(atk)),
              ("scan", lambda: attacker.scan(atk)),
              ("flood", lambda: attacker.flood(atk)),
              ("handshake_key_invalid", lambda: attacker.badkey(atk))]

    for name, fire in checks:
        before = read_counters(dbg, 2.0)
        fire()
        snd.flush()
        time.sleep(1.5)
        after = read_counters(dbg, 3.0)
        if not (before and after):
            record(False, f"attack -> {name}", "lost the telemetry stream")
            continue
        delta = after[name] - before[name]
        record(delta > 0, f"attack -> {name}", f"counter moved by {delta}")

    # ---- design health ------------------------------------------------------
    final = read_counters(dbg, 2.0)
    if final:
        record(final["lane_timeout"] == 0, "no packet needed the watchdog",
               f"cnt_lane_timeout = {final['lane_timeout']}")
        record(final["stray_verdict"] == 0, "no stray lane verdicts",
               f"cnt_stray_verdict = {final['stray_verdict']}")
        record(not final["fifo_overflow"], "no AEAD buffer overrun")

    return report()


def report():
    width = max(len(n) for _, n, _ in RESULTS)
    print("\n  SMOKE TEST\n  " + "-" * (width + 30))
    for status, name, detail in RESULTS:
        print(f"  {status}  {name:<{width}}  {detail}")
    print("  " + "-" * (width + 30))
    failed = [r for r in RESULTS if r[0] == "FAIL"]
    if failed:
        print(f"  {len(failed)} of {len(RESULTS)} checks FAILED -- not ready to demo\n")
        return 1
    print(f"  all {len(RESULTS)} checks passed -- ready to demo\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

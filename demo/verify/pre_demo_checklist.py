"""
demo/verify/pre_demo_checklist.py
Automated go/no-go, run BEFORE the judge arrives.

Prints PASS/FAIL per item and exits 0 only if everything passes. The checks
that need hardware are marked SKIP until Phase VIII -- the point is that the
list itself exists and grows, not that it is complete today.

    python demo/verify/pre_demo_checklist.py
"""

import importlib.util
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

RESULTS = []


def check(name, fn, hardware=False):
    if hardware and not os.environ.get("DEMO_HARDWARE"):
        RESULTS.append(("SKIP", name, "set DEMO_HARDWARE=1 once the board is on the bench"))
        return
    try:
        ok, detail = fn()
    except Exception as e:                                   # noqa: BLE001
        ok, detail = False, f"{type(e).__name__}: {e}"
    RESULTS.append(("PASS" if ok else "FAIL", name, detail))


# ------------------------------------------------------------ software
def _deps():
    missing = [m for m in ("serial", "Crypto") if importlib.util.find_spec(m) is None]
    return (not missing, "all present" if not missing else f"missing: {', '.join(missing)}")


def _model_imports():
    from model.mlkem.kem import KeyGen, Encaps, Decaps        # noqa: F401
    return True, "model.mlkem.kem imports"


def _kem_roundtrip():
    from model.mlkem.kem import KeyGen, Encaps, Decaps
    ek, dk = KeyGen()
    k, c = Encaps(ek)
    return (Decaps(dk, c) == k), "shared secrets agree"


def _kat_vectors():
    base = os.path.join("sim", "vectors", "fips203_kat")
    need = ["mlkem512_keygen.json", "mlkem512_encap_decap.json"]
    miss = [f for f in need if not os.path.isfile(os.path.join(base, f))]
    return (not miss, "present" if not miss else f"missing: {miss}")


def _config():
    from demo.config import demo_config as cfg
    return (cfg.BAUD_RATE == 3_000_000), f"baud {cfg.BAUD_RATE}"


def _attack_sequence():
    import json
    with open(os.path.join("demo", "config", "attack_sequence.json")) as f:
        seq = json.load(f)["sequence"]
    return (len(seq) > 0), f"{len(seq)} steps"


# ------------------------------------------------------------ hardware
def _serial_ports():
    import serial                                            # noqa: F401
    from demo.config import demo_config as cfg
    import serial.tools.list_ports as lp
    have = {p.device for p in lp.comports()}
    want = {cfg.PORT_DEVICE_A, cfg.PORT_DEVICE_B, cfg.PORT_ATTACKER}
    missing = want - have
    return (not missing, "all open" if not missing else f"missing: {sorted(missing)}")


def _bitstream():
    p = os.path.join("build", "pqc_nids.bit")
    return (os.path.isfile(p), p if os.path.isfile(p) else "not built")


def _fpga_ping():
    return False, "not implemented until Phase VIII"


if __name__ == "__main__":
    check("Python dependencies", _deps)
    check("Model imports", _model_imports)
    check("ML-KEM round trip", _kem_roundtrip)
    check("KAT vectors on disk", _kat_vectors)
    check("demo_config loads", _config)
    check("attack_sequence.json parses", _attack_sequence)
    check("Serial ports open", _serial_ports, hardware=True)
    check("Bitstream built", _bitstream, hardware=True)
    check("FPGA responds over UART", _fpga_ping, hardware=True)

    width = max(len(n) for _, n, _ in RESULTS)
    print("\n  PRE-DEMO CHECKLIST\n  " + "-" * (width + 30))
    for status, name, detail in RESULTS:
        print(f"  {status:<5} {name:<{width}}  {detail}")

    failed = sum(1 for s, _, _ in RESULTS if s == "FAIL")
    skipped = sum(1 for s, _, _ in RESULTS if s == "SKIP")
    print("  " + "-" * (width + 30))
    print(f"  {len(RESULTS) - failed - skipped} pass, {failed} fail, {skipped} skipped\n")
    sys.exit(1 if failed else 0)

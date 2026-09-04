"""
model/mlkem/kat_test.py
FIPS 203 known-answer test (KAT) runner for ML-KEM-512.

Phase 6 hard gate. Self-tests prove internal consistency (encaps then decaps
agree with each other). They cannot prove correctness: an implementation with
a wrong zeta table, wrong bit order, or wrong domain separator will still
round-trip with itself perfectly. Only fixed external vectors catch that,
because they pin every intermediate byte to what NIST's reference produced.

Vector files are ACVP-format and contain ML-KEM-512, -768 and -1024 in the
same file despite the -512 filename. We implement only 512, so every group
is filtered on parameterSet.

Groups exercised
----------------
  keyGen AFT            (d,z)  -> ek, dk     tests keygen_internal
  encapsulation AFT     (ek,m) -> c,  k      tests encaps_internal
  decapsulation VAL     (dk,c) -> k          tests decaps_internal

The decapsulation group is the one that matters most. Its cases are a mix of
"valid decapsulation" and "modified ciphertext", and it gives the expected
shared secret for BOTH. On a modified ciphertext the expected value is the
implicit-rejection key Kbar = J(z||c), so this group proves the FO transform
is byte-exact rather than merely "returns something different" -- which is
all the round-trip self-test could establish.

  encapsulationKeyCheck  ek     -> bool     tests check_ek  (sec 7.2)
  decapsulationKeyCheck  dk     -> bool     tests check_dk  (sec 7.3)

The two key-check groups assert a boolean rather than a value: given a key,
does the implementation accept it? Half the cases carry deliberately corrupted
keys -- an ek with coefficients in 3329..4095 ("noisy linear system values too
large"), or a dk whose embedded H(ek) was altered ("modified H") -- and the
implementation is required to reject exactly those and no others.
"""

import json
import os
import sys

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from model.mlkem.kem import (keygen_internal, encaps_internal, decaps_internal,
                            check_ek, check_dk)

PARAM_SET = "ML-KEM-512"
VECTOR_DIR = os.path.join(repo_root, "sim", "vectors", "fips203_kat")

passed = 0
failed = 0
skipped = 0
failures = []


def hx(s):
    """ACVP hex is uppercase; bytes.fromhex is case-insensitive."""
    return bytes.fromhex(s)


def record(ok, tcid, group, detail=""):
    global passed, failed
    if ok:
        passed += 1
    else:
        failed += 1
        failures.append((group, tcid, detail))


def cmp_field(name, got, want):
    """Return a short diff description, or None if equal."""
    if got == want:
        return None
    if len(got) != len(want):
        return f"{name}: length {len(got)} != expected {len(want)}"
    first = next(i for i in range(len(got)) if got[i] != want[i])
    return (f"{name}: first differing byte at offset {first} "
            f"(got 0x{got[first]:02X}, want 0x{want[first]:02X}); "
            f"got={got.hex()[:32]}... want={want.hex()[:32]}...")


# ---------------------------------------------------------------- keyGen
def run_keygen(path):
    doc = json.load(open(path))
    for g in doc["testGroups"]:
        if g.get("parameterSet") != PARAM_SET:
            continue
        print(f"\n-- keyGen  tgId={g['tgId']}  {g['testType']}  "
              f"({len(g['tests'])} cases)")
        for t in g["tests"]:
            d, z = hx(t["d"]), hx(t["z"])
            want_ek, want_dk = hx(t["ek"]), hx(t["dk"])
            got_ek, got_dk = keygen_internal(d, z)
            diffs = [x for x in (cmp_field("ek", got_ek, want_ek),
                                 cmp_field("dk", got_dk, want_dk)) if x]
            record(not diffs, t["tcId"], "keyGen", "; ".join(diffs))
        print(f"   {len(g['tests'])} cases run")


# ------------------------------------------------------- encaps / decaps
def run_encap_decap(path):
    doc = json.load(open(path))
    for g in doc["testGroups"]:
        if g.get("parameterSet") != PARAM_SET:
            continue
        fn = g.get("function")
        n = len(g["tests"])

        if fn == "encapsulation":
            print(f"\n-- encapsulation  tgId={g['tgId']}  {g['testType']}  "
                  f"({n} cases)")
            for t in g["tests"]:
                ek, m = hx(t["ek"]), hx(t["m"])
                want_k, want_c = hx(t["k"]), hx(t["c"])
                got_k, got_c = encaps_internal(ek, m)
                diffs = [x for x in (cmp_field("c", got_c, want_c),
                                     cmp_field("k", got_k, want_k)) if x]
                record(not diffs, t["tcId"], "encapsulation", "; ".join(diffs))
            print(f"   {n} cases run")

        elif fn == "decapsulation":
            reasons = {}
            for t in g["tests"]:
                reasons[t.get("reason", "?")] = reasons.get(t.get("reason", "?"), 0) + 1
            print(f"\n-- decapsulation  tgId={g['tgId']}  {g['testType']}  "
                  f"({n} cases)")
            for r, c in sorted(reasons.items()):
                print(f"     {c:2d} x {r}")
            for t in g["tests"]:
                dk, c = hx(t["dk"]), hx(t["c"])
                want_k = hx(t["k"])
                got_k = decaps_internal(dk, c)
                diff = cmp_field("k", got_k, want_k)
                detail = f"[{t.get('reason','?')}] {diff}" if diff else ""
                record(not diff, t["tcId"], "decapsulation", detail)
            print(f"   {n} cases run")

        elif fn in ("encapsulationKeyCheck", "decapsulationKeyCheck"):
            # These groups assert a boolean: does the implementation ACCEPT
            # this key? Expected answer is t["testPassed"]. A case with
            # testPassed=False carries a deliberately corrupted key and the
            # implementation is required to reject it.
            check = check_ek if fn == "encapsulationKeyCheck" else check_dk
            field = "ek" if fn == "encapsulationKeyCheck" else "dk"
            reasons = {}
            for t in g["tests"]:
                r = t.get("reason", "?")
                reasons[r] = reasons.get(r, 0) + 1
            print(f"\n-- {fn}  tgId={g['tgId']}  {g['testType']}  ({n} cases)")
            for r, cnt in sorted(reasons.items()):
                print(f"     {cnt:2d} x {r}")
            for t in g["tests"]:
                want = t["testPassed"]
                got = check(hx(t[field]))
                detail = ("" if got == want else
                          f"[{t.get('reason','?')}] check_{field} returned "
                          f"{got}, expected {want}")
                record(got == want, t["tcId"], fn, detail)
            print(f"   {n} cases run")

        else:
            global skipped
            skipped += n
            print(f"\n-- {fn}  tgId={g['tgId']}  ({n} cases)  SKIP -- unhandled")


if __name__ == "__main__":
    print("=" * 68)
    print(f"FIPS 203 KAT runner -- {PARAM_SET}")
    print("=" * 68)

    run_keygen(os.path.join(VECTOR_DIR, "mlkem512_keygen.json"))
    run_encap_decap(os.path.join(VECTOR_DIR, "mlkem512_encap_decap.json"))

    print("\n" + "=" * 68)
    if failures:
        print(f"FAILURES ({len(failures)}):\n")
        for grp, tcid, detail in failures[:15]:
            print(f"  {grp} tcId={tcid}")
            print(f"    {detail}")
        if len(failures) > 15:
            print(f"  ... and {len(failures)-15} more")
        print()

    print(f"passed  {passed}")
    print(f"failed  {failed}")
    print(f"skipped {skipped}")
    print("=" * 68)

    if failed:
        print("\nGATE FAILED")
        raise SystemExit(1)
    print("\nGATE PASSED -- ML-KEM-512 matches FIPS 203 reference vectors.")

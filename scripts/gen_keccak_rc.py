#!/usr/bin/env python3
"""
scripts/gen_keccak_rc.py
Emit rtl/crypto/sha3/keccak_rc.vh from the frozen Python twin.

Why this exists
---------------
model/sha3.py holds the 24 iota round constants (RC) and the 5x5 rho rotation
offsets (ROTC). Hand-copying them into keccak_f1600.v is the obvious approach
and the wrong one: a single mistyped hex digit yields a module that permutes
deterministically, passes a smoke test, and then fails FIPS 202 with a diffused
1600-bit mismatch that says nothing about which constant is wrong. Bisecting
that costs more than a day, and the same bug inside mlkem_top.v silently
corrupts every SHAKE expansion downstream.

Generating the header makes the constants have exactly one source -- the frozen,
KAT-verified model -- so the transcription bug is impossible rather than merely
unlikely.

Usage
-----
    python scripts/gen_keccak_rc.py            # write the header
    python scripts/gen_keccak_rc.py --check    # verify it is up to date (CI)

--check exits non-zero if the committed header does not match what the model
would produce right now, so the header cannot silently drift from the twin.
"""

import argparse
import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from model.sha3 import RC, ROTC  # noqa: E402

OUT = os.path.join(REPO, "rtl", "crypto", "sha3", "keccak_rc.vh")


def render() -> str:
    assert len(RC) == 24, f"expected 24 round constants, got {len(RC)}"
    assert len(ROTC) == 5 and all(len(r) == 5 for r in ROTC), "ROTC must be 5x5"

    L = []
    L.append("// -----------------------------------------------------------------------------")
    L.append("// keccak_rc.vh -- Keccak-f[1600] constants for rtl/crypto/sha3/keccak_f1600.v")
    L.append("//")
    L.append("// GENERATED FILE -- DO NOT EDIT BY HAND.")
    L.append("//   source:    model/sha3.py  (RC, ROTC)")
    L.append("//   generator: scripts/gen_keccak_rc.py")
    L.append("//   regenerate: python scripts/gen_keccak_rc.py")
    L.append("//   verify:     python scripts/gen_keccak_rc.py --check")
    L.append("//")
    L.append("// The model is the single source of truth for these values and is frozen and")
    L.append("// KAT-verified. Editing this header by hand reintroduces exactly the")
    L.append("// transcription bug the generator exists to prevent.")
    L.append("// -----------------------------------------------------------------------------")
    L.append("")
    L.append("`ifndef KECCAK_RC_VH")
    L.append("`define KECCAK_RC_VH")
    L.append("")
    L.append("// A shared constants header defines more than any single consumer uses:")
    L.append("// keccak_f1600.v may index KECCAK_RC_FLAT by a round counter and never")
    L.append("// reference the individual KECCAK_RCnn, while a differently-structured")
    L.append("// implementation does the reverse. Under -Wall that is 39 UNUSEDPARAM")
    L.append("// warnings and a red lint job, for a header whose whole purpose is to")
    L.append("// offer every form the RTL might want. Scoped off for this file only.")
    L.append("/* verilator lint_off UNUSEDPARAM */")
    L.append("")
    L.append("// iota round constants, FIPS 202 sec 3.2.5 -- one 64-bit lane per round.")
    L.append("// Indexed by round number 0..23.")
    L.append("localparam integer KECCAK_ROUNDS = 24;")
    L.append("")
    for i, v in enumerate(RC):
        L.append(f"localparam [63:0] KECCAK_RC{i:02d} = 64'h{v:016X};")
    L.append("")
    L.append("// Packed form, for indexing by a round counter:")
    L.append("//   wire [63:0] rc = KECCAK_RC_FLAT[64*rnd +: 64];")
    flat = "".join(f"{v:016X}" for v in reversed(RC))
    L.append(f"localparam [{24*64-1}:0] KECCAK_RC_FLAT = {24*64}'h{flat};")
    L.append("")
    L.append("// rho rotation offsets, FIPS 202 sec 3.2.2, indexed [x][y].")
    L.append("// Lane index in the state array is x + 5*y.")
    for x in range(5):
        for y in range(5):
            L.append(
                f"localparam integer KECCAK_ROT_{x}_{y} = {ROTC[x][y]:2d};"
                f"  // lane {x + 5*y:2d}"
            )
    L.append("")
    L.append("/* verilator lint_on UNUSEDPARAM */")
    L.append("")
    L.append("`endif // KECCAK_RC_VH")
    L.append("")
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="verify the committed header matches the model; do not write")
    args = ap.parse_args()

    want = render()

    if args.check:
        if not os.path.exists(OUT):
            print(f"FAIL  {os.path.relpath(OUT, REPO)} does not exist.")
            print("      run: python scripts/gen_keccak_rc.py")
            return 1
        with open(OUT, encoding="utf-8") as f:
            have = f.read()
        if have != want:
            print(f"FAIL  {os.path.relpath(OUT, REPO)} is out of date with model/sha3.py.")
            print("      run: python scripts/gen_keccak_rc.py")
            return 1
        print(f"OK    {os.path.relpath(OUT, REPO)} matches model/sha3.py "
              f"({len(RC)} round constants, 5x5 rotation offsets).")
        return 0

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(want)
    print(f"wrote {os.path.relpath(OUT, REPO)}  "
          f"({len(RC)} round constants, 5x5 rotation offsets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

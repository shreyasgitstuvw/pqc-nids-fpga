#!/usr/bin/env python3
"""
scripts/gen_zetas.py
Emit rtl/crypto/ntt/ntt_zetas.vh from the frozen Python twin (model/mlkem/ntt.py).

Why this exists
---------------
model/mlkem/ntt.py defines the 128 twiddle factors (ZETAS) and the scaling constant
INV_N = pow(128, -1, 3329) = 3303. Hand-copying 128 12-bit constants into Verilog
is error-prone: a single typo causes catastrophic NTT mismatches that diffuse across
all 256 coefficients and are tedious to isolate.

Generating the header gives the constants a single source of truth -- the frozen,
KAT-verified model.

Usage
-----
    python scripts/gen_zetas.py            # write the header
    python scripts/gen_zetas.py --check    # verify it is up to date (CI)
"""

import argparse
import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from model.mlkem.ntt import ZETAS, INV_N, Q, N, ZETA  # noqa: E402
from model.mlkem.pke import GAMMAS  # noqa: E402

OUT = os.path.join(REPO, "rtl", "crypto", "ntt", "ntt_zetas.vh")


def render() -> str:
    assert len(ZETAS) == 128, f"expected 128 twiddle factors, got {len(ZETAS)}"
    assert Q == 3329, f"expected modulus 3329, got {Q}"
    assert INV_N == 3303, f"expected INV_N 3303, got {INV_N}"
    assert (128 * INV_N) % Q == 1, "INV_N * 128 mod Q must equal 1"
    assert len(GAMMAS) == 128, f"expected 128 GAMMAS, got {len(GAMMAS)}"

    L = []
    L.append("// -----------------------------------------------------------------------------")
    L.append("// ntt_zetas.vh -- NTT twiddle factors and constants for ML-KEM-512")
    L.append("//")
    L.append("// GENERATED FILE -- DO NOT EDIT BY HAND.")
    L.append("//   source:     model/mlkem/ntt.py  (ZETAS, INV_N, Q)")
    L.append("//               model/mlkem/pke.py  (GAMMAS)")
    L.append("//   generator:  scripts/gen_zetas.py")
    L.append("//   regenerate: python scripts/gen_zetas.py")
    L.append("//   verify:     python scripts/gen_zetas.py --check")
    L.append("//")
    L.append("// The model is the single source of truth for these values and is frozen and")
    L.append("// KAT-verified. Editing this header by hand reintroduces exactly the")
    L.append("// transcription bug the generator exists to prevent.")
    L.append("// -----------------------------------------------------------------------------")
    L.append("")
    L.append("/* verilator lint_off UNUSEDPARAM */")
    L.append("")
    L.append("// Field modulus and dimension parameters")
    L.append("localparam [11:0] NTT_Q     = 12'd3329;")
    L.append("localparam integer NTT_N     = 256;")
    L.append("localparam [11:0] NTT_INV_N = 12'd3303; // pow(128, -1, 3329)")
    L.append("")
    L.append("// Twiddle factor table ZETAS[k] = 17^bit_rev_7(k) mod 3329 for k = 0..127")
    for i, z in enumerate(ZETAS):
        L.append(f"localparam [11:0] NTT_ZETA_{i:03d} = 12'd{z};")
    L.append("")
    L.append("// Packed form for twiddle ROM / flat indexing:")
    L.append("//   wire [11:0] zeta = NTT_ZETAS_FLAT[12*k +: 12];")
    # Pack high-to-low so index 0 is at bit [11:0]
    flat_hex = ""
    # In Verilog packed constant, slice [12*k +: 12] selects entry k if ordered with k=127 at MSB
    flat_val = 0
    for i, z in enumerate(ZETAS):
        flat_val |= (z << (12 * i))
    L.append(f"localparam [{128*12-1}:0] NTT_ZETAS_FLAT = {128*12}'h{flat_val:0384X};")
    L.append("")
    L.append("// Base-case multiplication twiddles GAMMAS[i] = 17^(2*bit_rev_7(i)+1) mod 3329 for i = 0..127")
    gamma_val = 0
    for i, g in enumerate(GAMMAS):
        L.append(f"localparam [11:0] NTT_GAMMA_{i:03d} = 12'd{g};")
        gamma_val |= (g << (12 * i))
    L.append("")
    L.append(f"localparam [{128*12-1}:0] NTT_GAMMAS_FLAT = {128*12}'h{gamma_val:0384X};")
    L.append("")
    L.append("/* verilator lint_on UNUSEDPARAM */")
    L.append("")
    return "\n".join(L)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="exit non-zero if the committed header is not up to date")
    args = parser.parse_args()

    expected = render()

    if args.check:
        if not os.path.exists(OUT):
            sys.stderr.write(f"FAIL: {OUT} does not exist. Run scripts/gen_zetas.py to create it.\n")
            return 1
        with open(OUT, "r", encoding="utf-8") as f:
            actual = f.read()
        if actual != expected:
            sys.stderr.write(f"FAIL: {OUT} is out of date. Run scripts/gen_zetas.py to regenerate.\n")
            return 1
        print(f"OK: {OUT} is up to date with model/mlkem/ntt.py.")
        return 0

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(expected)
    print(f"Wrote {OUT} ({len(expected.splitlines())} lines).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

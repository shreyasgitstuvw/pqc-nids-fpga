# model/compress_hw.py
#
# Hardware-exact model of Compress_d and Decompress_d for ML-KEM-512 (FIPS 203).
# Bit-exact specification for compress.v and decompress.v.
#
# Parameters (ML-KEM-512, Table 2):
#   q = 3329
#   du = 10 (vector u in R_q^2: 2 * 256 coefficients)
#   dv = 4  (polynomial v in R_q: 256 coefficients)
#   d  = 1  (message bits m in {0, 1}^256: 256 coefficients)
#
# Arithmetic Specifications:
#
# 1. Compress_d(x):
#    FIPS 203 Eq 4.7: Compress_d(x) = round(2^d * x / q) mod 2^d
#    Integer rounding: round(N / q) = floor((N + floor(q/2)) / q) = floor((N + 1664) / 3329)
#    Where N = (x << d).
#    Range: x in [0, 3328]
#      d=1:  N in [0, 6656],    P = N + 1664 in [1664, 8320]
#      d=4:  N in [0, 53248],   P = N + 1664 in [1664, 54912]
#      d=10: N in [0, 3407872], P = N + 1664 in [1664, 3409536]
#
#    Division-free via Reciprocal Multiplication:
#      floor(P / 3329) = (P * M) >> S
#      Theorem: For S = 33, M = ceil(2^33 / 3329) = 2580335:
#        floor(P * 2580335 / 2^33) == floor(P / 3329)
#        holds for ALL integers P in [0, 3409536].
#      Mod 2^d Wrap:
#        q_unwrapped = (P * M) >> S
#        Compress_d(x) = q_unwrapped & ((1 << d) - 1)
#
# 2. Decompress_d(y):
#    FIPS 203 Eq 4.8: Decompress_d(y) = round(q * y / 2^d)
#    Integer rounding: round(T / 2^d) = floor((T + 2^(d-1)) / 2^d)
#    Where T = y * 3329.
#    Since denominator is a power of 2, this is exact bit-shift:
#      Decompress_d(y) = (y * 3329 + (1 << (d - 1))) >> d
#    Shift-Add decomposition of Q = 3329:
#      y * 3329 = (y << 11) + (y << 10) + (y << 8) + y
#    Zero division required in hardware.

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from model.mlkem.pke import compress as model_compress, decompress as model_decompress, Q

# Minimum exact (M, S) pairs per parameter D:
# d=1:  S=20, M=315      (P_max = 8,320;   R=59;   P_max * R = 490,880 < 2^20 = 1,048,576)
# d=4:  S=26, M=20159    (P_max = 54,912;  R=447;  P_max * R = 24,545,664 < 2^26 = 67,108,864)
# d=10: S=33, M=2580335  (P_max = 3409536; R=623;  P_max * R = 2,124,140,928 < 2^33 = 8,589,934,592)
RECIPROCAL_PARAMS = {
    1:  {"S": 20, "M": 315,     "R": 59,  "P_max": (3328 << 1) + 1664},
    4:  {"S": 26, "M": 20159,   "R": 447, "P_max": (3328 << 4) + 1664},
    10: {"S": 33, "M": 2580335, "R": 623, "P_max": (3328 << 10) + 1664},
}


def compress_hw(x: int, d: int) -> int:
    """Hardware-exact division-free Compress_d using minimum (M, S) pairs."""
    assert 0 <= x < Q, f"x={x} out of range [0, {Q-1}]"
    assert d in RECIPROCAL_PARAMS, f"Unsupported d={d}"

    p = RECIPROCAL_PARAMS[d]
    P = (x << d) + 1664
    q_unwrapped = (P * p["M"]) >> p["S"]
    return q_unwrapped & ((1 << d) - 1)


def compress_csd(x: int, d: int) -> int:
    """Hardware-exact Compress_d using Canonical Signed Digit (CSD) shift-add tree."""
    assert 0 <= x < Q, f"x={x} out of range [0, {Q-1}]"
    assert d in (1, 4, 10), f"Unsupported d={d}"

    P = (x << d) + 1664
    if d == 1:
        # M = 315 = 2^8 + 2^6 - 2^2 - 1 (4 terms, 3 add/subs)
        prod = (P << 8) + (P << 6) - (P << 2) - P
        q_unwrapped = prod >> 20
    elif d == 4:
        # M = 20159 = 2^14 + 2^12 - 2^8 - 2^6 - 1 (5 terms, 4 add/subs)
        prod = (P << 14) + (P << 12) - (P << 8) - (P << 6) - P
        q_unwrapped = prod >> 26
    else:  # d == 10
        # M = 2580335 = 2^21 + 2^19 - 2^15 - 2^13 - 2^7 - 2^4 - 1 (7 terms, 6 add/subs)
        prod = (P << 21) + (P << 19) - (P << 15) - (P << 13) - (P << 7) - (P << 4) - P
        q_unwrapped = prod >> 33

    return q_unwrapped & ((1 << d) - 1)


def decompress_hw(y: int, d: int) -> int:
    """Hardware-exact division-free Decompress_d for d in {1, 4, 10} and y in [0, 2^d - 1]."""
    assert 0 <= y < (1 << d), f"y={y} out of range [0, {(1 << d) - 1}]"
    assert d in (1, 4, 10), f"Unsupported d={d}"

    # Shift-add decomposition of y * 3329: 3329 = 2^11 + 2^10 + 2^8 + 1
    y_mult_q = (y << 11) + (y << 10) + (y << 8) + y

    # Add rounding bias 2^(d-1) and right shift by d
    return (y_mult_q + (1 << (d - 1))) >> d


def self_test():
    """Exhaustively verify compress_hw, compress_csd, and decompress_hw against frozen model."""
    print("Running exhaustive self-test for model/compress_hw.py...")

    # 1. Verify analytical error bound for each (M, S) pair: P_max * R < 2^S
    for d, p in RECIPROCAL_PARAMS.items():
        err_bound = p["P_max"] * p["R"]
        assert err_bound < (1 << p["S"]), f"Error bound violated for d={d}"
        print(f"  [PROVE] d={d}: P_max*R={err_bound} < 2^{p['S']}={1 << p['S']} (ratio={err_bound / (1 << p['S']):.4f} < 1.0)")

    # 2. Exhaustive check of Compress_d over all x in [0, 3328] for d in {1, 4, 10}
    for d in (1, 4, 10):
        for x in range(Q):
            hw_val = compress_hw(x, d)
            csd_val = compress_csd(x, d)
            gold_val = model_compress(x, d)
            assert hw_val == gold_val, (
                f"Compress mismatch at d={d}, x={x}: hw={hw_val}, gold={gold_val}"
            )
            assert csd_val == gold_val, (
                f"CSD mismatch at d={d}, x={x}: csd={csd_val}, gold={gold_val}"
            )
        print(f"  [PASS] Compress_{d} (M,S & CSD): 3,329/3,329 inputs bit-exact vs model/mlkem/pke.py")

    # 3. Exhaustive check of Decompress_d over all y in [0, 2^d - 1] for d in {1, 4, 10}
    for d in (1, 4, 10):
        max_y = 1 << d
        for y in range(max_y):
            hw_val = decompress_hw(y, d)
            gold_val = model_decompress(y, d)
            assert hw_val == gold_val, (
                f"Decompress mismatch at d={d}, y={y}: hw={hw_val}, gold={gold_val}"
            )
        print(f"  [PASS] Decompress_{d}: {max_y}/{max_y} inputs bit-exact vs model/mlkem/pke.py")

    # 4. Tie-breaking check (round half-up at y = 2^(d-1))
    for d in (1, 4, 10):
        y_tie = 1 << (d - 1)
        res = decompress_hw(y_tie, d)
        assert res == 1665, f"Tie-breaking failure at d={d}: expected 1665, got {res}"
    print("  [PASS] Tie-breaking: exact round-up to 1665 verified for all d")

    # 5. Mod 2^d wrap-around boundary cases:
    # d=1:  x=2496 -> 1, x=2497 -> 0 (wrap begins), x=3328 -> 0
    assert compress_hw(2496, 1) == 1 and compress_csd(2496, 1) == 1
    assert compress_hw(2497, 1) == 0 and compress_csd(2497, 1) == 0
    assert compress_hw(3328, 1) == 0 and compress_csd(3328, 1) == 0

    # d=4:  x=3224 -> 15, x=3225 -> 0 (wrap begins), x=3328 -> 0
    assert compress_hw(3224, 4) == 15 and compress_csd(3224, 4) == 15
    assert compress_hw(3225, 4) == 0 and compress_csd(3225, 4) == 0
    assert compress_hw(3328, 4) == 0 and compress_csd(3328, 4) == 0

    # d=10: x=3327 -> 1023, x=3328 -> 0 (wrap at boundary)
    assert compress_hw(3327, 10) == 1023 and compress_csd(3327, 10) == 1023
    assert compress_hw(3328, 10) == 0 and compress_csd(3328, 10) == 0
    print("  [PASS] Modulo wrap-around boundaries: exact transitions verified for all d")

    print("\nALL COMPRESS / DECOMPRESS PROOFS AND TESTS PASSED!")


if __name__ == "__main__":
    self_test()

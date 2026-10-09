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

# Reciprocal constants for Compress_d
S_RECIPROCAL = 33
M_RECIPROCAL = 2580335  # ceil(2^33 / 3329)


def compress_hw(x: int, d: int) -> int:
    """Hardware-exact division-free Compress_d for d in {1, 4, 10} and x in [0, 3328]."""
    assert 0 <= x < Q, f"x={x} out of range [0, {Q-1}]"
    assert d in (1, 4, 10), f"Unsupported d={d}"

    # Step 1: Scale by 2^d and add half-modulus rounding offset (1664)
    P = (x << d) + 1664

    # Step 2: Division-free reciprocal multiply and right shift by 33
    q_unwrapped = (P * M_RECIPROCAL) >> S_RECIPROCAL

    # Step 3: Mod 2^d bit-mask (wrap around)
    return q_unwrapped & ((1 << d) - 1)


def decompress_hw(y: int, d: int) -> int:
    """Hardware-exact division-free Decompress_d for d in {1, 4, 10} and y in [0, 2^d - 1]."""
    assert 0 <= y < (1 << d), f"y={y} out of range [0, {(1 << d) - 1}]"
    assert d in (1, 4, 10), f"Unsupported d={d}"

    # Shift-add decomposition of y * 3329
    # 3329 = 2^11 + 2^10 + 2^8 + 1
    y_mult_q = (y << 11) + (y << 10) + (y << 8) + y

    # Add rounding bias 2^(d-1) and right shift by d
    return (y_mult_q + (1 << (d - 1))) >> d


def self_test():
    """Exhaustively verify compress_hw and decompress_hw against frozen model."""
    print("Running exhaustive self-test for model/compress_hw.py...")

    # 1. Exhaustive check of Compress_d over all x in [0, 3328] for d in {1, 4, 10}
    for d in (1, 4, 10):
        for x in range(Q):
            hw_val = compress_hw(x, d)
            gold_val = model_compress(x, d)
            assert hw_val == gold_val, (
                f"Compress mismatch at d={d}, x={x}: hw={hw_val}, gold={gold_val}"
            )
        print(f"  [PASS] Compress_{d}: 3,329/3,329 inputs bit-exact vs model/mlkem/pke.py")

    # 2. Exhaustive check of Decompress_d over all y in [0, 2^d - 1] for d in {1, 4, 10}
    for d in (1, 4, 10):
        max_y = 1 << d
        for y in range(max_y):
            hw_val = decompress_hw(y, d)
            gold_val = model_decompress(y, d)
            assert hw_val == gold_val, (
                f"Decompress mismatch at d={d}, y={y}: hw={hw_val}, gold={gold_val}"
            )
        print(f"  [PASS] Decompress_{d}: {max_y}/{max_y} inputs bit-exact vs model/mlkem/pke.py")

    # 3. Continuous integer range check of reciprocal division [0, 3409536]
    max_P = (3328 << 10) + 1664
    for P in range(max_P + 1):
        quot_hw = (P * M_RECIPROCAL) >> S_RECIPROCAL
        quot_true = P // Q
        assert quot_hw == quot_true, f"Quotient mismatch at P={P}: hw={quot_hw}, true={quot_true}"
    print(f"  [PASS] Reciprocal division: all {max_P + 1} continuous integers in [0, {max_P}] exact")

    # 4. Tie-breaking check (round half-up at y = 2^(d-1))
    for d in (1, 4, 10):
        y_tie = 1 << (d - 1)
        res = decompress_hw(y_tie, d)
        assert res == 1665, f"Tie-breaking failure at d={d}: expected 1665, got {res}"
    print("  [PASS] Tie-breaking: exact round-up to 1665 verified for all d")

    # 5. Mod 2^d wrap-around check
    # For x = 3328, (x << d) + 1664 // 3329 == 2^d before the mod
    for d in (1, 4, 10):
        P_wrap = (3328 << d) + 1664
        q_unwrapped = (P_wrap * M_RECIPROCAL) >> S_RECIPROCAL
        assert q_unwrapped == (1 << d), f"Wrap condition failed at d={d}: un-wrapped={q_unwrapped}"
        assert compress_hw(3328, d) == 0, f"Mod wrap failed at d={d}: result={compress_hw(3328, d)}"
    print("  [PASS] Modulo wrap-around: un-wrapped 2^d -> 0 verified for all d")

    print("\nALL COMPRESS / DECOMPRESS PROOFS AND TESTS PASSED!")


if __name__ == "__main__":
    self_test()

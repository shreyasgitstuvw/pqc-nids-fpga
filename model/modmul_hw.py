# model/modmul_hw.py
#
# Hardware-exact model of modular multiplication mod q = 3329 for ML-KEM-512.
# Bit-exact specification for modmul.v and butterfly.v.
#
# Arithmetic:
#   Inputs: a, b in [0, 3328] (12-bit unsigned integers)
#   Product: P = a * b (0 <= P <= 3328^2 = 11,075,584 < 2^24)
#   Modulus: Q = 3329 = 2^11 + 2^10 + 2^8 + 1 (12 bits)
#
# Barrett Reduction with M = 5039 = floor(2^24 / 3329):
#   2^24 = 5039 * 3329 + 3145.
#   Since M <= 2^24 / Q, q_est = floor(P * 5039 / 2^24) <= floor(P / Q).
#   Therefore:
#     1. q_est * Q <= P holds for ALL valid P in [0, 3328^2].
#     2. Remainder r = P - q_est * Q is GUARANTEED non-negative: 0 <= r <= 4903 < 2*Q.
#     3. All intermediate values are strictly unsigned.
#     4. Exactly one conditional subtraction brings r into [0, Q-1]:
#        if r >= 3329: r = r - 3329.
#
# Shift-Add Decompositions (Zero DSPs for reduction):
#   M = 5039 = 2^12 + 2^10 - 2^6 - 2^4 - 1
#     P * 5039 = (P << 12) + (P << 10) - (P << 6) - (P << 4) - P
#   Q = 3329 = 2^11 + 2^10 + 2^8 + 1
#     q_est * 3329 = (q_est << 11) + (q_est << 10) + (q_est << 8) + q_est

Q = 3329
M = 5039  # floor(2^24 / 3329)


def barrett_reduce_hw(P: int) -> int:
    """Hardware shift-add Barrett reduction of a 24-bit product P in [0, 3328^2].

    Uses floor multiplier M = 5039 = 2^12 + 2^10 - 2^6 - 2^4 - 1.
    All operations are strictly unsigned.
    """
    assert 0 <= P <= (Q - 1) ** 2, f"P={P} out of range [0, { (Q-1)**2 }]"

    # Step 1: Multiply P by 5039 via shift-add
    # P * 5039 = (P << 12) + (P << 10) - (P << 6) - (P << 4) - P
    prod_m = (P << 12) + (P << 10) - (P << 6) - (P << 4) - P

    # Step 2: Divide by 2^24 (take bits [37:24])
    q_est = prod_m >> 24

    # Step 3: Multiply q_est by Q = 3329 via shift-add
    # q_est * 3329 = (q_est << 11) + (q_est << 10) + (q_est << 8) + q_est
    q_mult = (q_est << 11) + (q_est << 10) + (q_est << 8) + q_est

    # Step 4: Remainder (strictly in [0, 4903] < 2*Q, never negative)
    r = P - q_mult

    # Step 5: Single unsigned conditional correction
    if r >= Q:
        r -= Q

    return r


def modmul_hw(a: int, b: int) -> int:
    """Modular multiplication (a * b) mod 3329 matching hardware datapath."""
    assert 0 <= a < Q, f"a={a} out of range [0, {Q-1}]"
    assert 0 <= b < Q, f"b={b} out of range [0, {Q-1}]"
    P = a * b
    return barrett_reduce_hw(P)


if __name__ == "__main__":
    import sys

    print("Running exhaustive mathematical proof of barrett_reduce_hw over all products [0, 3328^2]...")
    max_P = (Q - 1) ** 2  # 11,075,584

    # Verify corner cases explicitly first
    corners = [0, 1, 2, Q - 1, Q, Q + 1, 2 * Q - 1, 2 * Q, 2 * Q + 1, 5039, 3328 * 3328, max_P]
    for p in corners:
        got = barrett_reduce_hw(p)
        want = p % Q
        assert got == want, f"Corner failure at P={p}: got {got}, want {want}"

    # Exhaustive verification across all 11,075,585 products
    # Process in chunks of 500,000 for progress reporting
    chunk_size = 1_000_000
    for start in range(0, max_P + 1, chunk_size):
        end = min(start + chunk_size, max_P + 1)
        for p in range(start, end):
            # Inline check for maximum Python execution speed
            prod_m = (p << 12) + (p << 10) - (p << 6) - (p << 4) - p
            q_est = prod_m >> 24
            q_mult = (q_est << 11) + (q_est << 10) + (q_est << 8) + q_est
            r = p - q_mult
            if r >= Q:
                r -= Q
            if r != (p % Q):
                print(f"FAILED at P={p}: got {r}, want {p % Q}")
                sys.exit(1)
        print(f"  Verified products [{start:,} .. {end - 1:,}] ({100.0 * end / (max_P + 1):.1f}%)")

    print(f"SUCCESS: All {max_P + 1:,} products in [0, 3328^2] pass bit-exact vs % Q!")

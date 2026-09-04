# model/mlkem/pke.py
#
# K-PKE: the public-key encryption scheme underneath ML-KEM's KEM wrapper.
# Implements FIPS 203 Algorithms 5-8, 11-15 for the ML-KEM-512 parameter set
# (k=2, eta1=3, eta2=2, du=10, dv=4 -- Table 2).
#
# Layout:
#   1. Compress/Decompress          (Eq 4.7, 4.8)
#   2. PRF                          (Eq 4.3)
#   3. ByteEncode/ByteDecode        (Algorithm 5, 6)
#   4. SampleNTT                    (Algorithm 7)
#   5. SamplePolyCBD (general eta)  (Algorithm 8)
#   6. NTT-domain multiplication    (Algorithm 11, 12)
#   7. Vector/matrix helpers over R_q and T_q
#   8. K-PKE.KeyGen / Encrypt / Decrypt   (Algorithm 13, 14, 15)

import os
import sys

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from model.sha3 import shake128, shake256, sha3_512
from model.mlkem.ntt import ntt, intt, bit_rev_7, add_mod, sub_mod, mul_mod, Q, ZETA

# ML-KEM-512 parameter set (FIPS 203 Table 2)
K = 2
ETA1 = 3
ETA2 = 2
DU = 10
DV = 4


# ---------------------------------------------------------------------------
# 1. Compress / Decompress  (Eq 4.7, 4.8) -- integer-only rounding
# ---------------------------------------------------------------------------

def compress(x: int, d: int) -> int:
    """Compress_d: Z_q -> Z_{2^d}. Scale-shift-mask, no floats."""
    return ((x << d) + (Q // 2)) // Q & ((1 << d) - 1)


def decompress(y: int, d: int) -> int:
    """Decompress_d: Z_{2^d} -> Z_q."""
    return ((y * Q) + (1 << (d - 1))) >> d


# ---------------------------------------------------------------------------
# 2. PRF  (Eq 4.3) -- SHAKE256(seed || counter_byte, 64*eta bytes)
# ---------------------------------------------------------------------------

def prf(eta: int, seed: bytes, b: int) -> bytes:
    """PRF_eta(seed, b) := SHAKE256(seed || b, 64*eta bytes)."""
    return shake256(seed + bytes([b]), 64 * eta)


# ---------------------------------------------------------------------------
# 3. ByteEncode / ByteDecode  (Algorithm 5, 6)
# ---------------------------------------------------------------------------

def byte_encode(coeffs: list, d: int) -> bytes:
    """Pack 256 integers (each fitting in d bits) into 32*d bytes, LSB-first
    throughout (matches BitsToBytes/BytesToBits, sec 4.2.1)."""
    assert len(coeffs) == 256
    bits = []
    for a in coeffs:
        for _ in range(d):
            bits.append(a & 1)
            a >>= 1
    out = bytearray(len(bits) // 8)
    for i, bit in enumerate(bits):
        out[i // 8] |= bit << (i % 8)
    return bytes(out)


def byte_decode(data: bytes, d: int) -> list:
    """Inverse of byte_encode. Reduces mod q when d == 12 (12 bits can
    represent values up to 4095, but q=3329 only needs 12 bits, not fills
    them -- see sec 4.2.1)."""
    assert len(data) == 32 * d
    bits = []
    for byte in data:
        for j in range(8):
            bits.append((byte >> j) & 1)
    m = Q if d == 12 else (1 << d)
    coeffs = []
    for i in range(256):
        value = 0
        for j in range(d):
            value += bits[i * d + j] << j
        coeffs.append(value % m)
    return coeffs


# ---------------------------------------------------------------------------
# 4. SampleNTT  (Algorithm 7) -- rejection sampling via SHAKE128 XOF
# ---------------------------------------------------------------------------

def sample_ntt(seed_bytes: bytes) -> list:
    """seed_bytes: 34 bytes (32-byte seed + 2 index bytes). Returns 256
    uniformly distributed coefficients in [0, Q)."""
    a_hat = []
    squeezes_done = 0
    while len(a_hat) < 256:
        full = shake128(seed_bytes, (squeezes_done + 1) * 3)
        chunk = full[squeezes_done * 3: (squeezes_done + 1) * 3]
        squeezes_done += 1

        c0, c1, c2 = chunk[0], chunk[1], chunk[2]
        d1 = c0 + 256 * (c1 % 16)
        d2 = (c1 // 16) + 16 * c2

        if d1 < Q:
            a_hat.append(d1)
        if d2 < Q and len(a_hat) < 256:
            a_hat.append(d2)
    return a_hat


# ---------------------------------------------------------------------------
# 5. SamplePolyCBD, general eta  (Algorithm 8)
#
# Your cbd.py's nibble-splitting only works for eta=2 (4 bits/coefficient
# divides evenly into a byte). ML-KEM-512 needs eta=3 for s and y (6
# bits/coefficient), which doesn't -- so this is the spec's general bit
# formula instead, usable for any eta.
# ---------------------------------------------------------------------------

def _bytes_to_bits(data: bytes) -> list:
    bits = []
    for byte in data:
        for j in range(8):
            bits.append((byte >> j) & 1)
    return bits


def sample_poly_cbd(byte_stream: bytes, eta: int) -> list:
    """byte_stream must be exactly 64*eta bytes (PRF's output length)."""
    bits = _bytes_to_bits(byte_stream)
    f = []
    for i in range(256):
        x = sum(bits[2 * i * eta + j] for j in range(eta))
        y = sum(bits[2 * i * eta + eta + j] for j in range(eta))
        f.append((x - y) % Q)
    return f


# ---------------------------------------------------------------------------
# 6. NTT-domain multiplication  (Algorithm 11, 12)
#
# T_q is a direct sum of 128 quadratic extensions, not 256 independent
# scalars -- multiplying two NTT-domain polynomials means 128 independent
# degree-1 multiplications mod (X^2 - gamma_i), not coefficient-wise
# multiplication. See sec 4.3, Eq 4.10.
# ---------------------------------------------------------------------------

GAMMAS = [pow(ZETA, 2 * bit_rev_7(i) + 1, Q) for i in range(128)]


def base_case_multiply(a0, a1, b0, b1, gamma):
    """Product of (a0 + a1*X) and (b0 + b1*X) mod (X^2 - gamma)."""
    c0 = (a0 * b0 + a1 * b1 * gamma) % Q
    c1 = (a0 * b1 + a1 * b0) % Q
    return c0, c1


def multiply_ntts(f_hat: list, g_hat: list) -> list:
    """Product of two NTT-domain polynomials (Algorithm 11)."""
    h_hat = [0] * 256
    for i in range(128):
        c0, c1 = base_case_multiply(
            f_hat[2 * i], f_hat[2 * i + 1],
            g_hat[2 * i], g_hat[2 * i + 1],
            GAMMAS[i],
        )
        h_hat[2 * i] = c0
        h_hat[2 * i + 1] = c1
    return h_hat


# ---------------------------------------------------------------------------
# 7. Vector / matrix helpers (entries are 256-coefficient polynomials;
#    "_hat" suffix means NTT-domain, matching the spec's notation)
# ---------------------------------------------------------------------------

def poly_add(a: list, b: list) -> list:
    return [add_mod(x, y) for x, y in zip(a, b)]


def poly_sub(a: list, b: list) -> list:
    return [sub_mod(x, y) for x, y in zip(a, b)]


def vec_add(u: list, v: list) -> list:
    return [poly_add(a, b) for a, b in zip(u, v)]


def transpose(mat: list) -> list:
    k = len(mat)
    return [[mat[j][i] for j in range(k)] for i in range(k)]


def mat_vec_mult_ntt(mat_hat: list, vec_hat: list) -> list:
    """mat_hat: k x k matrix of NTT-domain polys. vec_hat: length-k vector
    of NTT-domain polys. Returns length-k vector: row i = sum_j mat[i][j] *_Tq vec[j]."""
    k = len(vec_hat)
    result = []
    for i in range(k):
        acc = [0] * 256
        for j in range(k):
            acc = poly_add(acc, multiply_ntts(mat_hat[i][j], vec_hat[j]))
        result.append(acc)
    return result


def dot_ntt(vec1_hat: list, vec2_hat: list) -> list:
    """Sum_i vec1[i] *_Tq vec2[i] -- a single polynomial (transpose-vector
    dot product, e.g. t_hat^T o y_hat)."""
    acc = [0] * 256
    for a, b in zip(vec1_hat, vec2_hat):
        acc = poly_add(acc, multiply_ntts(a, b))
    return acc


def encode_vec(polys: list, d: int) -> bytes:
    return b"".join(byte_encode(p, d) for p in polys)


def decode_vec(data: bytes, d: int, k: int) -> list:
    size = 32 * d
    return [byte_decode(data[i * size:(i + 1) * size], d) for i in range(k)]


def g(data: bytes):
    """G(c) := SHA3-512(c), split into two 32-byte halves (Eq 4.5)."""
    out = sha3_512(data)
    return out[:32], out[32:]


# ---------------------------------------------------------------------------
# 8. K-PKE.KeyGen / Encrypt / Decrypt  (Algorithm 13, 14, 15)
# ---------------------------------------------------------------------------

def keygen(d: bytes):
    """K-PKE.KeyGen(d). d: 32 random bytes. Returns (ek_pke, dk_pke)."""
    assert len(d) == 32
    rho, sigma = g(d + bytes([K]))  # domain-separate on module dimension K

    a_hat = [[sample_ntt(rho + bytes([j]) + bytes([i])) for j in range(K)]
             for i in range(K)]

    n = 0
    s = []
    for _ in range(K):
        s.append(sample_poly_cbd(prf(ETA1, sigma, n), ETA1))
        n += 1
    e = []
    for _ in range(K):
        e.append(sample_poly_cbd(prf(ETA1, sigma, n), ETA1))
        n += 1

    s_hat = [ntt(p) for p in s]
    e_hat = [ntt(p) for p in e]
    t_hat = vec_add(mat_vec_mult_ntt(a_hat, s_hat), e_hat)

    ek_pke = encode_vec(t_hat, 12) + rho
    dk_pke = encode_vec(s_hat, 12)
    return ek_pke, dk_pke


def encrypt(ek_pke: bytes, m: bytes, r: bytes) -> bytes:
    """K-PKE.Encrypt(ek_pke, m, r). m, r: 32 bytes each. Returns ciphertext c."""
    assert len(m) == 32 and len(r) == 32

    t_hat = decode_vec(ek_pke[:384 * K], 12, K)
    rho = ek_pke[384 * K: 384 * K + 32]
    a_hat = [[sample_ntt(rho + bytes([j]) + bytes([i])) for j in range(K)]
             for i in range(K)]

    n = 0
    y = []
    for _ in range(K):
        y.append(sample_poly_cbd(prf(ETA1, r, n), ETA1))
        n += 1
    e1 = []
    for _ in range(K):
        e1.append(sample_poly_cbd(prf(ETA2, r, n), ETA2))
        n += 1
    e2 = sample_poly_cbd(prf(ETA2, r, n), ETA2)
    n += 1

    y_hat = [ntt(p) for p in y]
    at_hat = transpose(a_hat)
    u = [poly_add(intt(row), noise)
         for row, noise in zip(mat_vec_mult_ntt(at_hat, y_hat), e1)]

    mu_bits = byte_decode(m, 1)
    mu = [decompress(b, 1) for b in mu_bits]

    v = poly_add(poly_add(intt(dot_ntt(t_hat, y_hat)), e2), mu)

    c1 = b"".join(byte_encode([compress(x, DU) for x in poly], DU) for poly in u)
    c2 = byte_encode([compress(x, DV) for x in v], DV)
    return c1 + c2


def decrypt(dk_pke: bytes, c: bytes) -> bytes:
    """K-PKE.Decrypt(dk_pke, c). Returns recovered 32-byte message m."""
    c1 = c[:32 * DU * K]
    c2 = c[32 * DU * K: 32 * (DU * K + DV)]

    size = 32 * DU
    u_prime = [
        [decompress(y, DU) for y in byte_decode(c1[i * size:(i + 1) * size], DU)]
        for i in range(K)
    ]
    v_prime = [decompress(y, DV) for y in byte_decode(c2, DV)]

    s_hat = decode_vec(dk_pke, 12, K)
    u_hat = [ntt(p) for p in u_prime]

    w = poly_sub(v_prime, intt(dot_ntt(s_hat, u_hat)))
    return byte_encode([compress(x, 1) for x in w], 1)


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import random

    # --- compress/decompress ---
    for d in (4, 10):
        for x in range(Q):
            c = compress(x, d)
            assert 0 <= c < (1 << d)
    for d in (4, 10):
        for y in range(1 << d):
            assert compress(decompress(y, d), d) == y
    print("compress/decompress: OK")

    # --- prf ---
    seed = os.urandom(32)
    assert prf(2, seed, 0) == prf(2, seed, 0)
    assert prf(2, seed, 0) != prf(2, seed, 1)
    assert len(prf(3, seed, 0)) == 192
    print("prf: OK")

    # --- byte_encode/byte_decode ---
    for d in (1, 4, 10, 11, 12):
        for _ in range(10):
            bound = Q if d == 12 else (1 << d)
            coeffs = [random.randrange(bound) for _ in range(256)]
            assert byte_decode(byte_encode(coeffs, d), d) == coeffs
    print("byte_encode/byte_decode: OK")

    # --- sample_ntt ---
    seed34 = os.urandom(32) + bytes([0, 1])
    poly = sample_ntt(seed34)
    assert len(poly) == 256 and all(0 <= c < Q for c in poly)
    assert sample_ntt(seed34) == poly
    print("sample_ntt: OK")

    # --- sample_poly_cbd, general eta ---
    for eta in (2, 3):
        stream = os.urandom(64 * eta)
        f = sample_poly_cbd(stream, eta)
        assert len(f) == 256
        valid = set(range(eta + 1)) | {Q - k for k in range(1, eta + 1)}
        assert all(c in valid for c in f)
    print("sample_poly_cbd: OK")

    # --- multiply_ntts vs brute-force polynomial multiplication mod (X^256+1) ---
    def poly_mul_naive(a, b):
        prod = [0] * (2 * 256 - 1)
        for i, ai in enumerate(a):
            if ai == 0:
                continue
            for j, bj in enumerate(b):
                prod[i + j] = (prod[i + j] + ai * bj) % Q
        result = [0] * 256
        for i, coeff in enumerate(prod):
            if i < 256:
                result[i] = (result[i] + coeff) % Q
            else:
                result[i - 256] = (result[i - 256] - coeff) % Q  # X^256 = -1
        return result

    for _ in range(5):
        a = [random.randrange(Q) for _ in range(256)]
        b = [random.randrange(Q) for _ in range(256)]
        via_ntt = intt(multiply_ntts(ntt(a), ntt(b)))
        via_naive = poly_mul_naive(a, b)
        assert via_ntt == via_naive, "NTT-domain multiply disagrees with naive polynomial multiply"
    print("multiply_ntts: OK (matches naive polynomial multiplication mod X^256+1)")

    # --- full K-PKE round trip: keygen -> encrypt -> decrypt ---
    for trial in range(20):
        d = os.urandom(32)
        ek, dk = keygen(d)
        assert len(ek) == 384 * K + 32
        assert len(dk) == 384 * K

        m = os.urandom(32)
        r = os.urandom(32)
        c = encrypt(ek, m, r)
        assert len(c) == 32 * (DU * K + DV)

        recovered = decrypt(dk, c)
        assert recovered == m, f"trial {trial}: decrypt did not recover original message"

    print("K-PKE round trip (keygen/encrypt/decrypt), 20 trials: OK")
    print()
    print("ALL pke.py self-checks passed")

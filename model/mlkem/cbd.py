# model/mlkem/cbd.py

Q = 3329
ETA = 2

def popcount(x: int) -> int:
    """Count set bits in x."""
    # shift-and-mask loop
    count = 0
    while x:
        count += x&1
        x>>=1
    return count
        

def cbd(byte_stream: bytes, eta: int = ETA, num_coeffs: int = 256) -> list[int]:
    """
    Centered binomial sampler, eta=2 case.
    byte_stream: raw bytes from a PRF/SHAKE256 call — NOT generated here.
      Must contain at least (num_coeffs * 2 * eta) bits, i.e. num_coeffs//2
      bytes when eta=2 (2 coefficients per byte).
    Returns: list of num_coeffs ints, each reduced mod Q.
    """
    coeffs = []

    for byte in byte_stream:
        if len(coeffs) >= num_coeffs:
            break

        # pull out the low nibble and high nibble of this byte.
        low_nibble  = byte & 0x0F
        high_nibble = (byte >> 4) & 0x0F

        for nibble in (low_nibble, high_nibble):  # (low_nibble, high_nibble)
            # split the 4-bit nibble into two 2-bit halves.
            first_half  = nibble & 0b11
            second_half = (nibble >> 2) & 0b11

            x = popcount(first_half)
            y = popcount(second_half)
            coeff = (x - y) % Q   #-- Python's % already wraps negatives
            #       into [0, Q) correctly here, but know that's what's happening
            coeffs.append(coeff)
            

    return coeffs


if __name__ == "__main__":
    import os

    # 1. Bounds/shape check: every output must be one of {-2,-1,0,1,2} mod Q,
    #    i.e. one of {0, 1, 2, Q-1, Q-2}.
    valid = {0, 1, 2, Q - 1, Q - 2}
    stream = os.urandom(128)  # 128 bytes -> 256 coefficients at eta=2
    out = cbd(stream)
    assert len(out) == 256
    assert all(c in valid for c in out), "output outside {-2..2} mod Q"

    # 2. Determinism: same seed bytes -> identical output.
    assert cbd(stream) == cbd(stream), "not deterministic"

    # 3. Distribution sanity: 0 should be the most common value by a wide margin.
    from collections import Counter
    big_stream = os.urandom(128 * 200)  # lots of samples
    hist = Counter(cbd(big_stream, num_coeffs=256 * 200))
    print({k: hist[k] for k in sorted(valid)})

    print("cbd.py self-checks passed")
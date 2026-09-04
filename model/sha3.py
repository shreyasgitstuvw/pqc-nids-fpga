"""
model/sha3.py
Keccak-f[1600] permutation + sponge construction, giving SHA3-256, SHA3-512,
SHAKE128, SHAKE256 from one core.

This is the Python "golden model" — the thing you'll port to Verilog in
Phase 7 (rtl/crypto/sha3/). Every design choice below is written the way you'd
have to write it in RTL: fixed-width lanes, explicit bit ops, no shortcuts
that only make sense in a language with bignums.

State layout
------------
Keccak's state is 1600 bits = 25 lanes of 64 bits, addressed as A[x][y] with
x = column (0..4), y = row (0..4). We store it as a flat Python list of 25
ints, index = x + 5*y, each masked to 64 bits after every operation (in RTL
this masking is free — it's just wire width — but in Python we have to do it
by hand or the ints silently grow).

Byte <-> lane mapping (this is the #1 place implementations get silently
wrong): bytes are packed into lanes little-endian. Byte 0 of the input is
the LOW-order byte of lane A[0][0], byte 8 starts lane A[1][0], etc. Get this
backwards and every single-block digest comes out wrong in a way that looks
like a permutation bug but isn't.
"""

MASK64 = (1 << 64) - 1


def rotl64(x: int, n: int) -> int:
    n %= 64
    if n == 0:
        return x & MASK64
    return ((x << n) | (x >> (64 - n))) & MASK64


# Round constants for iota, one per round (24 rounds for the full 1600-bit
# permutation). These come from a fixed LFSR defined in FIPS 202 sec 3.2.5 —
# hardcoded here since they're a fixed table, exactly like you'll hardcode
# them in keccak_f1600.v later.
RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

# Rotation offsets for rho, indexed [x][y] per FIPS 202 sec 3.2.2.
ROTC = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def keccak_f1600(state):
    """In-place permutation on a 25-element list of 64-bit lanes (index = x+5*y)."""
    for rnd in range(24):
        # --- theta: column parity mixed back into every lane ---
        C = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
             for x in range(5)]
        D = [C[(x - 1) % 5] ^ rotl64(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= D[x]

        # --- rho + pi: rotate each lane, then permute lane positions ---
        # pi moves the lane at (x,y) to (y, 2x+3y mod 5); we build the new
        # state directly rather than doing two passes.
        B = [0] * 25
        for x in range(5):
            for y in range(5):
                new_x, new_y = y, (2 * x + 3 * y) % 5
                B[new_x + 5 * new_y] = rotl64(state[x + 5 * y], ROTC[x][y])

        # --- chi: nonlinear mixing along each row ---
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = B[x + 5 * y] ^ (
                    (~B[(x + 1) % 5 + 5 * y] & MASK64) & B[(x + 2) % 5 + 5 * y]
                )

        # --- iota: break the round symmetry with a per-round constant ---
        state[0] ^= RC[rnd]

    return state


def _bytes_to_state(block: bytes):
    """block must be exactly 200 bytes (25 lanes * 8 bytes), little-endian per lane."""
    assert len(block) == 200
    return [int.from_bytes(block[8 * i:8 * i + 8], "little") for i in range(25)]


def _state_to_bytes(state) -> bytes:
    return b"".join(lane.to_bytes(8, "little") for lane in state)


def keccak_sponge(data: bytes, rate_bytes: int, domain_suffix: int, output_len: int) -> bytes:
    """
    Generic sponge: absorb `data` at `rate_bytes` per block (capacity is the
    remaining 200-rate_bytes, implicit), then squeeze `output_len` bytes.

    domain_suffix is the padding start byte:
      0x06 for SHA3-256/512 (fixed-output "01" + pad10*1 domain sep)
      0x1F for SHAKE128/256 ("1111" domain sep + pad10*1)
    Pad10*1 rule: append domain_suffix, zero-pad, then OR 0x80 into the
    final byte of the block. If the message exactly fills to one byte short
    of the block, both land in the same byte (0x06|0x80=0x86, 0x1F|0x80=0x9F).
    """
    state = [0] * 25

    # ---- absorb ----
    padded = bytearray(data)
    padded.append(domain_suffix)
    while len(padded) % rate_bytes != 0:
        padded.append(0x00)
    padded[-1] |= 0x80

    for offset in range(0, len(padded), rate_bytes):
        block = bytes(padded[offset:offset + rate_bytes]) + b"\x00" * (200 - rate_bytes)
        block_state = _bytes_to_state(block)
        for i in range(25):
            state[i] ^= block_state[i]
        keccak_f1600(state)

    # ---- squeeze ----
    out = bytearray()
    while len(out) < output_len:
        out += _state_to_bytes(state)[:rate_bytes]
        if len(out) < output_len:
            keccak_f1600(state)
    return bytes(out[:output_len])


# Rate in bytes = (1600 - 2*capacity_bits) / 8. Capacity is what actually
# sets the security level; rate is just "how much input/output per
# permutation call" — bigger rate = fewer permutation calls = faster, at
# the cost of a smaller capacity/security margin. These four are the
# FIPS 202 fixed instances.
def sha3_256(data: bytes) -> bytes:
    return keccak_sponge(data, rate_bytes=136, domain_suffix=0x06, output_len=32)


def sha3_512(data: bytes) -> bytes:
    return keccak_sponge(data, rate_bytes=72, domain_suffix=0x06, output_len=64)


def shake128(data: bytes, output_len: int) -> bytes:
    return keccak_sponge(data, rate_bytes=168, domain_suffix=0x1F, output_len=output_len)


def shake256(data: bytes, output_len: int) -> bytes:
    return keccak_sponge(data, rate_bytes=136, domain_suffix=0x1F, output_len=output_len)


if __name__ == "__main__":
    # Cross-check against pycryptodome (NOT a dependency of the real code
    # above — Crypto.Hash is imported only inside this __main__ block, per
    # your plan step 9: "a well-established Python library... purely as a
    # cross-check oracle for this one step — never as your actual
    # dependency, since your real implementation must be something you can
    # port to Verilog." This is your Phase 2 gate before SHA3 becomes a
    # buried dependency inside NTT/CBD/PKE, where a bug is much harder to
    # localize.
    from Crypto.Hash import SHA3_256, SHA3_512, SHAKE128, SHAKE256
    import os

    failures = 0

    def check(label, got, want):
        global failures
        ok = got == want
        if not ok:
            failures += 1
        print(f"{'OK  ' if ok else 'FAIL'} {label}: got={got.hex()} want={want.hex()}")

    test_messages = [
        b"",
        b"abc",
        b"The quick brown fox jumps over the lazy dog",
        bytes(range(200)),          # spans multiple SHA3-256/SHAKE256 blocks (rate 136)
        os.urandom(1000),           # spans multiple blocks for every rate, random content
    ]

    for msg in test_messages:
        tag = msg[:16].hex() + (".." if len(msg) > 16 else "")
        check(f"SHA3-256({tag})", sha3_256(msg), SHA3_256.new(msg).digest())
        check(f"SHA3-512({tag})", sha3_512(msg), SHA3_512.new(msg).digest())
        # pycryptodome's SHAKE .read(n) is stateful (each call continues the
        # squeeze from where the last left off), so use a fresh object per length.
        check(f"SHAKE128({tag},32)", shake128(msg, 32), SHAKE128.new(msg).read(32))
        check(f"SHAKE128({tag},200)", shake128(msg, 200), SHAKE128.new(msg).read(200))
        check(f"SHAKE256({tag},32)", shake256(msg, 32), SHAKE256.new(msg).read(32))
        check(f"SHAKE256({tag},200)", shake256(msg, 200), SHAKE256.new(msg).read(200))

    print()
    if failures:
        print(f"{failures} FAILURE(S)")
        raise SystemExit(1)
    else:
        print("All self-checks passed against pycryptodome.")

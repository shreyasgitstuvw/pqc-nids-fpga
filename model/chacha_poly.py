#!/usr/bin/env python3
"""
model/chacha_poly.py

Bit-exact Python reference model and oracle for RFC 8439:
- ChaCha20 stream cipher
- Poly1305 MAC accumulator
- ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD)

Owner: Member D (@control)
Standard library only -- no external dependencies.
Used as the golden oracle for:
- rtl/crypto/chacha_poly/chacha20.v
- rtl/crypto/chacha_poly/poly1305.v
- sim/cocotb/test_chacha20.py
- sim/cocotb/test_poly1305.py
- sim/cocotb/test_chacha_poly.py
"""

import struct
from typing import Tuple, List


# ==============================================================================
# ChaCha20 Primitive (RFC 8439 Section 2.1 - 2.4)
# ==============================================================================

CHACHA20_CONSTANTS = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]  # "expand 32-byte k"


def rotl32(v: int, c: int) -> int:
    """32-bit left circular rotation."""
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def chacha20_quarter_round(a: int, b: int, c: int, d: int) -> Tuple[int, int, int, int]:
    """
    ChaCha20 quarter round on four 32-bit words (RFC 8439 Section 2.1).
    ARX (Add-Rotate-XOR) sequence.
    """
    a = (a + b) & 0xFFFFFFFF
    d = rotl32(d ^ a, 16)

    c = (c + d) & 0xFFFFFFFF
    b = rotl32(b ^ c, 12)

    a = (a + b) & 0xFFFFFFFF
    d = rotl32(d ^ a, 8)

    c = (c + d) & 0xFFFFFFFF
    b = rotl32(b ^ c, 7)

    return a, b, c, d


def chacha20_init_state(key: bytes, counter: int, nonce: bytes) -> List[int]:
    """
    Initializes the 16-word (4x4 matrix) ChaCha20 state (RFC 8439 Section 2.3).
    - Words 0-3:   Constants ("expand 32-byte k")
    - Words 4-11:  Key (256-bit / 8 words, little-endian)
    - Word 12:     Block counter (32-bit uint)
    - Words 13-15: Nonce (96-bit / 3 words, little-endian)
    """
    if len(key) != 32:
        raise ValueError(f"ChaCha20 key must be 32 bytes, got {len(key)}")
    if len(nonce) != 12:
        raise ValueError(f"ChaCha20 nonce must be 12 bytes, got {len(nonce)}")

    key_words = list(struct.unpack("<8I", key))
    nonce_words = list(struct.unpack("<3I", nonce))

    state = CHACHA20_CONSTANTS + key_words + [counter & 0xFFFFFFFF] + nonce_words
    return state


def chacha20_inner_rounds(state: List[int]) -> List[int]:
    """
    Performs 20 rounds (10 column rounds + 10 diagonal rounds) on 16-word state.
    """
    s = list(state)
    for _ in range(10):
        # Column rounds
        s[0], s[4], s[8], s[12] = chacha20_quarter_round(s[0], s[4], s[8], s[12])
        s[1], s[5], s[9], s[13] = chacha20_quarter_round(s[1], s[5], s[9], s[13])
        s[2], s[6], s[10], s[14] = chacha20_quarter_round(s[2], s[6], s[10], s[14])
        s[3], s[7], s[11], s[15] = chacha20_quarter_round(s[3], s[7], s[11], s[15])

        # Diagonal rounds
        s[0], s[5], s[10], s[15] = chacha20_quarter_round(s[0], s[5], s[10], s[15])
        s[1], s[6], s[11], s[12] = chacha20_quarter_round(s[1], s[6], s[11], s[12])
        s[2], s[7], s[8], s[13] = chacha20_quarter_round(s[2], s[7], s[8], s[13])
        s[3], s[4], s[9], s[14] = chacha20_quarter_round(s[3], s[4], s[9], s[14])
    return s


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """
    Generates a single 64-byte keystream block (RFC 8439 Section 2.3).
    """
    s_init = chacha20_init_state(key, counter, nonce)
    s_work = chacha20_inner_rounds(s_init)

    # Word-by-word addition mod 2^32
    out_words = [(s_init[i] + s_work[i]) & 0xFFFFFFFF for i in range(16)]
    return struct.pack("<16I", *out_words)


def chacha20_encrypt(key: bytes, counter: int, nonce: bytes, plaintext: bytes) -> bytes:
    """
    ChaCha20 stream encryption/decryption (RFC 8439 Section 2.4).
    XORs plaintext with generated keystream.
    """
    ciphertext = bytearray()
    num_blocks = (len(plaintext) + 63) // 64

    for i in range(num_blocks):
        block_counter = (counter + i) & 0xFFFFFFFF
        keystream = chacha20_block(key, block_counter, nonce)
        chunk = plaintext[i * 64 : (i + 1) * 64]
        for b, k in zip(chunk, keystream):
            ciphertext.append(b ^ k)

    return bytes(ciphertext)


# Decryption is identical to encryption due to XOR symmetry
chacha20_decrypt = chacha20_encrypt


# ==============================================================================
# Poly1305 One-Time Authenticator (RFC 8439 Section 2.5)
# ==============================================================================

POLY1305_PRIME = (1 << 130) - 5  # 2^130 - 5


def poly1305_clamp(r: int) -> int:
    """
    Clamps the 128-bit 'r' integer per RFC 8439 Section 2.5:
    r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
    """
    return r & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF


def poly1305_mac(msg: bytes, key: bytes) -> bytes:
    """
    Computes 16-byte Poly1305 MAC tag for message using 32-byte one-time key (RFC 8439 Section 2.5).
    Key is split into (r, s):
    - r = clamped first 16 bytes (little-endian uint128)
    - s = second 16 bytes (little-endian uint128)
    """
    if len(key) != 32:
        raise ValueError(f"Poly1305 key must be 32 bytes, got {len(key)}")

    r_raw = int.from_bytes(key[0:16], byteorder="little")
    r = poly1305_clamp(r_raw)
    s = int.from_bytes(key[16:32], byteorder="little")

    acc = 0
    msg_len = len(msg)
    offset = 0

    while offset < msg_len:
        chunk = msg[offset : offset + 16]
        chunk_len = len(chunk)

        # n = chunk as uintLE + 2^(8 * chunk_len) (append a 1-bit / 0x01 byte)
        n = int.from_bytes(chunk, byteorder="little") + (1 << (8 * chunk_len))

        acc = ((acc + n) * r) % POLY1305_PRIME
        offset += 16

    tag_int = (acc + s) & ((1 << 128) - 1)
    return tag_int.to_bytes(16, byteorder="little")


# ==============================================================================
# ChaCha20-Poly1305 AEAD Construction (RFC 8439 Section 2.8)
# ==============================================================================

def poly1305_key_gen(key: bytes, nonce: bytes) -> bytes:
    """
    Derives 32-byte one-time Poly1305 key from ChaCha20 block 0 (RFC 8439 Section 2.6).
    First 32 bytes of ChaCha20(key, counter=0, nonce).
    """
    block0 = chacha20_block(key, 0, nonce)
    return block0[:32]


def _pad16(data: bytes) -> bytes:
    """Zero-pad to 16-byte boundary per RFC 8439 Section 2.8."""
    remainder = len(data) % 16
    return b"\x00" * (16 - remainder) if remainder != 0 else b""


def chacha20_poly1305_encrypt(
    key: bytes, nonce: bytes, aad: bytes, plaintext: bytes
) -> Tuple[bytes, bytes]:
    """
    RFC 8439 Section 2.8 Authenticated Encryption with Associated Data (AEAD).
    Returns (ciphertext, 16-byte authentication tag).
    """
    otk = poly1305_key_gen(key, nonce)
    ciphertext = chacha20_encrypt(key, 1, nonce, plaintext)

    # Construct Poly1305 input:
    # AAD || pad16(AAD) || Ciphertext || pad16(Ciphertext) || len(AAD)_u64 || len(Ciphertext)_u64
    mac_data = (
        aad
        + _pad16(aad)
        + ciphertext
        + _pad16(ciphertext)
        + struct.pack("<QQ", len(aad), len(ciphertext))
    )

    tag = poly1305_mac(mac_data, otk)
    return ciphertext, tag


def chacha20_poly1305_decrypt(
    key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes, tag: bytes
) -> Tuple[bool, bytes]:
    """
    RFC 8439 Section 2.8 Authenticated Decryption.
    Verifies Poly1305 tag before returning plaintext.
    Returns (valid, plaintext). If invalid, plaintext is empty bytes.
    """
    otk = poly1305_key_gen(key, nonce)
    mac_data = (
        aad
        + _pad16(aad)
        + ciphertext
        + _pad16(ciphertext)
        + struct.pack("<QQ", len(aad), len(ciphertext))
    )

    computed_tag = poly1305_mac(mac_data, otk)
    if computed_tag != tag:
        return False, b""

    plaintext = chacha20_decrypt(key, 1, nonce, ciphertext)
    return True, plaintext


# ==============================================================================
# Self-Test against Official Published RFC 8439 Test Vectors
# ==============================================================================

def _run_self_tests():
    print("====================================================================")
    print("model/chacha_poly.py -- RFC 8439 Golden Vector Verification")
    print("====================================================================")

    # 1. RFC 8439 Section 2.1.1: Quarter Round
    a, b, c, d = 0x11111111, 0x01020304, 0x9B8D6F43, 0x01234567
    oa, ob, oc, od = chacha20_quarter_round(a, b, c, d)
    assert (oa, ob, oc, od) == (0xEA2A92F4, 0xCB1CF8CE, 0x4581472E, 0x5881C4BB), "QR test failed"
    print("[PASS] RFC 8439 Sec 2.1.1: Quarter round test vector")

    # 2. RFC 8439 Section 2.2.1: Quarter Round on ChaCha State
    test_state = [
        0x879531E0, 0xC5ECF37D, 0x516461B1, 0xC9A62F8A,
        0x44C20EF3, 0x3390AF7F, 0xD9FC690B, 0x2A5F714C,
        0x53372767, 0xB00A5631, 0x974C541A, 0x359E9963,
        0x5C971061, 0x3D631689, 0x2098D9D6, 0x91DBD320,
    ]
    # Apply quarter round on indices (2, 7, 8, 13) per RFC 8439 Sec 2.2.1
    s2, s7, s8, s13 = chacha20_quarter_round(
        test_state[2], test_state[7], test_state[8], test_state[13]
    )
    assert (s2, s7, s8, s13) == (0xBDB886DC, 0xCFACAFD2, 0xE46BEA80, 0xCCC07C79), "State QR failed"
    print("[PASS] RFC 8439 Sec 2.2.1: Quarter round on state vector (indices 2, 7, 8, 13)")

    # 3. RFC 8439 Section 2.3.2: ChaCha20 Block Function
    key_2_3 = bytes(range(32))  # 00:01:02:...:1f
    nonce_2_3 = bytes([0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4A, 0x00, 0x00, 0x00, 0x00])
    counter_2_3 = 1
    expected_block_2_3 = bytes([
        # RFC 8439 §2.3.2 serialized block, verbatim from the RFC text
        0x10, 0xF1, 0xE7, 0xE4, 0xD1, 0x3B, 0x59, 0x15,  # 000–007
        0x50, 0x0F, 0xDD, 0x1F, 0xA3, 0x20, 0x71, 0xC4,  # 008–015
        0xC7, 0xD1, 0xF4, 0xC7, 0x33, 0xC0, 0x68, 0x03,  # 016–023
        0x04, 0x22, 0xAA, 0x9A, 0xC3, 0xD4, 0x6C, 0x4E,  # 024–031
        0xD2, 0x82, 0x64, 0x46, 0x07, 0x9F, 0xAA, 0x09,  # 032–039
        0x14, 0xC2, 0xD7, 0x05, 0xD9, 0x8B, 0x02, 0xA2,  # 040–047
        0xB5, 0x12, 0x9C, 0xD1, 0xDE, 0x16, 0x4E, 0xB9,  # 048–055
        0xCB, 0xD0, 0x83, 0xE8, 0xA2, 0x50, 0x3C, 0x4E,  # 056–063
    ])
    block_out = chacha20_block(key_2_3, counter_2_3, nonce_2_3)
    assert block_out == expected_block_2_3, f"Block mismatch: got {block_out.hex()} expected {expected_block_2_3.hex()}"
    print("[PASS] RFC 8439 Sec 2.3.2: ChaCha20 block function test vector (64 bytes exact)")

    # 4. RFC 8439 Section 2.4.2: ChaCha20 Encryption
    # Same key (00..1f) and counter (1), but DIFFERENT nonce from §2.3.2.
    # §2.4.2 nonce: 00:00:00:00:00:00:00:4a:00:00:00:00 (byte 3 is 0x00, not 0x09)
    nonce_2_4 = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4A, 0x00, 0x00, 0x00, 0x00])
    plain_2_4 = (
        b"Ladies and Gentlemen of the class of '99: "
        b"If I could offer you only one tip for the future, sunscreen would be it."
    )
    rfc_cipher_hex_2_4 = (
        "6e2e359a2568f98041ba0728dd0d6981"
        "e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b357"
        "1639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e"
        "52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42"
        "874d"
    )
    expected_cipher_bytes_2_4 = bytes.fromhex(rfc_cipher_hex_2_4)
    cipher_2_4 = chacha20_encrypt(key_2_3, counter_2_3, nonce_2_4, plain_2_4)
    assert cipher_2_4 == expected_cipher_bytes_2_4, "Encryption mismatch"
    decrypted_2_4 = chacha20_decrypt(key_2_3, counter_2_3, nonce_2_4, cipher_2_4)
    assert decrypted_2_4 == plain_2_4, "Decryption round-trip mismatch"
    print("[PASS] RFC 8439 Sec 2.4.2: ChaCha20 streaming encryption & round-trip (114 bytes)")


    # 5. RFC 8439 Section 2.5.2: Poly1305 MAC
    poly_key_2_5 = bytes.fromhex(
        "85d6be7857556d337f4452fe42d506a8"
        "0103808afb0db2fd4abff6af4149f51b"
    )
    poly_msg_2_5 = b"Cryptographic Forum Research Group"
    expected_tag_2_5 = bytes.fromhex("a8061dc1305136c6c22b8baf0c0127a9")
    computed_tag_2_5 = poly1305_mac(poly_msg_2_5, poly_key_2_5)
    assert computed_tag_2_5 == expected_tag_2_5, f"Poly1305 mismatch: {computed_tag_2_5.hex()} vs {expected_tag_2_5.hex()}"
    print("[PASS] RFC 8439 Sec 2.5.2: Poly1305 MAC vector")

    # 6. RFC 8439 Section 2.8.2: ChaCha20-Poly1305 AEAD Test Vector
    aead_key = bytes.fromhex(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
    )
    aead_nonce = bytes.fromhex("070000004041424344454647")
    aead_aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    aead_plain = (
        b"Ladies and Gentlemen of the class of '99: "
        b"If I could offer you only one tip for the future, sunscreen would be it."
    )
    expected_aead_cipher = bytes.fromhex(
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b"
        "1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58"
        "fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b"
        "6116"
    )
    expected_aead_tag = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")

    cipher_out, tag_out = chacha20_poly1305_encrypt(aead_key, aead_nonce, aead_aad, aead_plain)
    assert cipher_out == expected_aead_cipher, f"AEAD cipher mismatch: {cipher_out.hex()}"
    assert tag_out == expected_aead_tag, f"AEAD tag mismatch: {tag_out.hex()} vs {expected_aead_tag.hex()}"

    valid, decrypted_plain = chacha20_poly1305_decrypt(
        aead_key, aead_nonce, aead_aad, cipher_out, tag_out
    )
    assert valid and decrypted_plain == aead_plain, "AEAD decrypt failure"

    # Verify tamper detection on ciphertext
    tampered_cipher = bytearray(cipher_out)
    tampered_cipher[0] ^= 0x01
    tamper_valid, _ = chacha20_poly1305_decrypt(
        aead_key, aead_nonce, aead_aad, bytes(tampered_cipher), tag_out
    )
    assert not tamper_valid, "Tampered ciphertext unexpectedly accepted"

    # Verify tamper detection on AAD
    tamper_aad = bytearray(aead_aad)
    tamper_aad[0] ^= 0x01
    tamper_valid_aad, _ = chacha20_poly1305_decrypt(
        aead_key, aead_nonce, bytes(tamper_aad), cipher_out, tag_out
    )
    assert not tamper_valid_aad, "Tampered AAD unexpectedly accepted"

    print("[PASS] RFC 8439 Sec 2.8.2: ChaCha20-Poly1305 AEAD encrypt, decrypt, & tamper detection")
    print("====================================================================")
    print("ALL RFC 8439 ChaCha20-Poly1305 checks PASSED.")
    print("====================================================================")


if __name__ == "__main__":
    _run_self_tests()

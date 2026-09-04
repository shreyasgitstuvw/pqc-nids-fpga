import os
import sys

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)
from model.sha3 import sha3_256,sha3_512,shake256
from model.mlkem.pke import keygen,encrypt,decrypt,byte_encode,byte_decode

def h(s):
    return sha3_256(s)

def g(s):
    out = sha3_512(s)
    return out[:32], out[32:]

def j(s):
    return shake256(s, 32)

def keygen_internal(d:bytes, z:bytes) -> tuple[bytes, bytes]:
    
   ek,dk0 = keygen(d)
   hash = h(ek)
   dk = dk0 + ek + hash + z
   
   return ek,dk

def encaps_internal(ek,m:bytes) -> tuple[bytes, bytes]: 
    assert len(ek) == 800, f"ek is: {len(ek)} bytes"
    assert len(m) == 32, f"m is: {len(m)} bytes"
    k,r=g(m+h(ek))
    c= encrypt(ek, m, r)
    return k,c

def decaps_internal(dk, c):
    dk_pke = dk[:768]
    ek     = dk[768:1568]
    h_ek   = dk[1568:1600]
    z      = dk[1600:1632]
    
    m_prime = decrypt(dk_pke, c)
    K_prime, r_prime = g(m_prime + h_ek)
    K_bar = j(z + c)
    c_prime = encrypt(ek, m_prime, r_prime)
    
    if c == c_prime:
        return K_prime
    else: 
        return K_bar
    
# ---------------------------------------------------------------------------
# Input validation -- FIPS 203 sec 7.2 / 7.3
#
# These are NOT part of the KEM algorithms proper; they are preconditions the
# spec requires before a key is used. kem.py's internal functions assume
# well-formed input, so the checks live at the outer API boundary where
# untrusted bytes actually arrive.
#
# In the NIDS, ek arrives over the wire from the peer during handshake, i.e.
# it is attacker-controlled. check_ek is the guard on that path.
# ---------------------------------------------------------------------------

EK_BYTES = 384 * 2 + 32      # 800  (k=2)
DK_BYTES = 768 * 2 + 96      # 1632


def check_ek(ek: bytes) -> bool:
    """
    Encapsulation key check (sec 7.2): type check + modulus check.

    ek is 768 bytes of encoded t_hat followed by a 32-byte seed rho. Each
    coefficient is stored in 12 bits, which can hold 0..4095 -- but valid
    coefficients are only 0..3328. Values in 3329..4095 are representable yet
    invalid, and nothing about the byte layout rejects them.

    The test: decode then re-encode. byte_decode reduces mod q, so a
    non-canonical 3500 comes back as 171 and re-encodes to different bytes.
    A canonical coefficient survives unchanged. Byte equality is therefore
    exactly the canonicality test, with no per-coefficient comparison needed.
    """
    if len(ek) != EK_BYTES:
        return False
    body = ek[:768]
    for i in range(2):                       # k = 2 polynomials
        chunk = body[i * 384:(i + 1) * 384]
        if byte_encode(byte_decode(chunk, 12), 12) != chunk:
            return False
    return True


def check_dk(dk: bytes) -> bool:
    """
    Decapsulation key check (sec 7.3): type check + hash check.

    dk is dk_pke(768) || ek(800) || H(ek)(32) || z(32). The embedded hash must
    match a fresh SHA3-256 over the embedded ek. This catches a dk whose two
    halves came from different keypairs, or local key-store corruption --
    which would otherwise produce a silently wrong shared secret.
    """
    if len(dk) != DK_BYTES:
        return False
    ek_embedded = dk[768:1568]
    return h(ek_embedded) == dk[1568:1600]


def KeyGen() -> tuple[bytes, bytes]:
    d = os.urandom(32)
    z = os.urandom(32)
    return keygen_internal(d, z)

def Encaps(ek: bytes) -> tuple[bytes, bytes]:
    # sec 7.2 -- reject a malformed peer key before it reaches the math
    if not check_ek(ek):
        raise ValueError("invalid encapsulation key (FIPS 203 sec 7.2)")
    m = os.urandom(32)
    return encaps_internal(ek, m)

def Decaps(dk: bytes, c: bytes) -> bytes:
    # sec 7.3 -- our own key must be internally consistent before we use it
    if not check_dk(dk):
        raise ValueError("invalid decapsulation key (FIPS 203 sec 7.3)")
    return decaps_internal(dk, c)

if __name__ == "__main__":
    print("=== ML-KEM-512 self-test ===\n")
    failures = 0

    def chk(label, cond, detail=""):
        global failures
        tag = "OK  " if cond else "FAIL"
        if not cond:
            failures += 1
        print(f"{tag} {label}" + (f": {detail}" if detail else ""))

    # size checks
    ek, dk = KeyGen()
    chk("ek length == 800",  len(ek) == 800,  f"got {len(ek)}")
    chk("dk length == 1632", len(dk) == 1632, f"got {len(dk)}")

    K_enc, c = Encaps(ek)
    chk("c  length == 768",  len(c) == 768,    f"got {len(c)}")
    chk("K  length == 32",   len(K_enc) == 32, f"got {len(K_enc)}")

    K_dec = Decaps(dk, c)
    chk("K_enc == K_dec (round-trip)", K_enc == K_dec,
        f"enc={K_enc.hex()} dec={K_dec.hex()}")

    # implicit rejection
    c_bad = bytes([c[0] ^ 0xFF]) + c[1:]
    K_bad = Decaps(dk, c_bad)
    chk("tampered c → different key", K_bad != K_enc)

    # 10 independent round-trips
    all_ok = True
    for i in range(10):
        ek_i, dk_i = KeyGen()
        K_e, c_i   = Encaps(ek_i)
        K_d        = Decaps(dk_i, c_i)
        if K_e != K_d:
            all_ok = False
            print(f"  FAIL round-trip {i}: enc={K_e.hex()} dec={K_d.hex()}")
    chk("10 independent round-trips", all_ok)

    print()
    if failures:
        print(f"{failures} FAILURE(S)")
        raise SystemExit(1)
    else:
        print("All self-checks passed.")

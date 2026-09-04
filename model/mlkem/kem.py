import os
import sys

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)
from model.sha3 import sha3_256,sha3_512,shake256
from model.mlkem.pke import keygen,encrypt,decrypt

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
    
def KeyGen() -> tuple[bytes, bytes]:
    d = os.urandom(32)
    z = os.urandom(32)
    return keygen_internal(d, z)

def Encaps(ek: bytes) -> tuple[bytes, bytes]:
    m = os.urandom(32)
    return encaps_internal(ek, m)

def Decaps(dk: bytes, c: bytes) -> bytes:
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

"""
model/mlkem/opcount.py
Operation counter for ML-KEM-512, to turn Member A's interface-contract
verdict-latency table (docs/Member A/interface_contract.md sec 6) from "?"
into numbers grounded in the golden model.

This is measurement infrastructure, not part of the crypto. It monkey-patches
counters around the primitives, runs each ML-KEM operation once, and reports
exact call counts. Nothing here is imported by kem.py or pke.py.

Why these four counters
-----------------------
  keccak_f1600  -- the 24-round permutation. Every SHA3/SHAKE byte in the
                   design flows through it, and in RTL it is a multi-cycle
                   block, so it usually dominates handshake latency.
  ntt / intt    -- 7 stages x 128 butterflies = 896 butterflies per call.
  base_case_mul -- 128 per polynomial multiply in the NTT domain.
  mul_mod       -- modular multiplications routed through ntt.mul_mod.
  modmul_total  -- mul_mod plus the 5 raw "% Q" multiplies inside each
                   base_case_multiply, which bypass mul_mod entirely. This is
                   the number to use for DSP budgeting; mul_mod alone
                   undercounts.
"""

import os
import sys

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

import model.sha3 as sha3
import model.mlkem.ntt as nttmod
import model.mlkem.pke as pke
from model.mlkem.kem import keygen_internal, encaps_internal, decaps_internal

COUNTS = {}


def _wrap(name, fn):
    def counted(*a, **kw):
        COUNTS[name] = COUNTS.get(name, 0) + 1
        return fn(*a, **kw)
    return counted


def install():
    """Patch counters in every module that holds its own reference."""
    sha3.keccak_f1600 = _wrap("keccak_f1600", sha3._orig_keccak)
    for mod in (pke,):
        mod.ntt = _wrap("ntt", nttmod._orig_ntt)
        mod.intt = _wrap("intt", nttmod._orig_intt)
        mod.mul_mod = _wrap("mul_mod", nttmod._orig_mul)
    pke.base_case_multiply = _wrap("base_case_multiply", pke._orig_bcm)
    nttmod.mul_mod = _wrap("mul_mod", nttmod._orig_mul)


# stash originals once
sha3._orig_keccak = sha3.keccak_f1600
nttmod._orig_ntt = nttmod.ntt
nttmod._orig_intt = nttmod.intt
nttmod._orig_mul = nttmod.mul_mod
pke._orig_bcm = pke.base_case_multiply


def measure(label, thunk):
    COUNTS.clear()
    install()
    result = thunk()
    return label, dict(COUNTS), result


if __name__ == "__main__":
    d = bytes(range(32))
    z = bytes(range(32, 64))
    m = bytes(range(64, 96))

    lbl1, c1, (ek, dk) = measure("KeyGen",  lambda: keygen_internal(d, z))
    lbl2, c2, (K, ct)  = measure("Encaps",  lambda: encaps_internal(ek, m))
    lbl3, c3, _        = measure("Decaps",  lambda: decaps_internal(dk, ct))

    rows = [(lbl1, c1), (lbl2, c2), (lbl3, c3)]

    # base_case_multiply uses raw "% Q" arithmetic rather than mul_mod, so it
    # contributes 5 modular multiplies per call that mul_mod never sees:
    #   a0*b0, a1*b1, (a1*b1)*gamma, a0*b1, a1*b0
    for _, c in rows:
        c["modmul_total"] = c.get("mul_mod", 0) + 5 * c.get("base_case_multiply", 0)

    keys = ["keccak_f1600", "ntt", "intt", "base_case_multiply",
            "mul_mod", "modmul_total"]

    print("=" * 74)
    print("ML-KEM-512 operation counts (per invocation, golden model)")
    print("=" * 74)
    print(f"{'operation':<22}" + "".join(f"{l:>16}" for l, _ in rows))
    print("-" * 74)
    for k in keys:
        print(f"{k:<22}" + "".join(f"{c.get(k,0):>16,}" for _, c in rows))
    print("=" * 74)

    print("""
Reading this for the RTL latency estimate
-----------------------------------------
Decaps is the FO transform: decrypt + G + J + re-encrypt. Its cost is
therefore roughly Encaps + Decrypt, which is why it is the largest column and
why it -- not Encaps -- sets the handshake-completion latency budget.

To convert to cycles, multiply each count by that block's cycle cost in your
RTL and sum the serial portion:

  cycles ~= (keccak_f1600 x C_perm) + ((ntt + intt) x C_ntt)
            + (base_case_multiply x C_bcm)

A single-round-per-cycle Keccak core gives C_perm = 24. A radix-2 NTT that
retires one butterfly per cycle gives C_ntt = 896 (7 stages x 128). These are
starting points for Member A's table, not measured RTL numbers -- replace them
once mlkem_top.v exists.
""")

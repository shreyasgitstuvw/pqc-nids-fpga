#==========================================================================
# sim/cocotb/test_kem_cycles.py
#
# C18 -- measured KeyGen / Encaps / Decaps cycle counts for synopsis sec 6.3.
# DUT: real mlkem_top.v (no mocks). Counts are SIMULATED clock cycles from the
# cmd_start edge to the kem_done strobe; wall-clock latency at 100 MHz is
# cycles x 10 ns and holds ONLY if Vivado closes timing at 100 MHz, which has
# not been run (all timing/resource figures are pre-synthesis estimates).
#
# Samples: both NIST KeyGen KATs + random seeds; NIST encaps KAT + random
# (ek, m); NIST VAL decaps vectors + random valid and corrupted ciphertexts.
# Every sample is also checked bit-exact against model/mlkem, so a number is
# only logged for a run whose output was correct.
#
# Asserted bounds (in cycles, see BOUNDS below; each is a window around the
# measured range, not a design target):
#   KeyGen : 17600 to 17720   (measured 17640 to 17669 in the C18 run)
#   Encaps : 23950 to 24120   (measured 24022 to 24049 in the C18 run)
#   Decaps : 33700 to 33900   (measured 33786 to 33814 in the C18 run)
#   Decaps count is IDENTICAL for authentic vs corrupted ciphertext on the
#   same dk (constant-time FO transform): asserted per pair via ca == cr.
#
# Set KEM_CYCLES_OUT=<path.json> to write the raw samples + summary.
#==========================================================================

import json
import os
import random
import statistics
import sys
from pathlib import Path

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import FallingEdge

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from model.mlkem.kem import keygen_internal, encaps_internal, decaps_internal
from test_mlkem_top import (  # noqa: E402
    reset_dut, run_encaps, run_decaps, read_dk_ram, load_kat_keygen,
    load_kat_encaps, load_kat_decaps_all,
)

N_RANDOM = 5
SAMPLES = {"keygen": [], "encaps": [], "decaps_authentic": [], "decaps_rejected": []}
BOUNDS = {"keygen": (17600, 17720), "encaps": (23950, 24120), "decaps": (33700, 33900)}


async def run_keygen(dut, d, z, timeout=50000):
    dut.seed_d.value = int.from_bytes(d, "little")
    dut.seed_z.value = int.from_bytes(z, "little")
    dut.cmd_op.value = 0
    dut.cmd_session_id.value = 1
    dut.cmd_start.value = 1
    await FallingEdge(dut.clk)
    dut.cmd_start.value = 0
    cycles = 0
    while not int(dut.kem_done.value):
        await FallingEdge(dut.clk)
        cycles += 1
        assert cycles < timeout, "KeyGen timeout"
    dk = await read_dk_ram(dut, 204)
    return cycles, dk


def summary(xs):
    return {"n": len(xs), "min": min(xs), "max": max(xs),
            "mean": round(statistics.mean(xs), 1), "samples": xs}


@cocotb.test()
async def measure_keygen(dut):
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    rng = random.Random(0xC18)
    seeds = []
    for tc in (1, 2):
        kat = load_kat_keygen(tc)
        seeds.append((bytes.fromhex(kat["d"]), bytes.fromhex(kat["z"])))
    seeds += [(bytes(rng.getrandbits(8) for _ in range(32)), bytes(rng.getrandbits(8) for _ in range(32)))
              for _ in range(N_RANDOM)]
    for d, z in seeds:
        await reset_dut(dut)
        cycles, dk = await run_keygen(dut, d, z)
        _, exp_dk = keygen_internal(d, z)
        assert dk == exp_dk, "KeyGen output != model; refusing to log a count for a wrong result"
        SAMPLES["keygen"].append(cycles)
    lo, hi = BOUNDS["keygen"]
    assert all(lo <= c <= hi for c in SAMPLES["keygen"]), SAMPLES["keygen"]
    dut._log.info(f"KeyGen cycles: {summary(SAMPLES['keygen'])}")


@cocotb.test()
async def measure_encaps(dut):
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    rng = random.Random(0xC18E)
    pairs = []
    kat = load_kat_encaps(1)
    pairs.append((bytes.fromhex(kat["ek"]), bytes.fromhex(kat["m"])))
    for _ in range(N_RANDOM):
        ek, _dk = keygen_internal(bytes(rng.getrandbits(8) for _ in range(32)),
                                  bytes(rng.getrandbits(8) for _ in range(32)))
        pairs.append((ek, bytes(rng.getrandbits(8) for _ in range(32))))
    for ek, m in pairs:
        await reset_dut(dut)
        cycles, outcome = await run_encaps(dut, ek, m)
        assert outcome == "done"
        exp_k, _c = encaps_internal(ek, m)
        assert int(dut.kem_shared_secret.value).to_bytes(32, "little") == exp_k
        SAMPLES["encaps"].append(cycles)
    lo, hi = BOUNDS["encaps"]
    assert all(lo <= c <= hi for c in SAMPLES["encaps"]), SAMPLES["encaps"]
    dut._log.info(f"Encaps cycles: {summary(SAMPLES['encaps'])}")


@cocotb.test()
async def measure_decaps(dut):
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    rng = random.Random(0xC18D)
    # NIST VAL vectors (include official implicit-rejection cases)
    for label, dk, c, k in load_kat_decaps_all()[:4]:
        await reset_dut(dut)
        cycles, got, _ = await run_decaps(dut, dk, c)
        assert got == k, label
        SAMPLES["decaps_authentic"].append(cycles)
    # random dk: authentic vs corrupted on the SAME dk must cost the same
    for _ in range(N_RANDOM):
        ek, dk = keygen_internal(bytes(rng.getrandbits(8) for _ in range(32)),
                                 bytes(rng.getrandbits(8) for _ in range(32)))
        k_true, c = encaps_internal(ek, bytes(rng.getrandbits(8) for _ in range(32)))
        bad = bytearray(c)
        bad[rng.randrange(768)] ^= 1 << rng.randrange(8)
        bad = bytes(bad)
        await reset_dut(dut)
        ca, ka, _ = await run_decaps(dut, dk, c)
        await reset_dut(dut)
        cr, kr, _ = await run_decaps(dut, dk, bad)
        assert ka == k_true and kr == decaps_internal(dk, bad) and kr != ka
        assert ca == cr, f"timing leak: authentic {ca} vs rejected {cr}"
        SAMPLES["decaps_authentic"].append(ca)
        SAMPLES["decaps_rejected"].append(cr)
    lo, hi = BOUNDS["decaps"]
    allc = SAMPLES["decaps_authentic"] + SAMPLES["decaps_rejected"]
    assert all(lo <= c <= hi for c in allc), allc
    dut._log.info(f"Decaps authentic: {summary(SAMPLES['decaps_authentic'])}")
    dut._log.info(f"Decaps rejected : {summary(SAMPLES['decaps_rejected'])}")

    out = os.environ.get("KEM_CYCLES_OUT")
    if out:
        data = {
            "note": "simulated cycles, cmd_start -> kem_done, real mlkem_top.v; pre-synthesis, "
                    "wall-clock = cycles x 10 ns only if timing closes at 100 MHz (not yet run)",
            "keygen": summary(SAMPLES["keygen"]),
            "encaps": summary(SAMPLES["encaps"]),
            "decaps_authentic": summary(SAMPLES["decaps_authentic"]),
            "decaps_rejected": summary(SAMPLES["decaps_rejected"]),
        }
        Path(out).write_text(json.dumps(data, indent=2))


# ==============================================================================
# Runner for pytest / command-line execution
# ==============================================================================
import pytest


@pytest.mark.parametrize("sim_build", ["sim_build_kem_cycles"])
def test_runner(sim_build):
    from cocotb.runner import get_runner

    proj_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    kem = lambda f: os.path.join(proj_path, "rtl", "crypto", "kem", f)
    sources = [kem(f) for f in (
        "poly_bank_ram.v", "sample_ntt.v", "cbd_sampler.v", "poly_add_sub.v",
        "byte_encode.v", "byte_decode.v", "compress.v", "decompress.v", "pack_8_to_64.v")]
    sources += [
        os.path.join(proj_path, "rtl", "crypto", "sha3", "keccak_f1600.v"),
        os.path.join(proj_path, "rtl", "crypto", "sha3", "shake_wrapper.v"),
        os.path.join(proj_path, "rtl", "crypto", "ntt", "modmul.v"),
        os.path.join(proj_path, "rtl", "crypto", "ntt", "butterfly.v"),
        os.path.join(proj_path, "rtl", "crypto", "ntt", "ntt_core.v"),
        os.path.join(proj_path, "rtl", "crypto", "ntt", "poly_mul_acc.v"),
        kem("mlkem_top.v"),
    ]
    includes = [os.path.join(proj_path, "rtl", d) for d in ("control", "crypto/ntt", "crypto/sha3", "crypto/kem")]
    runner = get_runner("icarus")
    runner.build(verilog_sources=sources, includes=includes, hdl_toplevel="mlkem_top",
                 build_dir=os.path.join(proj_path, "sim", sim_build), always=True)
    runner.test(hdl_toplevel="mlkem_top", test_module="test_kem_cycles",
                test_dir=os.path.join(proj_path, "sim", "cocotb"))


if __name__ == "__main__":
    test_runner("sim_build_kem_cycles")

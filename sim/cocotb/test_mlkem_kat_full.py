#==========================================================================
# sim/cocotb/test_mlkem_kat_full.py
#
# C16 -- FULL FIPS 203 ML-KEM-512 KAT sweep through the real mlkem_top.v.
# "Zero unexplained mismatches" is a statement about the whole vector set, not
# a sample, so this runs every ML-KEM-512 vector in sim/vectors/fips203_kat/:
#
#   keygen_all_25            keygen tgId 1                (25 vectors): ek and dk bit-exact
#   encaps_all_25            encapsulation tgId 1         (25 vectors): c and K bit-exact
#   encaps_key_check_all_10  encapsulationKeyCheck tgId 8 (10 vectors): RTL accepts exactly
#                            the keys NIST marks valid and rejects (kem_key_invalid) exactly
#                            the keys it marks invalid ("values too large")
#   decaps_all_10            decapsulation tgId 4         (10 vectors, includes modified
#                            ciphertexts = implicit rejection): K bit-exact, no verdict strobe
#
# NOT run through hardware, by design: decapsulationKeyCheck (tgId 7, FIPS 203 sec 7.3
# dk hash check). The device never imports a dk -- it generates it on-chip -- so
# the RTL has no dk-import path. That check is implemented and KAT-covered in
# model/mlkem (task C3).
#==========================================================================

import json
import os
import sys
from pathlib import Path

import cocotb
from cocotb.clock import Clock

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_mlkem_top import (  # noqa: E402
    reset_dut, run_encaps, run_decaps, read_c_ram, KAT_KEYGEN_PATH, KAT_ENCAP_PATH,
)
from test_kem_cycles import run_keygen  # noqa: E402


def groups(path, tg_id):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    for tg in data["testGroups"]:
        if tg["tgId"] == tg_id:
            return tg["tests"]
    raise KeyError(tg_id)


@cocotb.test()
async def keygen_all_25(dut):
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    tests = groups(KAT_KEYGEN_PATH, 1)
    assert len(tests) == 25
    for tc in tests:
        await reset_dut(dut)
        cycles, dk = await run_keygen(dut, bytes.fromhex(tc["d"]), bytes.fromhex(tc["z"]))
        assert dk == bytes.fromhex(tc["dk"]), f"keygen tcId {tc['tcId']}: dk != NIST"
        assert dk[768:1568] == bytes.fromhex(tc["ek"]), f"keygen tcId {tc['tcId']}: ek != NIST"


@cocotb.test()
async def encaps_all_25(dut):
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    tests = groups(KAT_ENCAP_PATH, 1)
    assert len(tests) == 25
    for tc in tests:
        await reset_dut(dut)
        cycles, outcome = await run_encaps(dut, bytes.fromhex(tc["ek"]), bytes.fromhex(tc["m"]))
        assert outcome == "done", f"encaps tcId {tc['tcId']}: {outcome}"
        got_c = await read_c_ram(dut, 96)
        got_k = int(dut.kem_shared_secret.value).to_bytes(32, "little")
        assert got_c == bytes.fromhex(tc["c"]), f"encaps tcId {tc['tcId']}: c != NIST"
        assert got_k == bytes.fromhex(tc["k"]), f"encaps tcId {tc['tcId']}: K != NIST"


@cocotb.test()
async def encaps_key_check_all_10(dut):
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    tests = groups(KAT_ENCAP_PATH, 8)
    assert len(tests) == 10
    n_valid = n_invalid = 0
    for tc in tests:
        await reset_dut(dut)
        _cycles, outcome = await run_encaps(dut, bytes.fromhex(tc["ek"]), bytes(32))
        want = "done" if tc["testPassed"] else "invalid"
        assert outcome == want, (
            f"ekCheck tcId {tc['tcId']} ({tc['reason']}): NIST testPassed={tc['testPassed']} "
            f"but RTL outcome={outcome}")
        n_valid += tc["testPassed"]
        n_invalid += not tc["testPassed"]
    assert n_valid > 0 and n_invalid > 0, "key-check group must contain both valid and invalid keys"


@cocotb.test()
async def decaps_all_10(dut):
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    tests = groups(KAT_ENCAP_PATH, 4)
    assert len(tests) == 10
    for tc in tests:
        await reset_dut(dut)
        cycles, got, _sid = await run_decaps(dut, bytes.fromhex(tc["dk"]), bytes.fromhex(tc["c"]))
        assert got == bytes.fromhex(tc["k"]), f"decaps tcId {tc['tcId']} ({tc['reason']}): K != NIST"


# ==============================================================================
# Runner for pytest / command-line execution
# ==============================================================================
import pytest


@pytest.mark.parametrize("sim_build", ["sim_build_mlkem_kat_full"])
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
    runner.test(hdl_toplevel="mlkem_top", test_module="test_mlkem_kat_full",
                test_dir=os.path.join(proj_path, "sim", "cocotb"))


if __name__ == "__main__":
    test_runner("sim_build_mlkem_kat_full")

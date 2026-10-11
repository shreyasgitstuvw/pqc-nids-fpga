#==========================================================================
# sim/cocotb/test_mlkem_top.py
#
# Cocotb testbench for mlkem_top.v (ML-KEM-512 Milestone a: KeyGen Internal).
# Bit-exact synthesizable RTL twin of FIPS 203 Section 5 (Algorithm 19)
# and model/mlkem/kem.py:keygen_internal.
#
# Tests:
#   1. keygen_kat_vector_1:
#      Bit-exact validation against NIST FIPS 203 KAT tcId: 1 for ML-KEM-512.
#      Asserts exact public key ek (800 bytes) and secret key dk (1632 bytes).
#      Measures latency in clock cycles.
#   2. keygen_kat_vector_2:
#      Bit-exact validation against NIST FIPS 203 KAT tcId: 2 for ML-KEM-512.
#   3. keygen_mid_stream_reset:
#      Asserts clean abort on synchronous reset mid-computation, and
#      clean recovery on subsequent KeyGen execution.
#==========================================================================

import json
import os
import sys
from pathlib import Path

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import FallingEdge, RisingEdge

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))

from model.mlkem.kem import keygen_internal, encaps_internal

KAT_KEYGEN_PATH = REPO / "sim" / "vectors" / "fips203_kat" / "mlkem512_keygen.json"
KAT_ENCAP_PATH  = REPO / "sim" / "vectors" / "fips203_kat" / "mlkem512_encap_decap.json"


def load_kat_keygen(tc_id=1):
    with open(KAT_KEYGEN_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    for tg in data["testGroups"]:
        for tc in tg["tests"]:
            if tc["tcId"] == tc_id:
                return tc
    raise ValueError(f"tcId {tc_id} not found in KAT keygen")


def load_kat_encaps(tc_id=1):
    with open(KAT_ENCAP_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    for tg in data["testGroups"]:
        for tc in tg["tests"]:
            if tc["tcId"] == tc_id:
                return tc
    raise ValueError(f"tcId {tc_id} not found in KAT encap")


async def reset_dut(dut):
    dut.rst.value = 1
    dut.cmd_start.value = 0
    dut.cmd_op.value = 0
    dut.cmd_session_id.value = 0
    dut.seed_d.value = 0
    dut.seed_z.value = 0
    dut.seed_m.value = 0
    dut.dk_ram_rd_addr.value = 0
    dut.dk_ram_wr_en.value = 0
    dut.dk_ram_wr_addr_ext.value = 0
    dut.dk_ram_wr_data_ext.value = 0
    dut.c_ram_rd_addr_ext.value = 0
    dut.packet_bus_valid.value = 0
    dut.packet_bus_sof.value = 0
    dut.packet_bus_eof.value = 0
    dut.packet_bus_data.value = 0
    dut.packet_bus_payload_len.value = 0
    dut.packet_bus_session_id.value = 0
    dut.packet_bus_packet_type.value = 0
    await FallingEdge(dut.clk)
    await FallingEdge(dut.clk)
    dut.rst.value = 0
    await FallingEdge(dut.clk)


async def read_dk_ram(dut, num_words=204):
    """Read 64-bit words from dk_ram via synchronous read port."""
    words = []
    for addr in range(num_words):
        dut.dk_ram_rd_addr.value = addr
        await RisingEdge(dut.clk)
        await FallingEdge(dut.clk)
        words.append(int(dut.dk_ram_rdata.value))
    byte_arr = bytearray()
    for w in words:
        byte_arr.extend(w.to_bytes(8, byteorder="little"))
    return bytes(byte_arr)


async def write_dk_ram(dut, data_bytes, start_word_addr=96):
    """Write bytes into dk_ram as 64-bit little-endian words."""
    assert len(data_bytes) % 8 == 0, f"data_bytes len {len(data_bytes)} not multiple of 8"
    num_words = len(data_bytes) // 8
    dut.dk_ram_wr_en.value = 1
    for i in range(num_words):
        word = int.from_bytes(data_bytes[i * 8 : (i + 1) * 8], byteorder="little")
        dut.dk_ram_wr_addr_ext.value = start_word_addr + i
        dut.dk_ram_wr_data_ext.value = word
        await RisingEdge(dut.clk)
        await FallingEdge(dut.clk)
    dut.dk_ram_wr_en.value = 0
    await FallingEdge(dut.clk)


async def read_c_ram(dut, num_words=96):
    """Read 64-bit words from c_ram via synchronous read port."""
    words = []
    for addr in range(num_words):
        dut.c_ram_rd_addr_ext.value = addr
        await RisingEdge(dut.clk)
        await FallingEdge(dut.clk)
        words.append(int(dut.c_ram_rdata_ext.value))
    byte_arr = bytearray()
    for w in words:
        byte_arr.extend(w.to_bytes(8, byteorder="little"))
    return bytes(byte_arr)


@cocotb.test()
async def keygen_kat_vector_1(dut):
    """FIPS 203 KAT Vector 1 bit-exact KeyGen verification and cycle measurement."""
    clock = Clock(dut.clk, 10, units="ns")
    cocotb.start_soon(clock.start())

    await reset_dut(dut)

    kat = load_kat_keygen(1)
    d_bytes = bytes.fromhex(kat["d"])
    z_bytes = bytes.fromhex(kat["z"])
    expected_ek = bytes.fromhex(kat["ek"])
    expected_dk = bytes.fromhex(kat["dk"])

    # Double check Python model oracle
    py_ek, py_dk = keygen_internal(d_bytes, z_bytes)
    assert py_ek == expected_ek, "Python model mismatch on KAT ek"
    assert py_dk == expected_dk, "Python model mismatch on KAT dk"

    # Load 256-bit seeds (little-endian integer representation)
    dut.seed_d.value = int.from_bytes(d_bytes, byteorder="little")
    dut.seed_z.value = int.from_bytes(z_bytes, byteorder="little")
    dut.cmd_op.value = 0  # OP_KEYGEN
    dut.cmd_session_id.value = 1
    dut.cmd_start.value = 1
    await FallingEdge(dut.clk)
    dut.cmd_start.value = 0

    cycles = 0
    while not int(dut.kem_done.value):
        await FallingEdge(dut.clk)
        cycles += 1
        if cycles > 50000:
            raise TimeoutError(f"KeyGen did not complete within {cycles} cycles")

    dut._log.info(f"KeyGen Vector 1 completed in {cycles} clock cycles")
    assert cycles == 17658, f"KeyGen Vector 1 expected 17658 cycles, got {cycles}"
    assert int(dut.kem_done.value) == 1, "kem_done must strobe high"
    assert int(dut.busy.value) == 0, "busy must deassert on completion"

    # Read back 204 words (1632 bytes) of dk_ram
    actual_dk = await read_dk_ram(dut, 204)
    actual_ek = actual_dk[768:1568]

    # Section checks:
    s0_match = (actual_dk[0:384] == expected_dk[0:384])
    s1_match = (actual_dk[384:768] == expected_dk[384:768])
    t0_match = (actual_dk[768:1152] == expected_dk[768:1152])
    t1_match = (actual_dk[1152:1536] == expected_dk[1152:1536])
    rho_match = (actual_dk[1536:1568] == expected_dk[1536:1568])
    hek_match = (actual_dk[1568:1600] == expected_dk[1568:1600])
    z_match = (actual_dk[1600:1632] == expected_dk[1600:1632])

    dut._log.info(f"Sections: s0={s0_match}, s1={s1_match}, t0={t0_match}, t1={t1_match}, rho={rho_match}, hek={hek_match}, z={z_match}")
    if not s0_match:
        dut._log.info(f"s0 exp: {expected_dk[0:32].hex()}")
        dut._log.info(f"s0 act: {actual_dk[0:32].hex()}")
    if not t0_match:
        dut._log.info(f"t0 exp: {expected_dk[768:800].hex()}")
        dut._log.info(f"t0 act: {actual_dk[768:800].hex()}")
    if not rho_match:
        dut._log.info(f"rho exp: {expected_dk[1536:1568].hex()}")
        dut._log.info(f"rho act: {actual_dk[1536:1568].hex()}")

    assert s0_match, "s0 mismatch"
    assert s1_match, "s1 mismatch"
    assert t0_match, "t0 mismatch"
    assert t1_match, "t1 mismatch"
    assert rho_match, "rho mismatch"
    assert hek_match, "hek mismatch"
    assert z_match, "z mismatch"
    assert actual_ek == expected_ek, "ek mismatch"
    assert actual_dk == expected_dk, "dk mismatch"
    dut._log.info("KeyGen Vector 1 bit-exact match against NIST KAT and Python model!")


@cocotb.test()
async def keygen_kat_vector_2(dut):
    """FIPS 203 KAT Vector 2 bit-exact KeyGen verification."""
    clock = Clock(dut.clk, 10, units="ns")
    cocotb.start_soon(clock.start())

    await reset_dut(dut)

    kat = load_kat_keygen(2)
    d_bytes = bytes.fromhex(kat["d"])
    z_bytes = bytes.fromhex(kat["z"])
    expected_ek = bytes.fromhex(kat["ek"])
    expected_dk = bytes.fromhex(kat["dk"])

    dut.seed_d.value = int.from_bytes(d_bytes, byteorder="little")
    dut.seed_z.value = int.from_bytes(z_bytes, byteorder="little")
    dut.cmd_op.value = 0  # OP_KEYGEN
    dut.cmd_session_id.value = 2
    dut.cmd_start.value = 1
    await FallingEdge(dut.clk)
    dut.cmd_start.value = 0

    cycles = 0
    while not int(dut.kem_done.value):
        await FallingEdge(dut.clk)
        cycles += 1
        if cycles > 50000:
            raise TimeoutError(f"KeyGen did not complete within {cycles} cycles")

    dut._log.info(f"KeyGen Vector 2 completed in {cycles} clock cycles")
    assert cycles == 17669, f"KeyGen Vector 2 expected 17669 cycles, got {cycles}"
    actual_dk = await read_dk_ram(dut, 204)
    actual_ek = actual_dk[768:1568]

    assert actual_ek == expected_ek, "ek mismatch on KAT vector 2"
    assert actual_dk == expected_dk, "dk mismatch on KAT vector 2"
    dut._log.info("KeyGen Vector 2 bit-exact match against NIST KAT!")


@cocotb.test()
async def keygen_mid_stream_reset(dut):
    """Verify that synchronous reset mid-computation cleans up and permits immediate rerun."""
    clock = Clock(dut.clk, 10, units="ns")
    cocotb.start_soon(clock.start())

    await reset_dut(dut)

    kat = load_kat_keygen(1)
    dut.seed_d.value = int.from_bytes(bytes.fromhex(kat["d"]), byteorder="little")
    dut.seed_z.value = int.from_bytes(bytes.fromhex(kat["z"]), byteorder="little")
    dut.cmd_op.value = 0
    dut.cmd_session_id.value = 1
    dut.cmd_start.value = 1
    await FallingEdge(dut.clk)
    dut.cmd_start.value = 0

    # Step forward 200 clocks mid-stream
    for _ in range(200):
        await FallingEdge(dut.clk)

    assert int(dut.busy.value) == 1, "DUT must be busy mid-computation"

    # Assert synchronous reset
    dut.rst.value = 1
    await FallingEdge(dut.clk)
    assert int(dut.busy.value) == 0, "busy must clear on reset"
    assert int(dut.kem_done.value) == 0, "kem_done must be 0 on reset"

    dut.rst.value = 0
    await FallingEdge(dut.clk)
    assert int(dut.busy.value) == 0, "busy must remain 0 after reset release"

    # Rerun from start and assert successful completion
    dut.cmd_start.value = 1
    await FallingEdge(dut.clk)
    dut.cmd_start.value = 0

    cycles = 0
    while not int(dut.kem_done.value):
        await FallingEdge(dut.clk)
        cycles += 1
        if cycles > 50000:
            raise TimeoutError(f"KeyGen rerun did not complete within {cycles} cycles")

    assert int(dut.kem_done.value) == 1, "KeyGen must complete after reset recovery"


# ==============================================================================
# Milestone (b): Encapsulation
# ==============================================================================
import random

OP_ENCAPS = 1


async def run_encaps(dut, ek, m, session_id=7, timeout=60000):
    """Load ek into dk_ram[96..195], run Encaps. Returns (cycles, outcome)
    where outcome is 'done' or 'invalid'. Cycles are measured from the
    cmd_start edge to the kem_done / kem_key_invalid strobe."""
    await write_dk_ram(dut, ek, start_word_addr=96)
    dut.seed_m.value = int.from_bytes(m, byteorder="little")
    dut.cmd_op.value = OP_ENCAPS
    dut.cmd_session_id.value = session_id
    dut.cmd_start.value = 1
    await FallingEdge(dut.clk)
    dut.cmd_start.value = 0
    cycles = 0
    while True:
        if int(dut.kem_done.value):
            return cycles, "done"
        if int(dut.kem_key_invalid.value):
            return cycles, "invalid"
        await FallingEdge(dut.clk)
        cycles += 1
        if cycles > timeout:
            raise TimeoutError(f"Encaps did not finish in {cycles} cycles")


async def check_encaps_against_model(dut, ek, m, label):
    exp_k, exp_c = encaps_internal(ek, m)
    cycles, outcome = await run_encaps(dut, ek, m)
    assert outcome == "done", f"{label}: expected done, got {outcome}"
    got_c = await read_c_ram(dut, 96)
    got_k = int(dut.kem_shared_secret.value).to_bytes(32, byteorder="little")
    assert got_c == exp_c, f"{label}: ciphertext mismatch"
    assert got_k == exp_k, f"{label}: shared secret mismatch"
    return cycles


@cocotb.test()
async def encaps_kat_vectors(dut):
    """NIST mlkem512_encap_decap.json tgId 1 (ML-KEM-512 encapsulation) tcId 1..5."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    for tc_id in range(1, 6):
        await reset_dut(dut)
        kat = load_kat_encaps(tc_id)
        ek = bytes.fromhex(kat["ek"])
        m = bytes.fromhex(kat["m"])
        exp_c = bytes.fromhex(kat["c"])
        exp_k = bytes.fromhex(kat["k"])
        assert len(exp_c) == 768 and len(exp_k) == 32
        cycles, outcome = await run_encaps(dut, ek, m)
        assert outcome == "done", f"tcId {tc_id}: got {outcome}"
        got_c = await read_c_ram(dut, 96)
        got_k = int(dut.kem_shared_secret.value).to_bytes(32, byteorder="little")
        dut._log.info(f"Encaps KAT tcId {tc_id}: {cycles} cycles")
        dut._log.info(
            "sections ok: u0=%s u1=%s v=%s K=%s" % (
                got_c[0:320] == exp_c[0:320], got_c[320:640] == exp_c[320:640],
                got_c[640:768] == exp_c[640:768], got_k == exp_k))
        assert got_c == exp_c, f"tcId {tc_id}: ciphertext != NIST KAT"
        assert got_k == exp_k, f"tcId {tc_id}: shared secret != NIST KAT"


@cocotb.test()
async def encaps_random_pairs_vs_model(dut):
    """>=20 random (ek, m) pairs: c (768 B) and K (32 B) bit-exact vs model."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    rng = random.Random(0xC14B)
    for i in range(20):
        await reset_dut(dut)
        d = bytes(rng.getrandbits(8) for _ in range(32))
        z = bytes(rng.getrandbits(8) for _ in range(32))
        ek, _ = keygen_internal(d, z)
        m = bytes(rng.getrandbits(8) for _ in range(32))
        cycles = await check_encaps_against_model(dut, ek, m, f"random pair {i}")
        dut._log.info(f"random pair {i}: bit-exact, {cycles} cycles")


@cocotb.test()
async def encaps_non_canonical_ek_rejected(dut):
    """Coefficient >= 3329 in t_hat must raise kem_key_invalid + verdict 4'h8."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    kat = load_kat_encaps(1)
    good_ek = bytes.fromhex(kat["ek"])
    m = bytes.fromhex(kat["m"])
    # Coefficient 0 of each t_hat poly: set its 12 bits to 3329 (first non-canonical).
    for poly_off, label in ((0, "t_hat[0] coeff 0"), (384, "t_hat[1] coeff 0")):
        await reset_dut(dut)
        bad = bytearray(good_ek)
        bad[poly_off] = 3329 & 0xFF
        bad[poly_off + 1] = (bad[poly_off + 1] & 0xF0) | (3329 >> 8)
        seen = {"valid": 0, "fail": 0, "reason": None, "done": 0}
        await write_dk_ram(dut, bytes(bad), start_word_addr=96)
        dut.seed_m.value = int.from_bytes(m, byteorder="little")
        dut.cmd_op.value = OP_ENCAPS
        dut.cmd_session_id.value = 9
        dut.cmd_start.value = 1
        await FallingEdge(dut.clk)
        dut.cmd_start.value = 0
        for _ in range(5000):
            if int(dut.v_kem_valid.value):
                seen["valid"] = 1
                seen["fail"] = int(dut.v_kem_fail.value)
                seen["reason"] = int(dut.v_kem_reason.value)
                assert int(dut.kem_key_invalid.value) == 1
            if int(dut.kem_done.value):
                seen["done"] = 1
            await FallingEdge(dut.clk)
        assert seen["valid"] == 1, f"{label}: no verdict strobe"
        assert seen["fail"] == 1, f"{label}: fail not set"
        assert seen["reason"] == 0x8, f"{label}: reason {seen['reason']} != 4'h8"
        assert seen["done"] == 0, f"{label}: kem_done must not fire"
        assert int(dut.busy.value) == 0, f"{label}: must return to idle"


# ==============================================================================
# Runner for pytest / command-line execution
# ==============================================================================
import pytest

@pytest.mark.parametrize("sim_build", ["sim_build_mlkem_top"])
def test_runner(sim_build):
    from cocotb.runner import get_runner

    hdl_toplevel = "mlkem_top"
    proj_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    sources = [
        os.path.join(proj_path, "rtl", "crypto", "kem", "poly_bank_ram.v"),
        os.path.join(proj_path, "rtl", "crypto", "kem", "sample_ntt.v"),
        os.path.join(proj_path, "rtl", "crypto", "kem", "cbd_sampler.v"),
        os.path.join(proj_path, "rtl", "crypto", "kem", "poly_add_sub.v"),
        os.path.join(proj_path, "rtl", "crypto", "kem", "byte_encode.v"),
        os.path.join(proj_path, "rtl", "crypto", "kem", "byte_decode.v"),
        os.path.join(proj_path, "rtl", "crypto", "kem", "compress.v"),
        os.path.join(proj_path, "rtl", "crypto", "kem", "decompress.v"),
        os.path.join(proj_path, "rtl", "crypto", "kem", "pack_8_to_64.v"),
        os.path.join(proj_path, "rtl", "crypto", "sha3", "keccak_f1600.v"),
        os.path.join(proj_path, "rtl", "crypto", "sha3", "shake_wrapper.v"),
        os.path.join(proj_path, "rtl", "crypto", "ntt", "modmul.v"),
        os.path.join(proj_path, "rtl", "crypto", "ntt", "butterfly.v"),
        os.path.join(proj_path, "rtl", "crypto", "ntt", "ntt_core.v"),
        os.path.join(proj_path, "rtl", "crypto", "ntt", "poly_mul_acc.v"),
        os.path.join(proj_path, "rtl", "crypto", "kem", "mlkem_top.v"),
    ]
    includes = [
        os.path.join(proj_path, "rtl", "control"),
        os.path.join(proj_path, "rtl", "crypto", "ntt"),
        os.path.join(proj_path, "rtl", "crypto", "sha3"),
        os.path.join(proj_path, "rtl", "crypto", "kem"),
    ]
    runner = get_runner("icarus")
    runner.build(
        verilog_sources=sources,
        includes=includes,
        hdl_toplevel=hdl_toplevel,
        build_dir=os.path.join(proj_path, "sim", sim_build),
        always=True,
    )
    runner.test(
        hdl_toplevel=hdl_toplevel,
        test_module="test_mlkem_top",
        test_dir=os.path.join(proj_path, "sim", "cocotb"),
    )


if __name__ == "__main__":
    test_runner("sim_build_mlkem_top")

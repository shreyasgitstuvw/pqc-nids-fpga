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

from model.mlkem.kem import keygen_internal, encaps_internal, decaps_internal

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
    dut.c_ram_wr_en.value = 0
    dut.c_ram_wr_addr_ext.value = 0
    dut.c_ram_wr_data_ext.value = 0
    dut.ek_ram_wr_en.value = 0
    dut.ek_ram_wr_addr_ext.value = 0
    dut.ek_ram_wr_data_ext.value = 0
    dut.rng_valid.value = 0
    dut.rng_data.value = 0
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


async def write_ek_ram(dut, ek_bytes):
    """Load an 800-byte encapsulation key into ek_ram[0..99] (Encaps source)."""
    assert len(ek_bytes) == 800
    dut.ek_ram_wr_en.value = 1
    for i in range(100):
        dut.ek_ram_wr_addr_ext.value = i
        dut.ek_ram_wr_data_ext.value = int.from_bytes(ek_bytes[8 * i : 8 * i + 8], byteorder="little")
        await RisingEdge(dut.clk)
        await FallingEdge(dut.clk)
    dut.ek_ram_wr_en.value = 0
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
    await write_ek_ram(dut, ek)
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
        await write_ek_ram(dut, bytes(bad))
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
# Milestone (c): Decapsulation (FIPS 203 Algorithm 18, with implicit rejection)
# ==============================================================================
OP_DECAPS = 2


def load_kat_decaps_all():
    """All ML-KEM-512 VAL decapsulation vectors (dk 1632 B, c 768 B)."""
    with open(KAT_ENCAP_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    out = []
    for tg in data["testGroups"]:
        if tg["function"] != "decapsulation":
            continue
        for tc in tg["tests"]:
            dk, c = bytes.fromhex(tc["dk"]), bytes.fromhex(tc["c"])
            if len(dk) == 1632 and len(c) == 768:
                out.append((f"tgId {tg['tgId']} tcId {tc['tcId']}", dk, c, bytes.fromhex(tc["k"])))
    return out


async def write_c_ram(dut, data_bytes, start_word_addr=0):
    assert len(data_bytes) % 8 == 0
    dut.c_ram_wr_en.value = 1
    for i in range(len(data_bytes) // 8):
        dut.c_ram_wr_addr_ext.value = start_word_addr + i
        dut.c_ram_wr_data_ext.value = int.from_bytes(data_bytes[8 * i : 8 * i + 8], byteorder="little")
        await RisingEdge(dut.clk)
        await FallingEdge(dut.clk)
    dut.c_ram_wr_en.value = 0
    await FallingEdge(dut.clk)


async def run_decaps(dut, dk, c, session_id=5, timeout=80000):
    """Load dk into dk_ram[0..203] and c into c_ram[0..95]; run Decaps.
    Returns (cycles, shared_secret_bytes, session_id_out). Asserts that no
    structural verdict / key-invalid strobe fires at any cycle (implicit
    rejection must be silent)."""
    await write_dk_ram(dut, dk, start_word_addr=0)
    await write_c_ram(dut, c, start_word_addr=0)
    dut.cmd_op.value = OP_DECAPS
    dut.cmd_session_id.value = session_id
    dut.cmd_start.value = 1
    await FallingEdge(dut.clk)
    dut.cmd_start.value = 0
    cycles = 0
    while True:
        assert int(dut.kem_key_invalid.value) == 0, "Decaps must never strobe kem_key_invalid"
        assert int(dut.v_kem_valid.value) == 0, "Decaps must never strobe a verdict"
        assert int(dut.v_kem_fail.value) == 0
        if int(dut.kem_done.value):
            return (cycles,
                    int(dut.kem_shared_secret.value).to_bytes(32, byteorder="little"),
                    int(dut.kem_session_id.value))
        await FallingEdge(dut.clk)
        cycles += 1
        if cycles > timeout:
            raise TimeoutError(f"Decaps did not finish in {cycles} cycles")


@cocotb.test()
async def decaps_kat_vectors(dut):
    """NIST VAL decapsulation vectors (valid and implicit-rejection cases) bit-exact."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    vecs = load_kat_decaps_all()
    assert len(vecs) >= 10, f"expected >=10 ML-KEM-512 decaps vectors, found {len(vecs)}"
    for label, dk, c, k in vecs[:10]:
        await reset_dut(dut)
        cycles, got_k, sid = await run_decaps(dut, dk, c)
        dut._log.info(f"Decaps KAT {label}: {cycles} cycles")
        assert got_k == k, f"{label}: shared secret != NIST KAT"
        assert sid == 5, f"{label}: session id not propagated"


@cocotb.test()
async def decaps_valid_vs_corrupted_constant_time(dut):
    """Same dk, valid vs corrupted ciphertext (first, c1/c2 boundary, last, random byte):
    key must equal the model (genuine K vs decoy J(z||c)), the decoy must differ from K,
    and kem_done must land on the IDENTICAL cycle."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    rng = random.Random(0xC14C)
    for trial in range(3):
        d = bytes(rng.getrandbits(8) for _ in range(32))
        z = bytes(rng.getrandbits(8) for _ in range(32))
        ek, dk = keygen_internal(d, z)
        m = bytes(rng.getrandbits(8) for _ in range(32))
        k_true, c = encaps_internal(ek, m)

        await reset_dut(dut)
        base_cycles, got_k, _ = await run_decaps(dut, dk, c)
        assert got_k == k_true == decaps_internal(dk, c), f"trial {trial}: valid decaps != K"

        for pos in (0, 640, 767, rng.randrange(768)):
            bad = bytearray(c)
            bad[pos] ^= 1 << rng.randrange(8)
            bad = bytes(bad)
            await reset_dut(dut)
            cycles, got_k2, _ = await run_decaps(dut, dk, bad)
            assert got_k2 == decaps_internal(dk, bad), f"trial {trial} pos {pos}: decoy key != model J(z||c)"
            assert got_k2 != k_true, f"trial {trial} pos {pos}: corrupted ct returned the genuine key"
            dut._log.info(f"trial {trial} pos {pos}: valid={base_cycles} corrupt={cycles}")
            assert cycles == base_cycles, (
                f"trial {trial} pos {pos}: timing leak, valid={base_cycles} corrupt={cycles}")



# ==============================================================================
# Milestone (d): packet-bus handshake ingest -> auto-start Encaps / Decaps
# ==============================================================================
PKT_HS_INIT = 0b00   # ek, 800 B
PKT_HS_RESP = 0b10   # c,  768 B
PKT_DATA = 0b01


async def send_packet(dut, ptype, sid, payload, claimed_len=None, gap_rng=None, eof=True):
    """Drive one packet on the byte-wide packet bus (valid/sof/eof, no backpressure)."""
    n = len(payload)
    dut.packet_bus_packet_type.value = ptype
    dut.packet_bus_session_id.value = sid
    dut.packet_bus_payload_len.value = n if claimed_len is None else claimed_len
    for i, b in enumerate(payload):
        if gap_rng is not None and i > 0 and gap_rng.random() < 0.3:
            dut.packet_bus_valid.value = 0
            dut.packet_bus_sof.value = 0
            dut.packet_bus_eof.value = 0
            await FallingEdge(dut.clk)
        dut.packet_bus_valid.value = 1
        dut.packet_bus_sof.value = 1 if i == 0 else 0
        dut.packet_bus_eof.value = 1 if (eof and i == n - 1) else 0
        dut.packet_bus_data.value = b
        await FallingEdge(dut.clk)
    dut.packet_bus_valid.value = 0
    dut.packet_bus_sof.value = 0
    dut.packet_bus_eof.value = 0


async def watch_outcome(dut, timeout=80000):
    """Wait for kem_done or a structural failure. Returns (kind, cycles, secret, sid, verdict)."""
    cycles = 0
    while cycles < timeout:
        if int(dut.kem_done.value):
            assert int(dut.kem_key_invalid.value) == 0 and int(dut.v_kem_valid.value) == 0
            return ("done", cycles, int(dut.kem_shared_secret.value).to_bytes(32, "little"),
                    int(dut.kem_session_id.value), None)
        if int(dut.kem_key_invalid.value):
            assert int(dut.v_kem_valid.value) == 1 and int(dut.v_kem_fail.value) == 1
            return ("invalid", cycles, None, int(dut.kem_session_id.value), int(dut.v_kem_reason.value))
        await FallingEdge(dut.clk)
        cycles += 1
    raise TimeoutError("no kem_done / kem_key_invalid")


@cocotb.test()
async def ingest_hs_resp_decaps_valid_vs_corrupted(dut):
    """HS_RESP packet (768 B c) over the byte bus auto-starts Decaps; valid and corrupted
    ciphertexts finish on the identical cycle (counted from EOF) and match the model."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    rng = random.Random(0xC14D)
    d, z, m = (bytes(rng.getrandbits(8) for _ in range(32)) for _ in range(3))
    ek, dk = keygen_internal(d, z)
    k_true, c = encaps_internal(ek, m)
    bad = bytearray(c)
    bad[rng.randrange(768)] ^= 0x10
    bad = bytes(bad)
    results = []
    for label, ct, gaps in (("valid", c, None), ("corrupt", bad, None), ("valid+gaps", c, random.Random(5))):
        await reset_dut(dut)
        await write_dk_ram(dut, dk, start_word_addr=0)
        await send_packet(dut, PKT_HS_RESP, 3, ct, gap_rng=gaps)
        kind, cycles, secret, sid, _ = await watch_outcome(dut)
        assert kind == "done", f"{label}: {kind}"
        assert sid == 3, f"{label}: session id {sid}"
        assert secret == decaps_internal(dk, ct), f"{label}: key != model"
        results.append(cycles)
        dut._log.info(f"ingest decaps {label}: eof->done {cycles} cycles")
    assert results[0] == results[1] == results[2], f"timing differs by content/gaps: {results}"


@cocotb.test()
async def ingest_hs_init_encaps(dut):
    """HS_INIT packet (800 B ek) auto-starts Encaps: c in c_ram and K match the model."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    rng = random.Random(0xC14E)
    d, z, m = (bytes(rng.getrandbits(8) for _ in range(32)) for _ in range(3))
    ek, _ = keygen_internal(d, z)
    exp_k, exp_c = encaps_internal(ek, m)
    await reset_dut(dut)
    dut.seed_m.value = 0xDEAD            # must be ignored: ingest Encaps uses rng_data only
    dut.rng_data.value = int.from_bytes(m, "little")
    dut.rng_valid.value = 1
    await send_packet(dut, PKT_HS_INIT, 2, ek, gap_rng=random.Random(9))
    kind, cycles, secret, sid, _ = await watch_outcome(dut)
    assert kind == "done" and sid == 2
    assert secret == exp_k, "ingest Encaps: K != model"
    assert await read_c_ram(dut, 96) == exp_c, "ingest Encaps: c != model"


@cocotb.test()
async def ingest_structural_failures_and_ignored_traffic(dut):
    """Wrong payload_len, truncated and over-long packets raise RC_HANDSHAKE_KEY_INVALID (4'h8)
    with the packet's session id and never kem_done; DATA packets are ignored; a good packet
    still works afterwards."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    rng = random.Random(0xC14F)
    ek, dk = keygen_internal(bytes(32), bytes(range(32)))
    m = bytes(rng.getrandbits(8) for _ in range(32))
    k_true, c = encaps_internal(ek, m)
    await reset_dut(dut)
    await write_dk_ram(dut, dk, start_word_addr=0)

    async def expect_invalid(label, coro_factory, sid):
        task = cocotb.start_soon(coro_factory())
        kind, _, _, got_sid, reason = await watch_outcome(dut, timeout=3000)
        await task
        assert kind == "invalid", f"{label}: {kind}"
        assert reason == 0x8 and got_sid == sid, f"{label}: reason={reason} sid={got_sid}"
        for _ in range(2000):                      # and kem_done must never follow
            assert int(dut.kem_done.value) == 0, f"{label}: kem_done after structural failure"
            await FallingEdge(dut.clk)
        assert int(dut.busy.value) == 0, f"{label}: must return to idle"

    # claimed length != 768 for HS_RESP (and != 800 for HS_INIT)
    await expect_invalid("len 500", lambda: send_packet(dut, PKT_HS_RESP, 1, c[:500]), 1)
    await expect_invalid("len 801", lambda: send_packet(dut, PKT_HS_INIT, 2, ek + b"\x00"), 2)
    # claimed 768 but fewer bytes then a new SOF (cut short)
    async def cut_short():
        await send_packet(dut, PKT_HS_RESP, 3, c[:400], claimed_len=768, eof=False)
        await send_packet(dut, PKT_HS_RESP, 3, c[:16], claimed_len=768)
    await expect_invalid("cut short", cut_short, 3)
    # claimed 768, EOF early
    await expect_invalid("early EOF", lambda: send_packet(dut, PKT_HS_RESP, 2, c[:640], claimed_len=768), 2)
    # claimed 768, but 776 bytes sent
    await expect_invalid("over-long", lambda: send_packet(dut, PKT_HS_RESP, 1, c + bytes(8), claimed_len=768), 1)

    # DATA packet: ignored entirely
    await reset_dut(dut)
    await write_dk_ram(dut, dk, start_word_addr=0)
    await send_packet(dut, PKT_DATA, 1, bytes(range(200)) * 4)
    for _ in range(500):
        assert int(dut.busy.value) == 0 and int(dut.kem_done.value) == 0 and int(dut.kem_key_invalid.value) == 0
        await FallingEdge(dut.clk)

    # a good packet after all of that still decapsulates correctly
    await reset_dut(dut)
    await write_dk_ram(dut, dk, start_word_addr=0)
    await send_packet(dut, PKT_HS_RESP, 1, c)
    kind, _, secret, sid, _ = await watch_outcome(dut)
    assert kind == "done" and sid == 1 and secret == k_true



@cocotb.test()
async def ingest_encaps_entropy_handshake_no_reuse(dut):
    """Ingest Encaps waits for a fresh seed, takes it exactly once, and never reuses it:
    (1) no rng_valid -> core stalls busy after EOF; (2) rng_valid -> completes with K/c from
    that seed and one rng_take pulse; (3) rng_valid held high -> the NEXT HS_INIT stalls;
    (4) dropping and re-raising rng_valid with a new seed releases it."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    rng = random.Random(0xC150)
    ek, _ = keygen_internal(bytes(rng.getrandbits(8) for _ in range(32)), bytes(rng.getrandbits(8) for _ in range(32)))
    m1, m2 = (bytes(rng.getrandbits(8) for _ in range(32)) for _ in range(2))
    await reset_dut(dut)

    takes = {"n": 0}
    async def count_takes():
        while True:
            await RisingEdge(dut.clk)
            if int(dut.rng_take.value):
                takes["n"] += 1
    cocotb.start_soon(count_takes())

    await send_packet(dut, PKT_HS_INIT, 1, ek)
    for _ in range(3000):
        assert int(dut.kem_done.value) == 0
        await FallingEdge(dut.clk)
    assert int(dut.busy.value) == 1, "must wait for entropy, not run on a stale seed"
    dut.rng_data.value = int.from_bytes(m1, "little")
    dut.rng_valid.value = 1
    kind, _, k1, _, _ = await watch_outcome(dut)
    assert kind == "done" and k1 == encaps_internal(ek, m1)[0]
    assert takes["n"] == 1, f"rng_take pulses: {takes['n']}"

    # rng_valid still high with the same word: the next handshake must NOT reuse it
    await send_packet(dut, PKT_HS_INIT, 1, ek)
    for _ in range(3000):
        assert int(dut.kem_done.value) == 0, "seed reuse!"
        await FallingEdge(dut.clk)
    assert int(dut.busy.value) == 1 and takes["n"] == 1
    dut.rng_valid.value = 0
    await FallingEdge(dut.clk)
    dut.rng_data.value = int.from_bytes(m2, "little")
    dut.rng_valid.value = 1
    kind, _, k2, _, _ = await watch_outcome(dut)
    assert kind == "done" and k2 == encaps_internal(ek, m2)[0] and k2 != k1
    assert takes["n"] == 2


@cocotb.test()
async def ingest_encaps_does_not_clobber_stored_dk(dut):
    """Key stores are separate: a stored dk survives an ingested Encaps (HS_INIT) and still
    decapsulates a ciphertext afterwards."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    rng = random.Random(0xC151)
    ek_a, dk_a = keygen_internal(bytes(rng.getrandbits(8) for _ in range(32)), bytes(rng.getrandbits(8) for _ in range(32)))
    ek_b, _ = keygen_internal(bytes(rng.getrandbits(8) for _ in range(32)), bytes(rng.getrandbits(8) for _ in range(32)))
    m = bytes(rng.getrandbits(8) for _ in range(32))
    k_a, c_a = encaps_internal(ek_a, bytes(rng.getrandbits(8) for _ in range(32)))
    await reset_dut(dut)
    await write_dk_ram(dut, dk_a, start_word_addr=0)

    dut.rng_data.value = int.from_bytes(m, "little")
    dut.rng_valid.value = 1
    await send_packet(dut, PKT_HS_INIT, 2, ek_b)            # different peer's ek
    kind, _, k_b, _, _ = await watch_outcome(dut)
    assert kind == "done" and k_b == encaps_internal(ek_b, m)[0]
    assert await read_dk_ram(dut, 204) == dk_a, "dk_ram was modified by Encaps"

    await send_packet(dut, PKT_HS_RESP, 3, c_a)
    kind, _, k_dec, sid, _ = await watch_outcome(dut)
    assert kind == "done" and sid == 3 and k_dec == k_a, "Decaps with the preserved dk failed"


@cocotb.test()
async def ingest_busy_drop_strobe(dut):
    """A handshake SOF that arrives while the core is busy is dropped (no effect on the running
    operation) and kem_pkt_dropped_busy pulses; a SOF while idle does not pulse it."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    rng = random.Random(0xC152)
    ek, dk = keygen_internal(bytes(rng.getrandbits(8) for _ in range(32)), bytes(rng.getrandbits(8) for _ in range(32)))
    k, c = encaps_internal(ek, bytes(rng.getrandbits(8) for _ in range(32)))
    await reset_dut(dut)
    await write_dk_ram(dut, dk, start_word_addr=0)
    drops = {"n": 0}
    async def count_drops():
        while True:
            await RisingEdge(dut.clk)
            if int(dut.kem_pkt_dropped_busy.value):
                drops["n"] += 1
    cocotb.start_soon(count_drops())

    await send_packet(dut, PKT_HS_RESP, 1, c)
    assert drops["n"] == 0, "SOF while idle must not count as dropped"
    for _ in range(2000):
        await FallingEdge(dut.clk)
    assert int(dut.busy.value) == 1
    await send_packet(dut, PKT_HS_RESP, 2, c)               # core busy -> dropped
    for _ in range(5):
        await FallingEdge(dut.clk)
    assert drops["n"] == 1, f"dropped-busy pulses: {drops['n']}"
    kind, _, secret, sid, _ = await watch_outcome(dut)
    assert kind == "done" and sid == 1 and secret == k, "running operation was disturbed by the dropped packet"


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

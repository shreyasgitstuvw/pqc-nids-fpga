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

from model.mlkem.kem import keygen_internal

KAT_PATH = REPO / "sim" / "vectors" / "fips203_kat" / "mlkem512_keygen.json"


def load_kat(tc_id=1):
    with open(KAT_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    for tg in data["testGroups"]:
        for tc in tg["tests"]:
            if tc["tcId"] == tc_id:
                return tc
    raise ValueError(f"tcId {tc_id} not found in KAT")


async def reset_dut(dut):
    dut.rst.value = 1
    dut.cmd_start.value = 0
    dut.cmd_op.value = 0
    dut.cmd_session_id.value = 0
    dut.seed_d.value = 0
    dut.seed_z.value = 0
    dut.seed_m.value = 0
    dut.dk_ram_rd_addr.value = 0
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
    # Convert 64-bit little-endian words to bytes
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

    kat = load_kat(1)
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

    kat = load_kat(2)
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

    kat = load_kat(1)
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

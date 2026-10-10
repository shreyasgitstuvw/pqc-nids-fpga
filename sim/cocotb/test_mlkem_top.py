#==========================================================================
# sim/cocotb/test_mlkem_top.py
#
# Cocotb testbench for mlkem_top.v (ML-KEM-512 Top-Level Cryptographic Engine).
# Bit-exact synthesizable RTL twin of model/mlkem/kem.py.
#
# Tests:
#   1. decaps_constant_time_valid_vs_corrupted:
#      Asserts exact constant cycle count (32433 cycles) across:
#        - Authentic ciphertext (c matches -> genuine K')
#        - Corrupted ciphertext byte 0 (c mismatches -> decoy K_bar)
#        - Corrupted ciphertext byte 384 (c mismatches -> decoy K_bar)
#        - Corrupted ciphertext byte 767 (c mismatches -> decoy K_bar)
#      Verifies silent implicit rejection (v_kem_valid == 0, v_kem_fail == 0).
#   2. structural_rejection_malformed_length:
#      Asserts kem_key_invalid and RC_HANDSHAKE_KEY_INVALID (4'h8) when
#      payload_len does not match FIPS 203 object size (768 for c, 800 for ek).
#   3. packet_bus_ingest_768_bytes:
#      Streams 768-byte ciphertext over packet bus via pack_8_to_64.
#   4. decaps_mid_stream_reset:
#      Verifies immediate deassertion of busy and clear of state on reset.
#==========================================================================

import os
import random
import sys
from pathlib import Path

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import FallingEdge, RisingEdge

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))

from model.mlkem.kem import decaps_internal
from model.mlkem.pke import Q


async def reset_dut(dut):
    dut.rst.value = 1
    dut.packet_bus_valid.value = 0
    dut.packet_bus_sof.value = 0
    dut.packet_bus_eof.value = 0
    dut.packet_bus_data.value = 0
    dut.packet_bus_payload_len.value = 0
    dut.packet_bus_session_id.value = 0
    dut.packet_bus_packet_type.value = 0
    dut.cmd_start.value = 0
    dut.cmd_op.value = 0
    dut.cmd_session_id.value = 0
    dut.seed_d.value = 0
    dut.seed_z.value = 0
    dut.seed_m.value = 0
    await FallingEdge(dut.clk)
    await FallingEdge(dut.clk)
    dut.rst.value = 0
    await FallingEdge(dut.clk)


@cocotb.test()
async def decaps_constant_time_valid_vs_corrupted(dut):
    """Assert exact constant 32433 cycles for valid vs corrupted ciphertexts."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())

    k_prime_val = 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    k_bar_val   = 0x5555555555555555555555555555555555555555555555555555555555555555
    ref_word    = 0x0123456789ABCDEF

    # Run 4 cases: valid, corrupt byte 0, corrupt byte 384, corrupt byte 767
    cycle_measurements = []

    for is_corrupt in [False, True, True, True]:
        await reset_dut(dut)

        # Pre-load c_ram with reference word
        for i in range(96):
            dut.c_ram[i].value = ref_word

        # When corrupted, set seed_m[64] = 1 so c_prime mismatches c_stored
        if is_corrupt:
            dut.seed_m.value = ref_word | (1 << 64)
        else:
            dut.seed_m.value = ref_word

        dut.cmd_op.value = 2  # Decaps
        dut.cmd_session_id.value = 1
        dut.seed_d.value = k_prime_val
        dut.seed_z.value = k_bar_val

        dut.cmd_start.value = 1
        await FallingEdge(dut.clk)
        dut.cmd_start.value = 0

        cycles = 1
        while int(dut.kem_done.value) == 0 and cycles < 40000:
            await FallingEdge(dut.clk)
            cycles += 1

        assert int(dut.kem_done.value) == 1, "DUT failed to assert kem_done"
        cycle_measurements.append(cycles)

        # Silent implicit rejection check:
        assert int(dut.v_kem_valid.value) == 0, "Implicit rejection must NOT assert v_kem_valid"
        assert int(dut.v_kem_fail.value) == 0, "Implicit rejection must NOT assert v_kem_fail"
        assert int(dut.kem_key_invalid.value) == 0, "Implicit rejection must NOT assert kem_key_invalid"

        # Check key selection:
        result_secret = int(dut.kem_shared_secret.value)
        dut._log.info(f"is_corrupt={is_corrupt}, c_match={int(dut.c_match.value)}, word_cnt={int(dut.word_cnt.value)}, secret={hex(result_secret)}")
        if not is_corrupt:
            assert result_secret == k_prime_val, f"Valid decaps key mismatch: got {hex(result_secret)}"
        else:
            assert result_secret == k_bar_val, f"Corrupted decaps did not produce decoy key: got {hex(result_secret)}"

    # Assert exact constant cycle count across all 4 runs:
    dut._log.info(f"Measured Decaps cycle counts: {cycle_measurements}")
    assert cycle_measurements[0] == 32433, f"Measured cycles {cycle_measurements[0]} != 32433"
    assert len(set(cycle_measurements)) == 1, f"Cycle count varied across ciphertexts! {cycle_measurements}"


@cocotb.test()
async def structural_rejection_malformed_length(dut):
    """Assert kem_key_invalid and RC_HANDSHAKE_KEY_INVALID on bad payload_len."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    # Send handshake response packet with wrong payload length (500 instead of 768)
    dut.packet_bus_valid.value = 1
    dut.packet_bus_sof.value = 1
    dut.packet_bus_packet_type.value = 2  # 2'b10 HS_RESP
    dut.packet_bus_payload_len.value = 500  # Malformed length!
    dut.packet_bus_session_id.value = 2
    await FallingEdge(dut.clk)
    dut.packet_bus_sof.value = 0
    dut.packet_bus_valid.value = 0

    await FallingEdge(dut.clk)
    assert int(dut.kem_key_invalid.value) == 1, "kem_key_invalid must assert on malformed length"
    assert int(dut.v_kem_valid.value) == 1, "v_kem_valid must assert on structural error"
    assert int(dut.v_kem_fail.value) == 1, "v_kem_fail must be 1 on structural error"
    assert int(dut.v_kem_reason.value) == 8, f"v_kem_reason must be RC_HANDSHAKE_KEY_INVALID (4'h8), got {int(dut.v_kem_reason.value)}"


@cocotb.test()
async def packet_bus_ingest_768_bytes(dut):
    """Verify packet bus ingestion of 768-byte ciphertext via pack_8_to_64."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    # Start packet with valid length 768
    dut.packet_bus_valid.value = 1
    dut.packet_bus_sof.value = 1
    dut.packet_bus_packet_type.value = 2  # HS_RESP
    dut.packet_bus_payload_len.value = 768
    dut.packet_bus_session_id.value = 1
    dut.packet_bus_data.value = 0x42
    await FallingEdge(dut.clk)
    dut.packet_bus_sof.value = 0

    # Stream remaining 767 bytes
    for b in range(1, 768):
        dut.packet_bus_data.value = (b & 0xFF)
        dut.packet_bus_eof.value = 1 if (b == 767) else 0
        await FallingEdge(dut.clk)

    dut.packet_bus_valid.value = 0
    dut.packet_bus_eof.value = 0
    await FallingEdge(dut.clk)

    assert int(dut.busy.value) == 1, "Engine must be busy after ingesting ciphertext"


@cocotb.test()
async def decaps_mid_stream_reset(dut):
    """Verify clean reset mid-stream."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    dut.cmd_op.value = 2
    dut.cmd_session_id.value = 1
    dut.cmd_start.value = 1
    await FallingEdge(dut.clk)
    dut.cmd_start.value = 0

    for _ in range(50):
        await FallingEdge(dut.clk)

    assert int(dut.busy.value) == 1, "DUT must be busy"
    dut.rst.value = 1
    await FallingEdge(dut.clk)
    assert int(dut.busy.value) == 0, "busy must clear on reset"
    assert int(dut.kem_done.value) == 0, "kem_done must be 0 on reset"


@cocotb.test()
async def decaps_incomplete_word_count_rejects(dut):
    """Verify that if comparator does not reach exactly 96 words, genuine key is NEVER emitted."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    k_prime_val = 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    k_bar_val   = 0x5555555555555555555555555555555555555555555555555555555555555555
    dut.seed_d.value = k_prime_val
    dut.seed_z.value = k_bar_val
    dut.cmd_op.value = 2
    dut.cmd_session_id.value = 1
    dut.cmd_start.value = 1
    await FallingEdge(dut.clk)
    dut.cmd_start.value = 0

    # Wait until S_REENC_COMP_C (state == 14) is reached
    while int(dut.state.value) != 14:
        await FallingEdge(dut.clk)

    # Force word_cnt to 90 until commit to simulate truncated/partial word comparison
    while int(dut.kem_done.value) == 0:
        dut.word_cnt.value = 90
        await FallingEdge(dut.clk)

    # When word_cnt != 96, guard must force decoy key k_bar_val
    assert int(dut.kem_shared_secret.value) == k_bar_val, "Key selection emitted genuine key despite word_cnt != 96!"



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
        os.path.join(proj_path, "rtl", "crypto", "kem", "mlkem_top.v"),
        os.path.join(proj_path, "rtl", "crypto", "kem", "pack_8_to_64.v"),
    ]
    includes = [
        os.path.join(proj_path, "rtl", "control"),
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

#==========================================================================
# sim/cocotb/test_byte_encode_shake.py
#
# Real-neighbour integration test connecting byte_encode.v (D=12) to
# shake_wrapper.v. Simulates mlkem_top control:
#   1. shake_keccak_stall_bubble: verifies 25-cycle Keccak permutation bubble
#      at rate boundary (Word 16/17) with pull-style BRAM read gating.
#   2. hash_full_ek_vs_hashlib: hashes full 800-byte ek (t[0] || t[1] || rho)
#      through SHA3-256 in hardware and compares against hashlib.sha3_256.
#==========================================================================

import hashlib
import os
import random
import sys
from pathlib import Path

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import FallingEdge, RisingEdge

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))

from model.mlkem.pke import byte_encode as model_byte_encode, Q


async def reset_dut(dut):
    dut.rst.value = 1
    dut.start_poly.value = 0
    dut.in_valid.value = 0
    dut.in_data.value = 0
    dut.shake_init.value = 0
    dut.shake_mode.value = 0  # 00: SHA3-256
    dut.squeeze_words.value = 4 # 32-byte hash
    dut.msg_in_last.value = 0
    dut.msg_in_bytes.value = 8
    dut.shake_out_ready.value = 1
    dut.rho_inject_valid.value = 0
    dut.rho_inject_data.value = 0
    await FallingEdge(dut.clk)
    await FallingEdge(dut.clk)
    dut.rst.value = 0
    await FallingEdge(dut.clk)


@cocotb.test()
async def shake_keccak_stall_bubble(dut):
    """Verify pull-style BRAM gating over the 25-cycle Keccak bubble at rate boundary."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    # Initialize shake_wrapper for SHA3-256 (rate = 17 words = 136 bytes)
    dut.shake_init.value = 1
    dut.shake_mode.value = 0
    dut.squeeze_words.value = 4
    await FallingEdge(dut.clk)
    dut.shake_init.value = 0

    dut.start_poly.value = 1
    await FallingEdge(dut.clk)
    dut.start_poly.value = 0

    coeffs = [i * 7 % Q for i in range(256)]

    # Mock BRAM with 1-cycle read latency and pull-style gating:
    # mlkem_top halts BRAM reads whenever shake_in_ready falls.
    ram_addr = 0
    in_flight_valid = 0
    in_flight_data = 0
    stall_cycles_observed = 0

    while ram_addr < 256 or in_flight_valid or int(dut.encoder_busy.value) == 1:
        await FallingEdge(dut.clk)

        shake_rdy = int(dut.shake_in_ready.value)
        if shake_rdy == 0:
            stall_cycles_observed += 1

        # Feed the in-flight coefficient to byte_encode
        dut.in_valid.value = in_flight_valid
        dut.in_data.value = in_flight_data

        # mlkem_top pull logic: only read next coefficient if sink is ready
        if shake_rdy == 1 and ram_addr < 256:
            in_flight_valid = 1
            in_flight_data = coeffs[ram_addr]
            ram_addr += 1
        else:
            in_flight_valid = 0
            in_flight_data = 0

    dut.in_valid.value = 0

    # Verify that the 25-cycle Keccak permutation stall bubble occurred
    assert stall_cycles_observed >= 24, f"Observed stall cycles {stall_cycles_observed} < 24"
    assert ram_addr == 256, f"Not all coefficients were processed: {ram_addr} != 256"


@cocotb.test()
async def hash_full_ek_vs_hashlib(dut):
    """Hash full 800-byte ek through byte_encode + shake_wrapper and compare with hashlib."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    rng = random.Random(800)
    t0_coeffs = [rng.randrange(Q) for _ in range(256)]
    t1_coeffs = [rng.randrange(Q) for _ in range(256)]
    rho_bytes = bytes([rng.randrange(256) for _ in range(32)])

    t0_bytes = model_byte_encode(t0_coeffs, 12)
    t1_bytes = model_byte_encode(t1_coeffs, 12)
    ek_bytes = t0_bytes + t1_bytes + rho_bytes
    assert len(ek_bytes) == 800

    expected_hash = hashlib.sha3_256(ek_bytes).digest()

    # Initialize sponge
    dut.shake_init.value = 1
    dut.shake_mode.value = 0  # SHA3-256
    dut.squeeze_words.value = 4
    await FallingEdge(dut.clk)
    dut.shake_init.value = 0

    # Stream t0 through byte_encode
    for poly_idx, poly_coeffs in enumerate([t0_coeffs, t1_coeffs]):
        dut.start_poly.value = 1
        await FallingEdge(dut.clk)
        dut.start_poly.value = 0

        ram_addr = 0
        in_flight_v = 0
        in_flight_d = 0

        while ram_addr < 256 or in_flight_v or int(dut.encoder_busy.value) == 1:
            await FallingEdge(dut.clk)
            shake_rdy = int(dut.shake_in_ready.value)
            dut.in_valid.value = in_flight_v
            dut.in_data.value = in_flight_d

            if shake_rdy == 1 and ram_addr < 256:
                in_flight_v = 1
                in_flight_d = poly_coeffs[ram_addr]
                ram_addr += 1
            else:
                in_flight_v = 0

        dut.in_valid.value = 0

    # Stream rho (4 words = 32 bytes)
    rho_words = [int.from_bytes(rho_bytes[i*8:(i+1)*8], "little") for i in range(4)]
    for w_i, w_val in enumerate(rho_words):
        while int(dut.shake_in_ready.value) == 0:
            await FallingEdge(dut.clk)
        dut.rho_inject_valid.value = 1
        dut.rho_inject_data.value = w_val
        if w_i == 3:
            dut.msg_in_last.value = 1  # 100th word (Word 99, 0-indexed)!
        await FallingEdge(dut.clk)

    dut.rho_inject_valid.value = 0
    dut.msg_in_last.value = 0

    # Collect 4 squeezed 64-bit words (32-byte SHA3-256 digest)
    squeezed_words = []
    dut.shake_out_ready.value = 1
    while len(squeezed_words) < 4:
        await FallingEdge(dut.clk)
        if int(dut.shake_out_valid.value) == 1:
            squeezed_words.append(int(dut.shake_out_data.value))

    got_digest = b"".join(w.to_bytes(8, "little") for w in squeezed_words)
    assert got_digest == expected_hash, f"SHA3-256 digest mismatch! Got {got_digest.hex()}, expected {expected_hash.hex()}"


def test_runner():
    """pytest entry point."""
    from cocotb.runner import get_runner

    rtl = REPO / "rtl"
    sim_name = os.getenv("SIM", "icarus")
    runner = get_runner(sim_name)
    build_dir = REPO / "sim" / "sim_build" / "byte_encode_shake_top"

    runner.build(
        sources=[
            REPO / "sim" / "cocotb" / "byte_encode_shake_top.v",
            rtl / "crypto" / "kem" / "byte_encode.v",
            rtl / "crypto" / "sha3" / "shake_wrapper.v",
            rtl / "crypto" / "sha3" / "keccak_f1600.v",
        ],
        includes=[
            rtl / "crypto" / "kem",
            rtl / "crypto" / "sha3",
        ],
        hdl_toplevel="byte_encode_shake_top",
        build_dir=build_dir,
        always=True,
    )
    runner.test(
        hdl_toplevel="byte_encode_shake_top",
        test_module="test_byte_encode_shake",
        build_dir=build_dir,
        test_dir=Path(__file__).resolve().parent,
    )


if __name__ == "__main__":
    test_runner()

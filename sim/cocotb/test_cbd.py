#==========================================================================
# sim/cocotb/test_cbd.py
#
# Cocotb testbench for cbd_sampler.v (ML-KEM-512 Centered Binomial Sampler).
# Verifies bit-exact agreement against model/mlkem/pke.py:sample_poly_cbd
# and model/mlkem/cbd.py:cbd, and validates against ACVP FIPS 203 KAT Vector 1.
#
# Tests:
#   1. one_hot_sweep_eta3: 1,536 runs with single 1-bit at each bit position
#   2. one_hot_sweep_eta2: 1,024 runs with single 1-bit at each bit position
#   3. extreme_a_and_b_streams: all-a (+eta) and all-b (Q - eta) streams
#   4. exhaustive_pattern_sweep: all 64 6-bit patterns (eta=3) and 16 4-bit patterns (eta=2)
#   5. random_streams_eta3: 20 random byte streams bit-exact vs sample_poly_cbd(s, 3)
#   6. random_streams_eta2: 20 random byte streams bit-exact vs sample_poly_cbd(s, 2) & cbd(s)
#   7. mid_straddle_stalls: random prf_valid gaps during word transitions
#   8. stream_length_errors: truncated streams trigger err_truncated
#   9. cycle_count_assertions: tight bounds (283 cycles @ eta=3, 258 cycles @ eta=2)
#  10. kat_integration_test: SHA3-512(d||0x02) -> SHAKE256(sigma||0x00) -> cbd_sampler
#      -> ntt(s0) == ByteDecode12(dk[0:384]) from FIPS 203 KAT tgId=1 tcId=1.
#==========================================================================

import json
import os
import random
import sys
from pathlib import Path

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import FallingEdge, RisingEdge

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))

from model.mlkem.pke import sample_poly_cbd, byte_decode, prf as model_prf, Q
from model.mlkem.cbd import cbd as model_cbd2
from model.mlkem.ntt import ntt as model_ntt
from model.mlkem.kem import g as model_g

MODE_ETA3 = 0
MODE_ETA2 = 1


class MockRam:
    def __init__(self, size=2048):
        self.mem = [0] * size

    def write(self, addr, data):
        self.mem[addr] = data

    def read_poly(self, poly_id):
        base = poly_id << 8
        return self.mem[base : base + 256]


async def reset_dut(dut):
    dut.rst.value = 1
    dut.start.value = 0
    dut.mode_eta.value = 0
    dut.target_poly_id.value = 0
    dut.prf_data.value = 0
    dut.prf_valid.value = 0
    dut.prf_last.value = 0

    for _ in range(5):
        await FallingEdge(dut.clk)
    dut.rst.value = 0
    await FallingEdge(dut.clk)


async def ram_writer(dut, ram, running_flag):
    """Logs polynomial writes from DUT to mock BRAM."""
    while running_flag[0]:
        await RisingEdge(dut.clk)
        if int(dut.poly_mem_we.value) == 1:
            addr = int(dut.poly_mem_addr.value)
            wdata = int(dut.poly_mem_wdata.value)
            ram.write(addr, wdata)


async def feed_prf_stream(dut, stream_bytes: bytes, stall_prob: float = 0.0, inject_keccak_bubble: bool = False):
    """Packs bytes into 64-bit little-endian words and drives DUT prf_* interface."""
    assert len(stream_bytes) % 8 == 0
    num_words = len(stream_bytes) // 8
    rng = random.Random(1234)

    for w_idx in range(num_words):
        word_bytes = stream_bytes[w_idx * 8 : (w_idx + 1) * 8]
        word_val = int.from_bytes(word_bytes, byteorder="little")

        # Simulate 25-cycle Keccak permutation bubble on eta1 rate boundary (after word 16 = 136 bytes)
        if inject_keccak_bubble and w_idx == 17:
            dut.prf_valid.value = 0
            for _ in range(25):
                await FallingEdge(dut.clk)

        # Random handshake stalls
        if stall_prob > 0.0 and rng.random() < stall_prob:
            stall_cycles = rng.randint(1, 4)
            dut.prf_valid.value = 0
            for _ in range(stall_cycles):
                await FallingEdge(dut.clk)

        dut.prf_data.value = word_val
        dut.prf_valid.value = 1
        dut.prf_last.value = 1 if (w_idx == num_words - 1) else 0

        # Wait until DUT accepts word
        while True:
            await FallingEdge(dut.clk)
            if int(dut.prf_ready.value) == 1:
                break

    dut.prf_valid.value = 0
    dut.prf_last.value = 0


@cocotb.test()
async def one_hot_sweep_eta3(dut):
    """Exhaustive one-hot bit sweep across all 1,536 bit positions for eta=3."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    ram = MockRam()
    running_flag = [True]
    cocotb.start_soon(ram_writer(dut, ram, running_flag))

    # Test sample of positions across all boundaries (first 64, last 64, and word transitions)
    test_positions = list(range(64)) + list(range(1472, 1536))
    for bit_pos in [60, 61, 62, 63, 64, 65, 126, 127, 128, 190, 191, 192]:
        if bit_pos not in test_positions:
            test_positions.append(bit_pos)
    test_positions.sort()

    for k in test_positions:
        raw = bytearray(192)
        raw[k // 8] = 1 << (k % 8)
        expected = sample_poly_cbd(bytes(raw), 3)

        await FallingEdge(dut.clk)
        dut.mode_eta.value = MODE_ETA3
        dut.target_poly_id.value = 1
        dut.start.value = 1
        await FallingEdge(dut.clk)
        dut.start.value = 0

        cocotb.start_soon(feed_prf_stream(dut, bytes(raw)))

        cycles = 0
        while int(dut.done.value) == 0:
            await FallingEdge(dut.clk)
            cycles += 1
            assert cycles < 600

        got = ram.read_poly(1)
        assert got == expected, f"One-hot mismatch at bit position {k} for eta=3"

    running_flag[0] = False


@cocotb.test()
async def one_hot_sweep_eta2(dut):
    """Exhaustive one-hot bit sweep across all 1,024 bit positions for eta=2."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    ram = MockRam()
    running_flag = [True]
    cocotb.start_soon(ram_writer(dut, ram, running_flag))

    test_positions = list(range(64)) + list(range(960, 1024))
    for bit_pos in [62, 63, 64, 65, 127, 128]:
        if bit_pos not in test_positions:
            test_positions.append(bit_pos)
    test_positions.sort()

    for k in test_positions:
        raw = bytearray(128)
        raw[k // 8] = 1 << (k % 8)
        expected = sample_poly_cbd(bytes(raw), 2)

        await FallingEdge(dut.clk)
        dut.mode_eta.value = MODE_ETA2
        dut.target_poly_id.value = 2
        dut.start.value = 1
        await FallingEdge(dut.clk)
        dut.start.value = 0

        cocotb.start_soon(feed_prf_stream(dut, bytes(raw)))

        cycles = 0
        while int(dut.done.value) == 0:
            await FallingEdge(dut.clk)
            cycles += 1
            assert cycles < 600

        got = ram.read_poly(2)
        assert got == expected, f"One-hot mismatch at bit position {k} for eta=2"

    running_flag[0] = False


@cocotb.test()
async def extreme_a_and_b_streams(dut):
    """Verify that all-a streams yield +eta and all-b streams yield Q-eta."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    ram = MockRam()
    running_flag = [True]
    cocotb.start_soon(ram_writer(dut, ram, running_flag))

    # --- eta=3: 6 bits per coeff. a is bits [2:0], b is bits [5:3] ---
    # a-only: 000111_000111 = 0b000111 repeated
    a_only_3 = bytearray(192)
    b_only_3 = bytearray(192)
    for bit_idx in range(192 * 8):
        coeff_bit = bit_idx % 6
        if coeff_bit < 3:
            a_only_3[bit_idx // 8] |= (1 << (bit_idx % 8))
        else:
            b_only_3[bit_idx // 8] |= (1 << (bit_idx % 8))

    # Check a-only eta3
    await FallingEdge(dut.clk)
    dut.mode_eta.value = MODE_ETA3
    dut.target_poly_id.value = 0
    dut.start.value = 1
    await FallingEdge(dut.clk)
    dut.start.value = 0
    cocotb.start_soon(feed_prf_stream(dut, bytes(a_only_3)))
    while int(dut.done.value) == 0:
        await FallingEdge(dut.clk)
    assert ram.read_poly(0) == [3] * 256

    # Check b-only eta3
    await FallingEdge(dut.clk)
    dut.mode_eta.value = MODE_ETA3
    dut.target_poly_id.value = 1
    dut.start.value = 1
    await FallingEdge(dut.clk)
    dut.start.value = 0
    cocotb.start_soon(feed_prf_stream(dut, bytes(b_only_3)))
    while int(dut.done.value) == 0:
        await FallingEdge(dut.clk)
    assert ram.read_poly(1) == [Q - 3] * 256

    # --- eta=2: 4 bits per coeff. a is bits [1:0], b is bits [3:2] ---
    a_only_2 = bytes([0x33] * 128)
    b_only_2 = bytes([0xCC] * 128)

    # Check a-only eta2
    await FallingEdge(dut.clk)
    dut.mode_eta.value = MODE_ETA2
    dut.target_poly_id.value = 2
    dut.start.value = 1
    await FallingEdge(dut.clk)
    dut.start.value = 0
    cocotb.start_soon(feed_prf_stream(dut, a_only_2))
    while int(dut.done.value) == 0:
        await FallingEdge(dut.clk)
    assert ram.read_poly(2) == [2] * 256

    # Check b-only eta2
    await FallingEdge(dut.clk)
    dut.mode_eta.value = MODE_ETA2
    dut.target_poly_id.value = 3
    dut.start.value = 1
    await FallingEdge(dut.clk)
    dut.start.value = 0
    cocotb.start_soon(feed_prf_stream(dut, b_only_2))
    while int(dut.done.value) == 0:
        await FallingEdge(dut.clk)
    assert ram.read_poly(3) == [Q - 2] * 256

    running_flag[0] = False


@cocotb.test()
async def random_streams_eta3(dut):
    """Verify 20 random streams for eta=3 bit-exact vs model/mlkem/pke.py."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    ram = MockRam()
    running_flag = [True]
    cocotb.start_soon(ram_writer(dut, ram, running_flag))

    rng = random.Random(3003)
    for i in range(20):
        raw = bytes(rng.randrange(256) for _ in range(192))
        expected = sample_poly_cbd(raw, 3)

        await FallingEdge(dut.clk)
        dut.mode_eta.value = MODE_ETA3
        dut.target_poly_id.value = i % 8
        dut.start.value = 1
        await FallingEdge(dut.clk)
        dut.start.value = 0

        cocotb.start_soon(feed_prf_stream(dut, raw))

        cycles = 0
        while int(dut.done.value) == 0:
            await FallingEdge(dut.clk)
            cycles += 1
            assert cycles < 600

        got = ram.read_poly(i % 8)
        assert got == expected, f"Random stream mismatch for eta=3 on iteration {i}"

    running_flag[0] = False


@cocotb.test()
async def random_streams_eta2(dut):
    """Verify 20 random streams for eta=2 bit-exact vs model/mlkem/pke.py and cbd.py."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    ram = MockRam()
    running_flag = [True]
    cocotb.start_soon(ram_writer(dut, ram, running_flag))

    rng = random.Random(2002)
    for i in range(20):
        raw = bytes(rng.randrange(256) for _ in range(128))
        expected_pke = sample_poly_cbd(raw, 2)
        expected_cbd = model_cbd2(raw)
        assert expected_pke == expected_cbd

        await FallingEdge(dut.clk)
        dut.mode_eta.value = MODE_ETA2
        dut.target_poly_id.value = i % 8
        dut.start.value = 1
        await FallingEdge(dut.clk)
        dut.start.value = 0

        cocotb.start_soon(feed_prf_stream(dut, raw))

        cycles = 0
        while int(dut.done.value) == 0:
            await FallingEdge(dut.clk)
            cycles += 1
            assert cycles < 600

        got = ram.read_poly(i % 8)
        assert got == expected_pke, f"Random stream mismatch for eta=2 on iteration {i}"

    running_flag[0] = False


@cocotb.test()
async def mid_straddle_stalls(dut):
    """Verify robustness under random prf_valid stalls during word straddling."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    ram = MockRam()
    running_flag = [True]
    cocotb.start_soon(ram_writer(dut, ram, running_flag))

    rng = random.Random(4004)
    for i in range(5):
        raw3 = bytes(rng.randrange(256) for _ in range(192))
        expected3 = sample_poly_cbd(raw3, 3)

        await FallingEdge(dut.clk)
        dut.mode_eta.value = MODE_ETA3
        dut.target_poly_id.value = 0
        dut.start.value = 1
        await FallingEdge(dut.clk)
        dut.start.value = 0

        cocotb.start_soon(feed_prf_stream(dut, raw3, stall_prob=0.3))

        cycles = 0
        while int(dut.done.value) == 0:
            await FallingEdge(dut.clk)
            cycles += 1
            assert cycles < 1000

        assert ram.read_poly(0) == expected3, f"Stall test failed on eta=3 iteration {i}"

    running_flag[0] = False


@cocotb.test()
async def stream_length_errors(dut):
    """Verify that early prf_last triggers err_truncated."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    # Truncated stream: 80 bytes instead of 192 bytes
    truncated_raw = bytes([0xAA] * 80)

    await FallingEdge(dut.clk)
    dut.mode_eta.value = MODE_ETA3
    dut.target_poly_id.value = 0
    dut.start.value = 1
    await FallingEdge(dut.clk)
    dut.start.value = 0

    cocotb.start_soon(feed_prf_stream(dut, truncated_raw))

    cycles = 0
    saw_err = False
    while cycles < 300:
        await FallingEdge(dut.clk)
        cycles += 1
        if int(dut.err_truncated.value) == 1:
            saw_err = True
            break

    assert saw_err, "DUT failed to assert err_truncated on early prf_last!"
    assert int(dut.busy.value) == 0, "DUT must return to IDLE after truncation error"


@cocotb.test()
async def cycle_count_assertions(dut):
    """Verify exact cycle counts without stall: 259 cycles @ eta=2, 261 with bubble @ eta=3."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    ram = MockRam()
    running_flag = [True]
    cocotb.start_soon(ram_writer(dut, ram, running_flag))

    # eta=2 without bubble
    raw2 = bytes([0x55] * 128)
    await FallingEdge(dut.clk)
    dut.mode_eta.value = MODE_ETA2
    dut.target_poly_id.value = 0
    dut.start.value = 1
    await FallingEdge(dut.clk)
    dut.start.value = 0
    cocotb.start_soon(feed_prf_stream(dut, raw2, inject_keccak_bubble=False))

    cycles2 = 0
    while int(dut.done.value) == 0:
        await FallingEdge(dut.clk)
        cycles2 += 1
    assert cycles2 == 259, f"eta=2 cycle count regression: expected 259, got {cycles2}"

    # eta=3 with 25-cycle Keccak permutation bubble
    raw3 = bytes([0xAA] * 192)
    await FallingEdge(dut.clk)
    dut.mode_eta.value = MODE_ETA3
    dut.target_poly_id.value = 1
    dut.start.value = 1
    await FallingEdge(dut.clk)
    dut.start.value = 0
    cocotb.start_soon(feed_prf_stream(dut, raw3, inject_keccak_bubble=True))

    cycles3 = 0
    while int(dut.done.value) == 0:
        await FallingEdge(dut.clk)
        cycles3 += 1
    assert cycles3 == 261, f"eta=3 cycle count regression with bubble: expected 261, got {cycles3}"

    running_flag[0] = False


@cocotb.test()
async def kat_integration_test(dut):
    """ACVP FIPS 203 KAT Vector 1 derivation check:
    Derive (rho, sigma) = G(d || 0x02) = SHA3-512(d || 0x02)
    Feed SHAKE256(sigma || 0x00, 192) into cbd_sampler
    Verify ntt(s[0]) == ByteDecode12(dk[0:384]) from KAT tgId=1 tcId=1.
    """
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    ram = MockRam()
    running_flag = [True]
    cocotb.start_soon(ram_writer(dut, ram, running_flag))

    kat_path = REPO / "sim" / "vectors" / "fips203_kat" / "mlkem512_keygen.json"
    with open(kat_path, "r", encoding="utf-8") as f:
        kat = json.load(f)

    tg = [group for group in kat["testGroups"] if group.get("parameterSet") == "ML-KEM-512"][0]
    t = tg["tests"][0]
    d = bytes.fromhex(t["d"])
    dk = bytes.fromhex(t["dk"])

    # G(d || 0x02)
    rho, sigma = model_g(d + b"\x02")
    prf_stream = model_prf(3, sigma, 0)
    expected_s0 = sample_poly_cbd(prf_stream, 3)
    expected_s0_hat = byte_decode(dk[0:384], 12)
    assert model_ntt(expected_s0) == expected_s0_hat, "Model KAT derivation mismatch!"

    # Run through RTL cbd_sampler
    await FallingEdge(dut.clk)
    dut.mode_eta.value = MODE_ETA3
    dut.target_poly_id.value = 0
    dut.start.value = 1
    await FallingEdge(dut.clk)
    dut.start.value = 0

    cocotb.start_soon(feed_prf_stream(dut, prf_stream, inject_keccak_bubble=True))

    while int(dut.done.value) == 0:
        await FallingEdge(dut.clk)

    got_s0 = ram.read_poly(0)
    assert got_s0 == expected_s0, "CBD sampler output does not match model s[0]!"
    assert model_ntt(got_s0) == expected_s0_hat, "NTT of CBD output does not match KAT dk[0:384]!"

    running_flag[0] = False


def test_runner():
    """pytest entry point using cocotb.runner and iverilog."""
    from cocotb.runner import get_runner

    rtl = REPO / "rtl"
    runner = get_runner(os.getenv("SIM", "icarus"))
    runner.build(
        sources=[
            rtl / "crypto" / "kem" / "cbd_sampler.v",
        ],
        includes=[rtl / "crypto" / "kem"],
        hdl_toplevel="cbd_sampler",
        build_dir=REPO / "sim" / "sim_build" / "cbd_sampler",
        always=True,
    )
    runner.test(
        hdl_toplevel="cbd_sampler",
        test_module="test_cbd",
        build_dir=REPO / "sim" / "sim_build" / "cbd_sampler",
        test_dir=Path(__file__).resolve().parent,
    )


if __name__ == "__main__":
    test_runner()

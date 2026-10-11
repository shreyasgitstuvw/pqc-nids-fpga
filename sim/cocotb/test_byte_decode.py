#==========================================================================
# sim/cocotb/test_byte_decode.py
#
# Cocotb testbench for byte_decode.v (ML-KEM-512 Byte Decoder Core).
# Bit-exact synthesizable RTL twin of model/mlkem/pke.py:byte_decode.
# Verified against frozen model and independent Python bit-unpacking oracle.
#
# Tests (named without test_ prefix for pytest runner compatibility):
#   1. decode_random_polys: random polys across all D in {1, 4, 10, 12}
#   2. decode_straddle_coefficients: verifies straddling coefficients for D=10, 12
#   3. decode_backpressure_stalls: random in_valid pauses from upstream
#   4. decode_modulus_check_negative: canonical [0, 3328] vs non-canonical [3329, 4095]
#   5. decode_mid_stream_reset: rst flushes all pipeline stages, zero stale valids
#   6. decode_boundary_excess_words: in_ready deasserts after 256 coefficients
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

from model.mlkem.pke import byte_decode as model_byte_decode, Q


def independent_oracle_decode(words, d):
    """Independent bit-unpacking oracle matching FIPS 203 sec 4.2.1."""
    bits = []
    for w in words:
        for b in range(64):
            bits.append((w >> b) & 1)
    coeffs = []
    m = Q if d == 12 else (1 << d)
    for c_idx in range(256):
        val = 0
        for b in range(d):
            val |= bits[c_idx * d + b] << b
        coeffs.append(val % m)
    return coeffs


async def reset_dut(dut):
    dut.rst.value = 1
    dut.start_poly.value = 0
    dut.check_modulus.value = 0
    dut.in_valid.value = 0
    dut.in_data.value = 0
    await FallingEdge(dut.clk)
    await FallingEdge(dut.clk)
    dut.rst.value = 0
    await FallingEdge(dut.clk)


@cocotb.test()
async def decode_random_polys(dut):
    """Verify 10 random polynomials bit-exact vs model and independent oracle."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    d = int(dut.D.value)
    total_words = (256 * d) // 64
    rng = random.Random(100 + d)

    for poly_idx in range(10):
        # Generate random 64-bit words
        words = [rng.getrandbits(64) for _ in range(total_words)]
        raw_bytes = b"".join(w.to_bytes(8, byteorder="little") for w in words)

        expected_coeffs_model = model_byte_decode(raw_bytes, d)
        expected_coeffs_oracle = independent_oracle_decode(words, d)
        assert expected_coeffs_model == expected_coeffs_oracle, "Model vs oracle mismatch"

        dut.check_modulus.value = 0
        dut.start_poly.value = 1
        await FallingEdge(dut.clk)
        dut.start_poly.value = 0

        got_coeffs = []

        async def coeff_collector():
            while len(got_coeffs) < 256:
                await FallingEdge(dut.clk)
                if int(dut.out_valid.value) == 1:
                    got_coeffs.append(int(dut.out_data.value))

        collector = cocotb.start_soon(coeff_collector())

        # Stream words into DUT respecting in_ready
        for w in words:
            while int(dut.in_ready.value) == 0:
                await FallingEdge(dut.clk)
            dut.in_valid.value = 1
            dut.in_data.value = w
            await FallingEdge(dut.clk)

        dut.in_valid.value = 0
        dut.in_data.value = 0

        await collector
        assert got_coeffs == expected_coeffs_model, f"Poly {poly_idx} mismatch for D={d}"


@cocotb.test()
async def decode_straddle_coefficients(dut):
    """Verify straddling coefficients with structured one-hot words."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    d = int(dut.D.value)
    total_words = (256 * d) // 64

    for w_target in range(min(5, total_words)):
        words = [0] * total_words
        words[w_target] = 0xF0F0F0F00F0F0F0F # alternating bit pattern
        raw_bytes = b"".join(w.to_bytes(8, byteorder="little") for w in words)
        expected = model_byte_decode(raw_bytes, d)

        dut.start_poly.value = 1
        await FallingEdge(dut.clk)
        dut.start_poly.value = 0

        got_coeffs = []
        async def coeff_collector():
            while len(got_coeffs) < 256:
                await FallingEdge(dut.clk)
                if int(dut.out_valid.value) == 1:
                    got_coeffs.append(int(dut.out_data.value))

        collector = cocotb.start_soon(coeff_collector())

        for w in words:
            while int(dut.in_ready.value) == 0:
                await FallingEdge(dut.clk)
            dut.in_valid.value = 1
            dut.in_data.value = w
            await FallingEdge(dut.clk)

        dut.in_valid.value = 0
        await collector
        assert got_coeffs == expected, f"Straddle pattern mismatch at word {w_target} for D={d}"


@cocotb.test()
async def decode_backpressure_stalls(dut):
    """Verify random in_valid pauses from upstream word source."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    d = int(dut.D.value)
    total_words = (256 * d) // 64
    rng = random.Random(777 + d)

    words = [rng.getrandbits(64) for _ in range(total_words)]
    raw_bytes = b"".join(w.to_bytes(8, byteorder="little") for w in words)
    expected = model_byte_decode(raw_bytes, d)

    dut.start_poly.value = 1
    await FallingEdge(dut.clk)
    dut.start_poly.value = 0

    got_coeffs = []
    async def coeff_collector():
        while len(got_coeffs) < 256:
            await FallingEdge(dut.clk)
            if int(dut.out_valid.value) == 1:
                got_coeffs.append(int(dut.out_data.value))

    collector = cocotb.start_soon(coeff_collector())

    for w in words:
        # Random upstream bubbles
        while rng.random() < 0.4:
            dut.in_valid.value = 0
            await FallingEdge(dut.clk)

        while int(dut.in_ready.value) == 0:
            dut.in_valid.value = 0
            await FallingEdge(dut.clk)

        dut.in_valid.value = 1
        dut.in_data.value = w
        await FallingEdge(dut.clk)

    dut.in_valid.value = 0
    await collector
    assert got_coeffs == expected, f"Upstream bubble mismatch for D={d}"


@cocotb.test()
async def decode_modulus_check_negative(dut):
    """Verify canonical vs non-canonical coefficients for D=12 and sticky error flag."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    d = int(dut.D.value)
    if d != 12:
        return # Modulus check applies to D=12

    total_words = 48

    # Test 1: All canonical coefficients [0, 3328] with check_modulus=1
    dut.check_modulus.value = 1
    dut.start_poly.value = 1
    await FallingEdge(dut.clk)
    dut.start_poly.value = 0

    # Words encoding 256 canonical coefficients
    coeffs_canonical = [(i * 13) % 3329 for i in range(256)]
    from model.mlkem.pke import byte_encode as model_encode
    words_canonical = [int.from_bytes(model_encode(coeffs_canonical, 12)[i*8:(i+1)*8], "little") for i in range(48)]

    got = []
    async def coll():
        while len(got) < 256:
            await FallingEdge(dut.clk)
            if int(dut.out_valid.value) == 1:
                got.append(int(dut.out_data.value))

    c_task = cocotb.start_soon(coll())

    for w in words_canonical:
        while int(dut.in_ready.value) == 0:
            await FallingEdge(dut.clk)
        dut.in_valid.value = 1
        dut.in_data.value = w
        await FallingEdge(dut.clk)

    dut.in_valid.value = 0
    await c_task
    assert got == coeffs_canonical
    assert int(dut.err_non_canonical.value) == 0, "err_non_canonical asserted on canonical coefficients!"

    # Test 2: Inject non-canonical coefficient (e.g. 3500 >= 3329)
    # 3500 % 3329 = 171
    dut.check_modulus.value = 1
    dut.start_poly.value = 1
    await FallingEdge(dut.clk)
    dut.start_poly.value = 0
    assert int(dut.err_non_canonical.value) == 0, "err_non_canonical not cleared on start_poly"

    coeffs_bad = list(coeffs_canonical)
    coeffs_bad[10] = 3329 # non-canonical boundary value!
    # Pack manually without modulo reduction
    bits = []
    for c in coeffs_bad:
        for b in range(12):
            bits.append((c >> b) & 1)
    words_bad = []
    for w_i in range(48):
        v = 0
        for b in range(64):
            v |= bits[w_i * 64 + b] << b
        words_bad.append(v)

    got_bad = []
    async def coll_bad():
        while len(got_bad) < 256:
            await FallingEdge(dut.clk)
            if int(dut.out_valid.value) == 1:
                got_bad.append(int(dut.out_data.value))

    b_task = cocotb.start_soon(coll_bad())

    for w in words_bad:
        while int(dut.in_ready.value) == 0:
            await FallingEdge(dut.clk)
        dut.in_valid.value = 1
        dut.in_data.value = w
        await FallingEdge(dut.clk)

    dut.in_valid.value = 0
    await b_task

    # Coeff 10 must be reduced to 3329 - 3329 = 0
    assert got_bad[10] == 0, f"Non-canonical coeff 10 was {got_bad[10]}, expected 0"
    assert int(dut.err_non_canonical.value) == 1, "err_non_canonical failed to assert on non-canonical 3329!"

    # Test 3: check_modulus=0 suppresses err_non_canonical
    dut.check_modulus.value = 0
    dut.start_poly.value = 1
    await FallingEdge(dut.clk)
    dut.start_poly.value = 0
    assert int(dut.err_non_canonical.value) == 0

    got_suppressed = []
    async def coll_sup():
        while len(got_suppressed) < 256:
            await FallingEdge(dut.clk)
            if int(dut.out_valid.value) == 1:
                got_suppressed.append(int(dut.out_data.value))

    s_task = cocotb.start_soon(coll_sup())

    for w in words_bad:
        while int(dut.in_ready.value) == 0:
            await FallingEdge(dut.clk)
        dut.in_valid.value = 1
        dut.in_data.value = w
        await FallingEdge(dut.clk)

    dut.in_valid.value = 0
    await s_task
    assert got_suppressed[10] == 0
    assert int(dut.err_non_canonical.value) == 0, "err_non_canonical asserted when check_modulus=0!"


@cocotb.test()
async def decode_mid_stream_reset(dut):
    """Verify mid-stream reset clears all state, zero stale valid pulses."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    d = int(dut.D.value)
    dut.start_poly.value = 1
    await FallingEdge(dut.clk)
    dut.start_poly.value = 0

    # Stream 3 words
    for _ in range(3):
        while int(dut.in_ready.value) == 0:
            await FallingEdge(dut.clk)
        dut.in_valid.value = 1
        dut.in_data.value = 0xAAAAAAAAAAAAAAAA
        await FallingEdge(dut.clk)

    dut.rst.value = 1
    dut.in_valid.value = 0
    await FallingEdge(dut.clk)
    dut.rst.value = 0
    await FallingEdge(dut.clk)

    for _ in range(20):
        await FallingEdge(dut.clk)
        assert int(dut.out_valid.value) == 0, f"Stale out_valid asserted after reset for D={d}"
        assert int(dut.busy.value) == 0, f"Busy high after reset for D={d}"


@cocotb.test()
async def decode_boundary_excess_words(dut):
    """Verify in_ready deasserts after 256 coefficients and rejects further words."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    d = int(dut.D.value)
    total_words = (256 * d) // 64

    dut.start_poly.value = 1
    await FallingEdge(dut.clk)
    dut.start_poly.value = 0

    coeffs_collected = 0
    async def c_coll():
        nonlocal coeffs_collected
        while coeffs_collected < 256:
            await FallingEdge(dut.clk)
            if int(dut.out_valid.value) == 1:
                coeffs_collected += 1

    coll = cocotb.start_soon(c_coll())

    for _ in range(total_words):
        while int(dut.in_ready.value) == 0:
            await FallingEdge(dut.clk)
        dut.in_valid.value = 1
        dut.in_data.value = 0x5555555555555555
        await FallingEdge(dut.clk)

    dut.in_valid.value = 0
    await coll
    assert coeffs_collected == 256

    # Wait 2 cycles for complete state retirement
    await FallingEdge(dut.clk)
    await FallingEdge(dut.clk)

    # Verify in_ready is strictly 0 and busy is 0
    assert int(dut.in_ready.value) == 0, f"in_ready asserted after 256 coefficients for D={d}"
    assert int(dut.busy.value) == 0, f"busy asserted after 256 coefficients for D={d}"


def test_runner():
    """pytest entry point using cocotb.runner across all D in {1, 4, 10, 12}."""
    from cocotb.runner import get_runner

    rtl = REPO / "rtl"
    sim_name = os.getenv("SIM", "icarus")

    for d_val in [12, 10, 4, 1]:
        runner = get_runner(sim_name)
        build_dir = REPO / "sim" / "sim_build" / f"byte_decode_d{d_val}"
        runner.build(
            sources=[
                rtl / "crypto" / "kem" / "byte_decode.v",
            ],
            includes=[rtl / "crypto" / "kem"],
            parameters={"D": d_val},
            hdl_toplevel="byte_decode",
            build_dir=build_dir,
            always=True,
        )
        runner.test(
            hdl_toplevel="byte_decode",
            test_module="test_byte_decode",
            build_dir=build_dir,
            test_dir=Path(__file__).resolve().parent,
        )


if __name__ == "__main__":
    test_runner()

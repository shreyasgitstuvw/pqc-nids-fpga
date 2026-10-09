#==========================================================================
# sim/cocotb/test_byte_encode.py
#
# Cocotb testbench for byte_encode.v (ML-KEM-512 Byte Encoder Core).
# Bit-exact synthesizable RTL twin of model/mlkem/pke.py:byte_encode.
# Verified against frozen model and independent Python bit-packing oracle.
#
# Tests (named without test_ prefix for pytest runner compatibility):
#   1. encode_random_polys: random 256-coeff polys across all D in {1, 4, 10, 12}
#   2. encode_straddle_coefficients: verifies straddling coefficients for D=10, 12
#   3. encode_backpressure_stalls: out_ready deassertion at word boundaries
#   4. encode_latency_assertions: exact registered latency (L=6 for D=12) and 256 cycles
#   5. encode_mid_stream_reset: rst flushes pipeline, zero stale valid pulses
#   6. encode_overflow_provocation: buffer capacity (>128b) overflow assert and clear
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

# Exact latencies from first in_valid to first out_valid
LATENCY_D12 = 6
LATENCY_D10 = 7
LATENCY_D4  = 16
LATENCY_D1  = 64
TOTAL_CYCLES = 256


def independent_oracle_encode(coeffs, d):
    """Independent bit-packing oracle matching FIPS 203 sec 4.2.1."""
    bits = []
    for c in coeffs:
        for b in range(d):
            bits.append((c >> b) & 1)
    words = []
    for w_idx in range(len(bits) // 64):
        val = 0
        for b_idx in range(64):
            val |= bits[w_idx * 64 + b_idx] << b_idx
        words.append(val)
    return words


async def reset_dut(dut):
    dut.rst.value = 1
    dut.start_poly.value = 0
    dut.in_valid.value = 0
    dut.in_data.value = 0
    dut.out_ready.value = 1
    await FallingEdge(dut.clk)
    await FallingEdge(dut.clk)
    dut.rst.value = 0
    await FallingEdge(dut.clk)


@cocotb.test()
async def encode_random_polys(dut):
    """Verify 10 random polynomials bit-exact vs model and independent oracle."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    d = int(dut.D.value)
    total_words = (256 * d) // 64
    rng = random.Random(42 + d)

    for poly_idx in range(10):
        coeffs = [rng.randrange(1 << d) for _ in range(256)]
        expected_words = independent_oracle_encode(coeffs, d)
        expected_bytes = model_byte_encode(coeffs, d)

        # Confirm oracle and model agree
        for i, w in enumerate(expected_words):
            chunk = expected_bytes[i * 8 : (i + 1) * 8]
            w_bytes = w.to_bytes(8, byteorder="little")
            assert w_bytes == chunk, f"Model vs oracle mismatch at word {i}"

        dut.start_poly.value = 1
        await FallingEdge(dut.clk)
        dut.start_poly.value = 0

        got_words = []
        last_seen = False

        async def word_collector():
            nonlocal last_seen
            timeout = 0
            while len(got_words) < total_words and timeout < 350:
                await FallingEdge(dut.clk)
                timeout += 1
                if int(dut.out_valid.value) == 1 and int(dut.out_ready.value) == 1:
                    got_words.append(int(dut.out_data.value))
                    if int(dut.poly_last.value) == 1:
                        last_seen = True

        collector = cocotb.start_soon(word_collector())

        for c in coeffs:
            dut.in_valid.value = 1
            dut.in_data.value = c
            await FallingEdge(dut.clk)

        dut.in_valid.value = 0
        dut.in_data.value = 0

        await collector
        assert got_words == expected_words, f"Poly {poly_idx} word mismatch for D={d}"
        assert last_seen, f"Poly {poly_idx} poly_last not asserted for D={d}"


@cocotb.test()
async def encode_straddle_coefficients(dut):
    """Verify bit-exact packing of straddling coefficients with one-hot patterns."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    d = int(dut.D.value)
    total_words = (256 * d) // 64

    # Straddle indices
    straddle_indices = [5, 10, 21, 26] if d == 12 else ([6, 12, 19, 25] if d == 10 else [0, 1])

    for straddle_idx in straddle_indices:
        coeffs = [0] * 256
        coeffs[straddle_idx] = (1 << d) - 1 # all 1s
        expected_words = independent_oracle_encode(coeffs, d)

        dut.start_poly.value = 1
        await FallingEdge(dut.clk)
        dut.start_poly.value = 0

        got_words = []
        async def word_collector():
            timeout = 0
            while len(got_words) < total_words and timeout < 350:
                await FallingEdge(dut.clk)
                timeout += 1
                if int(dut.out_valid.value) == 1:
                    got_words.append(int(dut.out_data.value))

        collector = cocotb.start_soon(word_collector())

        for c in coeffs:
            dut.in_valid.value = 1
            dut.in_data.value = c
            await FallingEdge(dut.clk)

        dut.in_valid.value = 0
        await collector
        assert got_words == expected_words, f"Straddle coeff {straddle_idx} mismatch for D={d}"


@cocotb.test()
async def encode_backpressure_stalls(dut):
    """Verify out_ready deassertion stalls without losing data."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    d = int(dut.D.value)
    total_words = (256 * d) // 64
    rng = random.Random(1337 + d)

    coeffs = [rng.randrange(1 << d) for _ in range(256)]
    expected_words = independent_oracle_encode(coeffs, d)

    dut.start_poly.value = 1
    await FallingEdge(dut.clk)
    dut.start_poly.value = 0

    got_words = []

    async def throttled_collector():
        timeout = 0
        while len(got_words) < total_words and timeout < 500:
            await FallingEdge(dut.clk)
            timeout += 1
            if int(dut.out_valid.value) == 1:
                # Downstream sink randomly stalls
                if rng.random() < 0.35:
                    dut.out_ready.value = 0
                else:
                    dut.out_ready.value = 1
                    got_words.append(int(dut.out_data.value))
            else:
                dut.out_ready.value = 1
        dut.out_ready.value = 1

    collector = cocotb.start_soon(throttled_collector())

    # Producer streams 256 coefficients, pausing if sink stalls for >2 cycles
    c_idx = 0
    stall_count = 0

    while c_idx < 256:
        await FallingEdge(dut.clk)
        if int(dut.out_ready.value) == 0:
            stall_count += 1
            if stall_count <= 2:
                dut.in_valid.value = 1
                dut.in_data.value = coeffs[c_idx]
                c_idx += 1
            else:
                dut.in_valid.value = 0
                dut.in_data.value = 0
        else:
            stall_count = 0
            dut.in_valid.value = 1
            dut.in_data.value = coeffs[c_idx]
            c_idx += 1

    await FallingEdge(dut.clk)
    dut.in_valid.value = 0
    dut.in_data.value = 0

    await collector
    assert got_words == expected_words, f"Backpressure stall mismatch for D={d}"


@cocotb.test()
async def encode_latency_assertions(dut):
    """Verify exact first-word latency and 257-cycle polynomial completion."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    d = int(dut.D.value)
    expected_latency = LATENCY_D12 if d == 12 else (LATENCY_D10 if d == 10 else (LATENCY_D4 if d == 4 else LATENCY_D1))

    dut.start_poly.value = 1
    await FallingEdge(dut.clk)
    dut.start_poly.value = 0

    first_word_cycle = None
    final_word_cycle = None
    words_collected = 0
    total_words = (256 * d) // 64

    async def latency_tracker():
        nonlocal first_word_cycle, final_word_cycle, words_collected
        cycles = 0
        while words_collected < total_words and cycles < 350:
            await FallingEdge(dut.clk)
            cycles += 1
            if int(dut.out_valid.value) == 1:
                words_collected += 1
                if first_word_cycle is None:
                    first_word_cycle = cycles
                if words_collected == total_words:
                    final_word_cycle = cycles

    tracker = cocotb.start_soon(latency_tracker())

    for c_idx in range(256):
        dut.in_valid.value = 1
        dut.in_data.value = c_idx & ((1 << d) - 1)
        await FallingEdge(dut.clk)

    dut.in_valid.value = 0
    dut.in_data.value = 0

    await tracker
    assert first_word_cycle == expected_latency, f"First word cycle {first_word_cycle} != expected {expected_latency} for D={d}"
    assert final_word_cycle == TOTAL_CYCLES, f"Final word cycle {final_word_cycle} != {TOTAL_CYCLES} for D={d}"


@cocotb.test()
async def encode_mid_stream_reset(dut):
    """Verify mid-stream reset clears all state, zero stale valid pulses."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    d = int(dut.D.value)
    dut.start_poly.value = 1
    await FallingEdge(dut.clk)
    dut.start_poly.value = 0

    # Stream 30 coefficients
    for c in range(30):
        dut.in_valid.value = 1
        dut.in_data.value = c & ((1 << d) - 1)
        await FallingEdge(dut.clk)

    # Assert reset mid-stream
    dut.rst.value = 1
    dut.in_valid.value = 0
    await FallingEdge(dut.clk)
    dut.rst.value = 0
    await FallingEdge(dut.clk)

    # Check for 20 cycles that no out_valid occurs
    for _ in range(20):
        await FallingEdge(dut.clk)
        assert int(dut.out_valid.value) == 0, f"Stale out_valid asserted after mid-stream reset for D={d}"
        assert int(dut.busy.value) == 0, f"Busy high after reset for D={d}"


@cocotb.test()
async def encode_overflow_provocation(dut):
    """Verify sticky overflow flag asserts when buffer capacity (128b) is exceeded and clears on start_poly/rst."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    d = int(dut.D.value)
    assert int(dut.overflow.value) == 0, f"Overflow high after reset for D={d}"

    dut.start_poly.value = 1
    await FallingEdge(dut.clk)
    dut.start_poly.value = 0

    # Freeze receiver (out_ready = 0) to prevent word discharge
    dut.out_ready.value = 0

    # Ingest coefficients until accumulator buffer (>128 bits) overflows.
    # The first 64-bit word is staged in out_data, and the internal buffer holds 128 bits.
    # Total capacity before overflow is 64 + 128 = 192 bits.
    overflow_threshold = (192 // d) + 2
    for i in range(overflow_threshold):
        dut.in_valid.value = 1
        dut.in_data.value = i & ((1 << d) - 1)
        await FallingEdge(dut.clk)

    dut.in_valid.value = 0
    dut.in_data.value = 0

    # Check sticky overflow flag
    assert int(dut.overflow.value) == 1, f"Overflow failed to assert after {overflow_threshold} stalled coefficients for D={d}"

    # Verify sticky for multiple cycles
    for _ in range(5):
        await FallingEdge(dut.clk)
        assert int(dut.overflow.value) == 1, f"Overflow flag dropped prematurely for D={d}"

    # Verify cleared by start_poly
    dut.start_poly.value = 1
    await FallingEdge(dut.clk)
    dut.start_poly.value = 0
    assert int(dut.overflow.value) == 0, f"Overflow flag failed to clear on start_poly for D={d}"


def test_runner():
    """pytest entry point using cocotb.runner across all D in {1, 4, 10, 12}."""
    from cocotb.runner import get_runner

    rtl = REPO / "rtl"
    sim_name = os.getenv("SIM", "icarus")

    for d_val in [12, 10, 4, 1]:
        runner = get_runner(sim_name)
        build_dir = REPO / "sim" / "sim_build" / f"byte_encode_d{d_val}"
        runner.build(
            sources=[
                rtl / "crypto" / "kem" / "byte_encode.v",
            ],
            includes=[rtl / "crypto" / "kem"],
            parameters={"D": d_val},
            hdl_toplevel="byte_encode",
            build_dir=build_dir,
            always=True,
        )
        runner.test(
            hdl_toplevel="byte_encode",
            test_module="test_byte_encode",
            build_dir=build_dir,
            test_dir=Path(__file__).resolve().parent,
        )


if __name__ == "__main__":
    test_runner()

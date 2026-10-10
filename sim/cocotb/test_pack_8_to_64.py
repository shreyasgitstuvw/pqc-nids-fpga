# ==============================================================================
# sim/cocotb/test_pack_8_to_64.py
#
# Cocotb Testbench for pack_8_to_64 (C13c Byte Stream Packer).
# Verifies little-endian 64-bit word assembly against Python independent oracle,
# partial word flushing on in_eof, backpressure stalls, and mid-stream reset.
# ==============================================================================

import os
import random
import pytest
import cocotb
from cocotb.clock import Clock
from cocotb.triggers import FallingEdge

# Single Source of Truth for Cycle Counts (Self-Review Section B.4)
LATENCY_FIRST_WORD = 8


async def reset_dut(dut):
    """Synchronous active-high reset."""
    dut.rst.value = 1
    dut.in_valid.value = 0
    dut.in_data.value = 0
    dut.in_eof.value = 0
    dut.out_ready.value = 0
    await FallingEdge(dut.clk)
    await FallingEdge(dut.clk)
    dut.rst.value = 0
    dut.out_ready.value = 1
    await FallingEdge(dut.clk)


@cocotb.test()
async def pack_random_streams(dut):
    """Verify bit-exact 64-bit word packing vs Python int.from_bytes(b, 'little') oracle."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    # Test stream sizes: 64 bytes (8 words), 800 bytes (ek = 100 words), 768 bytes (c = 96 words)
    for total_bytes in (64, 800, 768):
        raw_bytes = [random.randint(0, 255) for _ in range(total_bytes)]
        expected_words = [
            int.from_bytes(bytes(raw_bytes[i:i + 8]), byteorder="little")
            for i in range(0, total_bytes, 8)
        ]

        received_words = []

        async def collect_words():
            timeout = 0
            while len(received_words) < len(expected_words) and timeout < 1500:
                await FallingEdge(dut.clk)
                timeout += 1
                if int(dut.out_valid.value) == 1 and int(dut.out_ready.value) == 1:
                    received_words.append(int(dut.out_data.value))

        collector = cocotb.start_soon(collect_words())

        for idx, b in enumerate(raw_bytes):
            while int(dut.in_ready.value) == 0:
                dut.in_valid.value = 0
                await FallingEdge(dut.clk)
            dut.in_valid.value = 1
            dut.in_data.value = b
            dut.in_eof.value = 1 if (idx == total_bytes - 1) else 0
            await FallingEdge(dut.clk)

        dut.in_valid.value = 0
        dut.in_eof.value = 0
        await collector

        assert received_words == expected_words, (
            f"Packed words mismatch for length {total_bytes}:\n"
            f"Got:      {received_words[:4]}...\n"
            f"Expected: {expected_words[:4]}..."
        )
        assert int(dut.out_last.value) == 1, f"out_last not asserted on final word for length {total_bytes}"


@cocotb.test()
async def pack_partial_eof_flush(dut):
    """Verify partial word flush on in_eof for unaligned byte counts."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    # Test unaligned lengths: 13 bytes (8 bytes + 5 bytes)
    for unaligned_len in (5, 13, 27):
        raw_bytes = [random.randint(0, 255) for _ in range(unaligned_len)]
        expected_num_words = (unaligned_len + 7) // 8
        rem_bytes = unaligned_len % 8
        if rem_bytes == 0:
            rem_bytes = 8

        received_words = []
        received_last = []
        received_bytes_count = []

        async def collect_words():
            timeout = 0
            while len(received_words) < expected_num_words and timeout < 200:
                await FallingEdge(dut.clk)
                timeout += 1
                if int(dut.out_valid.value) == 1 and int(dut.out_ready.value) == 1:
                    received_words.append(int(dut.out_data.value))
                    received_last.append(int(dut.out_last.value))
                    received_bytes_count.append(int(dut.out_bytes.value))

        collector = cocotb.start_soon(collect_words())

        for idx, b in enumerate(raw_bytes):
            while int(dut.in_ready.value) == 0:
                dut.in_valid.value = 0
                await FallingEdge(dut.clk)
            dut.in_valid.value = 1
            dut.in_data.value = b
            dut.in_eof.value = 1 if (idx == unaligned_len - 1) else 0
            await FallingEdge(dut.clk)

        dut.in_valid.value = 0
        dut.in_eof.value = 0
        await collector

        # Check final word bytes count
        assert received_bytes_count[-1] == rem_bytes, (
            f"Final word byte count mismatch for length {unaligned_len}: "
            f"got {received_bytes_count[-1]}, expected {rem_bytes}"
        )
        assert received_last[-1] == 1, "out_last failed to assert on partial word"


@cocotb.test()
async def pack_backpressure_stalls(dut):
    """Verify backpressure handling: out_ready deassertion stalls without dropping data."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    raw_bytes = [random.randint(0, 255) for _ in range(32)]
    expected_words = [
        int.from_bytes(bytes(raw_bytes[i:i + 8]), byteorder="little")
        for i in range(0, 32, 8)
    ]

    received_words = []

    async def collect_stalled():
        dut.out_ready.value = 1
        timeout = 0
        while len(received_words) < len(expected_words) and timeout < 500:
            await FallingEdge(dut.clk)
            timeout += 1
            if int(dut.out_valid.value) == 1:
                if random.random() < 0.4:
                    dut.out_ready.value = 0
                else:
                    dut.out_ready.value = 1
                    received_words.append(int(dut.out_data.value))
            else:
                dut.out_ready.value = 1
        dut.out_ready.value = 1

    collector = cocotb.start_soon(collect_stalled())

    for idx, b in enumerate(raw_bytes):
        while int(dut.in_ready.value) == 0:
            dut.in_valid.value = 0
            await FallingEdge(dut.clk)
        dut.in_valid.value = 1
        dut.in_data.value = b
        dut.in_eof.value = 1 if (idx == 31) else 0
        await FallingEdge(dut.clk)

    dut.in_valid.value = 0
    dut.in_eof.value = 0
    await collector

    assert len(received_words) == len(expected_words), f"Timed out! Got {len(received_words)}/{len(expected_words)}"
    assert received_words == expected_words, "Packed words mismatch under random backpressure"


@cocotb.test()
async def pack_sustained_backpressure(dut):
    """Verify sustained backpressure: downstream holds out_ready=0 forcing skid_valid entry and drain."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    # 16 bytes = exactly 2 words
    raw_bytes = list(range(1, 17))
    expected_words = [
        int.from_bytes(bytes(raw_bytes[:8]), byteorder="little"),
        int.from_bytes(bytes(raw_bytes[8:]), byteorder="little"),
    ]

    # Hold out_ready LOW initially (sustained backpressure)
    dut.out_ready.value = 0
    received_words = []

    # Send first 8 bytes (Word 0) -> goes into out_data
    for b in raw_bytes[:8]:
        while int(dut.in_ready.value) == 0:
            await FallingEdge(dut.clk)
        dut.in_valid.value = 1
        dut.in_data.value = b
        dut.in_eof.value = 0
        await FallingEdge(dut.clk)

    dut.in_valid.value = 0
    dut.in_eof.value = 0

    # Word 0 is now in out_data, out_valid=1, out_ready=0
    assert int(dut.out_valid.value) == 1, "Word 0 must be in out_data"
    assert int(dut.skid_valid.value) == 0, "Skid buffer must still be empty"
    assert int(dut.in_ready.value) == 1, "in_ready must still be 1 (can accept Word 1)"

    # Send next 8 bytes (Word 1) -> must go into skid_data because out_ready is still 0
    for idx, b in enumerate(raw_bytes[8:]):
        while int(dut.in_ready.value) == 0:
            await FallingEdge(dut.clk)
        dut.in_valid.value = 1
        dut.in_data.value = b
        dut.in_eof.value = 1 if (idx == 7) else 0
        await FallingEdge(dut.clk)

    dut.in_valid.value = 0
    dut.in_eof.value = 0

    # Now both out_data and skid_data are full!
    assert int(dut.out_valid.value) == 1, "out_valid must be 1"
    assert int(dut.skid_valid.value) == 1, "skid_valid must be 1"
    assert int(dut.in_ready.value) == 0, "in_ready must be 0 when full"

    # 1. Read Word 0 currently held on out_data
    received_words.append(int(dut.out_data.value))

    # 2. Acknowledge Word 0 by asserting out_ready=1
    dut.out_ready.value = 1
    await FallingEdge(dut.clk)

    # 3. Word 1 is popped from skid buffer onto out_data
    assert int(dut.out_valid.value) == 1, "Word 1 must now be in out_data"
    assert int(dut.skid_valid.value) == 0, "Skid buffer must now be empty"
    assert int(dut.in_ready.value) == 1, "in_ready must now be 1"
    received_words.append(int(dut.out_data.value))

    # 4. Acknowledge Word 1
    await FallingEdge(dut.clk)
    dut.out_ready.value = 0

    assert received_words == expected_words, (
        f"Sustained backpressure words mismatch:\nGot: {received_words}\nExpected: {expected_words}"
    )
    assert int(dut.out_valid.value) == 0, "out_valid must be 0 after all words retired"


@cocotb.test()
async def pack_latency_assertion(dut):
    """Assert exactly 8 cycles to accumulate first word under zero backpressure."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    dut.out_ready.value = 1
    cycle_count = 0
    first_word_cycle = None

    for idx in range(8):
        dut.in_valid.value = 1
        dut.in_data.value = idx + 1
        dut.in_eof.value = 0
        await FallingEdge(dut.clk)
        cycle_count += 1
        if int(dut.out_valid.value) == 1 and first_word_cycle is None:
            first_word_cycle = cycle_count

    # Wait 1 cycle for registered output
    if first_word_cycle is None:
        await FallingEdge(dut.clk)
        cycle_count += 1
        if int(dut.out_valid.value) == 1:
            first_word_cycle = cycle_count

    dut.in_valid.value = 0
    assert first_word_cycle == LATENCY_FIRST_WORD, (
        f"First word cycle {first_word_cycle} != expected {LATENCY_FIRST_WORD}"
    )


@cocotb.test()
async def pack_mid_stream_reset(dut):
    """Verify mid-stream reset clears state: zero stale out_valid or busy flags."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    # Ingest 5 bytes (partial word)
    for b in range(5):
        dut.in_valid.value = 1
        dut.in_data.value = b
        await FallingEdge(dut.clk)

    # Assert reset mid-stream
    dut.rst.value = 1
    dut.in_valid.value = 0
    await FallingEdge(dut.clk)
    dut.rst.value = 0
    await FallingEdge(dut.clk)

    # Verify bus remains quiescent post-reset: zero stale out_valid pulses
    stale_pulses = 0
    for _ in range(20):
        await FallingEdge(dut.clk)
        if int(dut.out_valid.value) != 0:
            stale_pulses += 1
    assert stale_pulses == 0, f"Observed {stale_pulses} stale valid pulses post-reset"


# ==============================================================================
# Runner for pytest execution
# ==============================================================================
@pytest.mark.parametrize("sim_build", ["sim_build_pack_8_to_64"])
def test_runner(sim_build):
    from cocotb.runner import get_runner
    hdl_toplevel = "pack_8_to_64"
    proj_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    sources = [
        os.path.join(proj_path, "rtl", "crypto", "kem", "pack_8_to_64.v")
    ]
    runner = get_runner("icarus")
    runner.build(
        verilog_sources=sources,
        hdl_toplevel=hdl_toplevel,
        build_dir=os.path.join(proj_path, "sim", sim_build),
        always=True,
    )
    runner.test(
        hdl_toplevel=hdl_toplevel,
        test_module="test_pack_8_to_64",
        test_dir=os.path.join(proj_path, "sim", "cocotb"),
    )

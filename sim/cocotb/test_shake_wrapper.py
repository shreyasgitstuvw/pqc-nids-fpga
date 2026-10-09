"""
cocotb testbench for rtl/crypto/sha3/shake_wrapper.v (Member C)

Verified against the Python twin: model/sha3.py (sha3_256, sha3_512, shake128, shake256)
imported live. Follows Member D's cocotb testbench pattern with test_runner() for pytest.

Test Plan Coverage:
  1. empty_messages:
     b"" on SHA3-256, SHA3-512, SHAKE128, SHAKE256.
  2. padding_matrix_all_modes:
     Lengths [0, 1, rate-1, rate, rate+1, 2*rate] across all 4 modes.
     Includes single-byte merges (0x86 for SHA3, 0x9F for SHAKE) and full-block deferral.
  3. upper_byte_masking:
     in_bytes < 8 with garbage driven into upper bits; verifies upper bits are masked to 0.
  4. random_stalls_and_backpressure:
     Random gaps on in_valid and random pauses on out_ready.
  5. real_sizes_ek_and_ct:
     800-byte input (ML-KEM ek) and 768-byte input (ML-KEM ct) with cycle counts.
  6. block_edge_squeeze_shake128:
     Exactly 21 words (1 block) vs 22 words (triggers 2nd permutation).
  7. init_sweep:
     Sweeps init across cycles 0..26 of a running permutation; verifies clean abort & recovery.
  8. counting_permutations:
     Probes core start pulses to assert 2 permutations on rate vs 1 on rate-1.

Run:
  pytest sim/cocotb/test_shake_wrapper.py -q
  python sim/cocotb/test_shake_wrapper.py
"""

import os
import random
import sys
from pathlib import Path

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import FallingEdge, RisingEdge

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from model.sha3 import sha3_256, sha3_512, shake128, shake256

MODE_SHA3_256 = 0
MODE_SHA3_512 = 1
MODE_SHAKE128 = 2
MODE_SHAKE256 = 3

RATES = {
    MODE_SHA3_256: 136,
    MODE_SHA3_512: 72,
    MODE_SHAKE128: 168,
    MODE_SHAKE256: 136,
}


async def reset_dut(dut):
    """Synchronous active-high reset for 2 clock cycles."""
    dut.rst.value = 1
    dut.init.value = 0
    dut.mode.value = 0
    dut.squeeze_words.value = 0
    dut.in_valid.value = 0
    dut.in_last.value = 0
    dut.in_data.value = 0
    dut.in_bytes.value = 0
    dut.out_ready.value = 0
    await FallingEdge(dut.clk)
    await FallingEdge(dut.clk)
    dut.rst.value = 0
    await FallingEdge(dut.clk)


async def send_message(dut, data: bytes, rng=None, stall_prob=0.0):
    """Feeds byte stream in 64-bit words through in_data/in_bytes/in_last."""
    if len(data) == 0:
        # Empty message: in_valid=1, in_last=1, in_bytes=0
        while dut.in_ready.value == 0:
            await FallingEdge(dut.clk)
        dut.in_valid.value = 1
        dut.in_last.value = 1
        dut.in_bytes.value = 0
        dut.in_data.value = 0
        await FallingEdge(dut.clk)
        dut.in_valid.value = 0
        dut.in_last.value = 0
        return

    offset = 0
    total = len(data)
    while offset < total:
        if rng and rng.random() < stall_prob:
            dut.in_valid.value = 0
            await FallingEdge(dut.clk)
            continue

        chunk = data[offset : offset + 8]
        n_bytes = len(chunk)
        is_last = 1 if (offset + n_bytes == total) else 0

        # Pack chunk little-endian
        word = int.from_bytes(chunk, "little")
        if n_bytes < 8:
            # Inject garbage in upper bytes to verify wrapper masking
            garbage = 0xAA55AA55AA55AA55 << (8 * n_bytes)
            word |= (garbage & ((1 << 64) - 1))

        while dut.in_ready.value == 0:
            await FallingEdge(dut.clk)

        dut.in_valid.value = 1
        dut.in_last.value = is_last
        dut.in_bytes.value = n_bytes
        dut.in_data.value = word
        await FallingEdge(dut.clk)
        offset += n_bytes

    dut.in_valid.value = 0
    dut.in_last.value = 0
    dut.in_bytes.value = 0
    dut.in_data.value = 0


async def collect_digest(dut, expected_words: int, rng=None, backpressure_prob=0.0):
    """Collects squeezed 64-bit words, checking out_mask and out_last."""
    words = []
    timeout = 2000
    cycles = 0

    while len(words) < expected_words:
        await FallingEdge(dut.clk)
        cycles += 1
        assert cycles < timeout, f"Timeout after {cycles} cycles waiting for word {len(words)}/{expected_words}"

        if rng and rng.random() < backpressure_prob:
            dut.out_ready.value = 0
            continue

        dut.out_ready.value = 1
        if dut.out_valid.value == 1:
            w = int(dut.out_data.value)
            mask = int(dut.out_mask.value)
            is_last = int(dut.out_last.value)

            assert mask == 0xFF, f"Expected full word mask 0xFF, got 0x{mask:02X}"
            words.append(w)

            if len(words) == expected_words:
                assert is_last == 1, "out_last must be asserted on final digest word"
            else:
                assert is_last == 0, f"out_last asserted prematurely on word {len(words)-1}"

    dut.out_ready.value = 0
    # Pack words into bytes
    return b"".join(w.to_bytes(8, "little") for w in words)


def reference_oracle(mode, data: bytes, out_len: int) -> bytes:
    if mode == MODE_SHA3_256:
        return sha3_256(data)
    elif mode == MODE_SHA3_512:
        return sha3_512(data)
    elif mode == MODE_SHAKE128:
        return shake128(data, out_len)
    elif mode == MODE_SHAKE256:
        return shake256(data, out_len)
    raise ValueError(f"Unknown mode {mode}")


@cocotb.test()
async def empty_messages(dut):
    """b"" on SHA3-256, SHA3-512, SHAKE128, SHAKE256."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    for mode in [MODE_SHA3_256, MODE_SHA3_512, MODE_SHAKE128, MODE_SHAKE256]:
        out_words = 4 if mode in (MODE_SHA3_256, MODE_SHAKE256) else (8 if mode == MODE_SHA3_512 else 21)
        expected = reference_oracle(mode, b"", out_words * 8)

        # Pulse init
        await FallingEdge(dut.clk)
        dut.mode.value = mode
        dut.squeeze_words.value = out_words
        dut.init.value = 1
        await FallingEdge(dut.clk)
        dut.init.value = 0

        await send_message(dut, b"")
        got = await collect_digest(dut, out_words)
        assert got == expected, f"Mode {mode} empty message mismatch:\n  got: {got.hex()}\n  exp: {expected.hex()}"


@cocotb.test()
async def padding_matrix_all_modes(dut):
    """Lengths [0, 1, 2, 7, 8, 9, rate-9, rate-8, rate-7, rate-2, rate-1, rate, rate+1, 2*rate] across all 4 modes."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    rng = random.Random(0x101_202)

    for mode in [MODE_SHA3_256, MODE_SHA3_512, MODE_SHAKE128, MODE_SHAKE256]:
        rate = RATES[mode]
        test_lengths = [
            0, 1, 2, 7, 8, 9,
            rate - 9, rate - 8, rate - 7, rate - 2, rate - 1,
            rate, rate + 1, 2 * rate,
        ]
        out_words = 4 if mode in (MODE_SHA3_256, MODE_SHAKE256) else (8 if mode == MODE_SHA3_512 else 21)

        for l in test_lengths:
            data = bytes([rng.randrange(256) for _ in range(l)])
            expected = reference_oracle(mode, data, out_words * 8)

            await FallingEdge(dut.clk)
            dut.mode.value = mode
            dut.squeeze_words.value = out_words
            dut.init.value = 1
            await FallingEdge(dut.clk)
            dut.init.value = 0

            await send_message(dut, data)
            got = await collect_digest(dut, out_words)
            assert got == expected, (
                f"Mode {mode} length {l} mismatch:\n  got: {got.hex()}\n  exp: {expected.hex()}"
            )


@cocotb.test()
async def upper_byte_masking(dut):
    """Directly drives dirty upper bits when in_bytes < 8 to verify bit-exact masking."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    rng = random.Random(0x334455)

    for mode in [MODE_SHA3_256, MODE_SHA3_512, MODE_SHAKE128, MODE_SHAKE256]:
        out_words = 4 if mode in (MODE_SHA3_256, MODE_SHAKE256) else (8 if mode == MODE_SHA3_512 else 21)
        for valid_len in [1, 2, 3, 4, 5, 6, 7]:
            raw_bytes = bytes([rng.randrange(256) for _ in range(valid_len)])
            expected = reference_oracle(mode, raw_bytes, out_words * 8)

            await FallingEdge(dut.clk)
            dut.mode.value = mode
            dut.squeeze_words.value = out_words
            dut.init.value = 1
            await FallingEdge(dut.clk)
            dut.init.value = 0

            # Drive single word with all upper bits set to 0xFF
            word_val = int.from_bytes(raw_bytes, "little")
            garbage = 0xFFFF_FFFF_FFFF_FFFF << (8 * valid_len)
            dirty_word = (word_val | garbage) & ((1 << 64) - 1)

            while dut.in_ready.value == 0:
                await FallingEdge(dut.clk)

            dut.in_valid.value = 1
            dut.in_last.value = 1
            dut.in_bytes.value = valid_len
            dut.in_data.value = dirty_word
            await FallingEdge(dut.clk)

            dut.in_valid.value = 0
            dut.in_last.value = 0
            dut.in_bytes.value = 0
            dut.in_data.value = 0

            got = await collect_digest(dut, out_words)
            assert got == expected, f"Mode {mode} len {valid_len} dirty bits leaked into hash!"


@cocotb.test()
async def counting_permutations(dut):
    """Probes core_start pulses to assert 2 permutations on rate vs 1 on rate-1."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    rng = random.Random(0xC0C0)

    for mode in [MODE_SHA3_256, MODE_SHA3_512, MODE_SHAKE128, MODE_SHAKE256]:
        rate = RATES[mode]
        out_words = 4 if mode in (MODE_SHA3_256, MODE_SHAKE256) else (8 if mode == MODE_SHA3_512 else 21)

        # Test case A: rate - 1 bytes -> exactly 1 permutation
        await FallingEdge(dut.clk)
        dut.mode.value = mode
        dut.squeeze_words.value = out_words
        dut.init.value = 1
        await FallingEdge(dut.clk)
        dut.init.value = 0

        core_starts = 0
        async def monitor_core_start():
            nonlocal core_starts
            while True:
                await RisingEdge(dut.clk)
                if dut.core_start.value == 1:
                    core_starts += 1

        mon_task = cocotb.start_soon(monitor_core_start())

        data_sub1 = bytes([rng.randrange(256) for _ in range(rate - 1)])
        await send_message(dut, data_sub1)
        got = await collect_digest(dut, out_words)
        assert got == reference_oracle(mode, data_sub1, out_words * 8)
        assert core_starts == 1, f"Mode {mode} rate-1 expected 1 permutation, got {core_starts}"
        mon_task.cancel()

        # Test case B: rate bytes -> exactly 2 permutations (Case C: full-block deferral)
        await FallingEdge(dut.clk)
        dut.mode.value = mode
        dut.squeeze_words.value = out_words
        dut.init.value = 1
        await FallingEdge(dut.clk)
        dut.init.value = 0

        core_starts = 0
        mon_task = cocotb.start_soon(monitor_core_start())

        data_rate = bytes([rng.randrange(256) for _ in range(rate)])
        await send_message(dut, data_rate)
        got = await collect_digest(dut, out_words)
        assert got == reference_oracle(mode, data_rate, out_words * 8)
        assert core_starts == 2, f"Mode {mode} rate expected 2 permutations, got {core_starts}"
        mon_task.cancel()


@cocotb.test()
async def random_stalls_and_backpressure(dut):
    """Random gaps on in_valid and random pauses on out_ready."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    rng = random.Random(0x57A11)

    for trial in range(10):
        mode = rng.choice([MODE_SHA3_256, MODE_SHA3_512, MODE_SHAKE128, MODE_SHAKE256])
        msg_len = rng.randint(5, 250)
        data = bytes([rng.randrange(256) for _ in range(msg_len)])
        out_words = 4 if mode in (MODE_SHA3_256, MODE_SHAKE256) else (8 if mode == MODE_SHA3_512 else 16)
        expected = reference_oracle(mode, data, out_words * 8)

        await FallingEdge(dut.clk)
        dut.mode.value = mode
        dut.squeeze_words.value = out_words
        dut.init.value = 1
        await FallingEdge(dut.clk)
        dut.init.value = 0

        await send_message(dut, data, rng=rng, stall_prob=0.3)
        got = await collect_digest(dut, out_words, rng=rng, backpressure_prob=0.3)
        assert got == expected, f"Trial {trial} stalled transfer mismatch"


@cocotb.test()
async def real_sizes_ek_and_ct(dut):
    """Hash an 800-byte input (ek) and 768-byte input (ciphertext) with cycle assertions."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    rng = random.Random(0xEE_CC)

    # 1. SHA3-256 on 800-byte ek: 800 bytes / 136 = 5 full blocks (680B) + 120B in block 6
    # Total permutations: 6 permutations = ~150 cycles core + 100 cycles absorption = < 350 cycles
    ek = bytes([rng.randrange(256) for _ in range(800)])
    expected_ek_h = sha3_256(ek)

    await FallingEdge(dut.clk)
    dut.mode.value = MODE_SHA3_256
    dut.squeeze_words.value = 4
    dut.init.value = 1
    await FallingEdge(dut.clk)
    dut.init.value = 0

    start_cyc = cocotb.utils.get_sim_time('ns')
    await send_message(dut, ek)
    got_ek = await collect_digest(dut, 4)
    end_cyc = cocotb.utils.get_sim_time('ns')
    cycles_ek = int((end_cyc - start_cyc) / 10)
    assert got_ek == expected_ek_h, "SHA3-256(ek) mismatch"
    assert cycles_ek <= 300, f"SHA3-256(800B ek) took {cycles_ek} cycles, exceeding bound of 300 cycles"

    # 2. SHAKE256 on 768-byte ct: 768 / 136 = 5 full blocks (680B) + 88B in block 6
    ct = bytes([rng.randrange(256) for _ in range(768)])
    expected_ct_k = shake256(ct, 32)

    await FallingEdge(dut.clk)
    dut.mode.value = MODE_SHAKE256
    dut.squeeze_words.value = 4
    dut.init.value = 1
    await FallingEdge(dut.clk)
    dut.init.value = 0

    start_ct = cocotb.utils.get_sim_time('ns')
    await send_message(dut, ct)
    got_ct = await collect_digest(dut, 4)
    end_ct = cocotb.utils.get_sim_time('ns')
    cycles_ct = int((end_ct - start_ct) / 10)
    assert got_ct == expected_ct_k, "SHAKE256(ct) mismatch"
    assert cycles_ct <= 300, f"SHAKE256(768B ct) took {cycles_ct} cycles, exceeding bound of 300 cycles"


@cocotb.test()
async def block_edge_squeeze_shake128(dut):
    """Squeeze exactly 21 words (1 block) and 22 words in SHAKE128."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    data = b"sample_ntt_test_seed_32_bytes!!"

    # Test 21 words (exactly 1 block)
    await FallingEdge(dut.clk)
    dut.mode.value = MODE_SHAKE128
    dut.squeeze_words.value = 21
    dut.init.value = 1
    await FallingEdge(dut.clk)
    dut.init.value = 0
    await send_message(dut, data)
    got_21 = await collect_digest(dut, 21)
    assert got_21 == shake128(data, 21 * 8)

    # Test 22 words (crosses boundary, requires 2nd permutation)
    await FallingEdge(dut.clk)
    dut.mode.value = MODE_SHAKE128
    dut.squeeze_words.value = 22
    dut.init.value = 1
    await FallingEdge(dut.clk)
    dut.init.value = 0
    await send_message(dut, data)
    got_22 = await collect_digest(dut, 22)
    assert got_22 == shake128(data, 22 * 8)


@cocotb.test()
async def init_sweep_abort(dut):
    """Sweep init across cycle offsets 0..26 of a permutation; verify clean recovery."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    msg_a = b"FirstMessageToAbortMidway1234567"
    msg_b = b"SecondValidMessageAfterCleanInit"
    expected_b = sha3_256(msg_b)

    for offset in range(27):
        # Start message A
        await FallingEdge(dut.clk)
        dut.mode.value = MODE_SHA3_256
        dut.squeeze_words.value = 4
        dut.init.value = 1
        await FallingEdge(dut.clk)
        dut.init.value = 0

        # Send full message to trigger permutation
        await send_message(dut, msg_a)

        # Wait until offset cycles into the permutation
        for _ in range(offset):
            await FallingEdge(dut.clk)

        # Fire init abort
        dut.mode.value = MODE_SHA3_256
        dut.squeeze_words.value = 4
        dut.init.value = 1
        await FallingEdge(dut.clk)
        dut.init.value = 0

        # Wait until wrapper returns to idle (in_ready goes high)
        while dut.in_ready.value == 0:
            await FallingEdge(dut.clk)

        # Send message B and verify bit-exact digest
        await send_message(dut, msg_b)
        got_b = await collect_digest(dut, 4)
        assert got_b == expected_b, f"Offset {offset} init abort corrupted subsequent hash"


def test_runner():
    """pytest entry point using cocotb.runner and iverilog."""
    from cocotb.runner import get_runner

    rtl = REPO / "rtl"
    runner = get_runner(os.getenv("SIM", "icarus"))
    runner.build(
        sources=[
            rtl / "crypto" / "sha3" / "keccak_f1600.v",
            rtl / "crypto" / "sha3" / "shake_wrapper.v",
        ],
        includes=[rtl / "crypto" / "sha3"],
        hdl_toplevel="shake_wrapper",
        build_dir=REPO / "sim" / "sim_build" / "shake_wrapper",
        always=True,
    )
    runner.test(
        hdl_toplevel="shake_wrapper",
        test_module="test_shake_wrapper",
        build_dir=REPO / "sim" / "sim_build" / "shake_wrapper",
        test_dir=Path(__file__).resolve().parent,
    )


if __name__ == "__main__":
    test_runner()

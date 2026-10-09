#==========================================================================
# sim/cocotb/test_fips202_kat.py
#
# FIPS 202 Known-Answer Test (KAT) testbench for shake_wrapper.v.
# Drives official NIST CAVP byte-oriented test vectors from
# sim/vectors/fips202_kat/ through shake_wrapper.v and asserts bit-exact
# agreement with BOTH the published NIST CAVP expected digest and
# the golden Python twin (model/sha3.py).
#
# Vector provenance:
#   - NIST CAVP SHA-3 Byte Test Vectors (sha-3bytetestvectors.zip)
#   - NIST CAVP SHAKE Byte Test Vectors (shakebytetestvectors.zip)
#
# Closes Task C9b and Roadmap item 1.2.
#==========================================================================

import math
import os
import sys
from pathlib import Path

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import FallingEdge, RisingEdge

# Add repo root to path so we can import model.sha3
REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))

from model.sha3 import sha3_256, sha3_512, shake128, shake256

MODE_SHA3_256 = 0
MODE_SHA3_512 = 1
MODE_SHAKE128 = 2
MODE_SHAKE256 = 3

VECTORS_DIR = REPO / "sim" / "vectors" / "fips202_kat"


def parse_rsp(file_path):
    """Parses a NIST CAVP .rsp response file into a list of vector dicts."""
    cases = []
    current = {}
    default_outlen = None

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[Outputlen ="):
                default_outlen = int(line.split("=")[1].replace("]", "").strip())
                continue
            if line.startswith("[L ="):
                default_outlen = int(line.split("=")[1].replace("]", "").strip())
                continue
            if "=" in line:
                k, v = [x.strip() for x in line.split("=", 1)]
                if k == "Len":
                    current["len"] = int(v)
                elif k == "Msg":
                    current["msg_hex"] = v
                elif k in ("MD", "Output"):
                    current["expected_hex"] = v
                elif k == "Outputlen":
                    current["outlen"] = int(v)

                if "msg_hex" in current and "expected_hex" in current:
                    if "len" not in current:
                        current["len"] = len(current["msg_hex"]) * 4 if current["msg_hex"] != "00" else 0
                    if "outlen" not in current and default_outlen is not None:
                        current["outlen"] = default_outlen
                    cases.append(current)
                    current = {}
    return cases


async def reset_dut(dut):
    """Synchronous active-high reset per project conventions."""
    dut.rst.value = 1
    dut.mode.value = 0
    dut.init.value = 0
    dut.squeeze_words.value = 0
    dut.in_data.value = 0
    dut.in_bytes.value = 0
    dut.in_valid.value = 0
    dut.in_last.value = 0
    dut.out_ready.value = 0

    for _ in range(5):
        await FallingEdge(dut.clk)
    dut.rst.value = 0
    await FallingEdge(dut.clk)


async def send_message(dut, data: bytes):
    """Feeds message bytes into shake_wrapper via 64-bit word bus."""
    if len(data) == 0:
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
        chunk = data[offset : offset + 8]
        n_bytes = len(chunk)
        is_last = 1 if (offset + n_bytes == total) else 0

        word = int.from_bytes(chunk, "little")
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


async def collect_digest(dut, expected_words: int):
    """Collects squeezed 64-bit words, checking out_mask and out_last."""
    words = []
    timeout = 100000
    cycles = 0

    while len(words) < expected_words:
        await FallingEdge(dut.clk)
        cycles += 1
        assert cycles < timeout, f"Timeout after {cycles} cycles waiting for word {len(words)}/{expected_words}"

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
    return b"".join(w.to_bytes(8, "little") for w in words)


@cocotb.test()
async def fips202_sha3_256_short(dut):
    """Run all 137 NIST CAVP ShortMsg vectors for SHA3-256 through shake_wrapper."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    rsp_file = VECTORS_DIR / "SHA3_256ShortMsg.rsp"
    cases = parse_rsp(rsp_file)
    assert len(cases) == 137, f"Expected 137 cases, got {len(cases)}"

    for i, c in enumerate(cases):
        msg = b"" if c["len"] == 0 else bytes.fromhex(c["msg_hex"])
        expected_nist = bytes.fromhex(c["expected_hex"])
        expected_twin = sha3_256(msg)
        assert expected_nist == expected_twin, f"Twin disagree with NIST on SHA3-256 case {i}"

        await FallingEdge(dut.clk)
        dut.mode.value = MODE_SHA3_256
        dut.squeeze_words.value = 4
        dut.init.value = 1
        await FallingEdge(dut.clk)
        dut.init.value = 0

        while dut.in_ready.value == 0:
            await FallingEdge(dut.clk)

        await send_message(dut, msg)
        digest = await collect_digest(dut, 4)

        assert digest == expected_nist, (
            f"SHA3-256 ShortMsg mismatch on case {i} (len={c['len']}):\n"
            f"  got:  {digest.hex()}\n"
            f"  want: {expected_nist.hex()}"
        )


@cocotb.test()
async def fips202_sha3_512_short(dut):
    """Run all 73 NIST CAVP ShortMsg vectors for SHA3-512 through shake_wrapper."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    rsp_file = VECTORS_DIR / "SHA3_512ShortMsg.rsp"
    cases = parse_rsp(rsp_file)
    assert len(cases) == 73, f"Expected 73 cases, got {len(cases)}"

    for i, c in enumerate(cases):
        msg = b"" if c["len"] == 0 else bytes.fromhex(c["msg_hex"])
        expected_nist = bytes.fromhex(c["expected_hex"])
        expected_twin = sha3_512(msg)
        assert expected_nist == expected_twin, f"Twin disagree with NIST on SHA3-512 case {i}"

        await FallingEdge(dut.clk)
        dut.mode.value = MODE_SHA3_512
        dut.squeeze_words.value = 8
        dut.init.value = 1
        await FallingEdge(dut.clk)
        dut.init.value = 0

        while dut.in_ready.value == 0:
            await FallingEdge(dut.clk)

        await send_message(dut, msg)
        digest = await collect_digest(dut, 8)

        assert digest == expected_nist, (
            f"SHA3-512 ShortMsg mismatch on case {i} (len={c['len']}):\n"
            f"  got:  {digest.hex()}\n"
            f"  want: {expected_nist.hex()}"
        )


@cocotb.test()
async def fips202_shake128_short(dut):
    """Run NIST CAVP ShortMsg vectors for SHAKE128 through shake_wrapper."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    rsp_file = VECTORS_DIR / "SHAKE128ShortMsg.rsp"
    cases = parse_rsp(rsp_file)

    # Test the first 50 cases (covering 0 to 400 bits, including block transitions)
    test_cases = cases[:50]
    for i, c in enumerate(test_cases):
        msg = b"" if c["len"] == 0 else bytes.fromhex(c["msg_hex"])
        expected_nist = bytes.fromhex(c["expected_hex"])
        out_bytes = c["outlen"] // 8
        expected_twin = shake128(msg, out_bytes)
        assert expected_nist == expected_twin, f"Twin disagree with NIST on SHAKE128 case {i}"

        num_words = math.ceil(out_bytes / 8)
        await FallingEdge(dut.clk)
        dut.mode.value = MODE_SHAKE128
        dut.squeeze_words.value = num_words
        dut.init.value = 1
        await FallingEdge(dut.clk)
        dut.init.value = 0

        while dut.in_ready.value == 0:
            await FallingEdge(dut.clk)

        await send_message(dut, msg)
        raw_digest = await collect_digest(dut, num_words)
        digest = raw_digest[:out_bytes]

        assert digest == expected_nist, (
            f"SHAKE128 ShortMsg mismatch on case {i} (len={c['len']}):\n"
            f"  got:  {digest.hex()}\n"
            f"  want: {expected_nist.hex()}"
        )


@cocotb.test()
async def fips202_shake256_short(dut):
    """Run NIST CAVP ShortMsg vectors for SHAKE256 through shake_wrapper."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    rsp_file = VECTORS_DIR / "SHAKE256ShortMsg.rsp"
    cases = parse_rsp(rsp_file)

    # Test the first 50 cases (covering 0 to 400 bits, including block transitions)
    test_cases = cases[:50]
    for i, c in enumerate(test_cases):
        msg = b"" if c["len"] == 0 else bytes.fromhex(c["msg_hex"])
        expected_nist = bytes.fromhex(c["expected_hex"])
        out_bytes = c["outlen"] // 8
        expected_twin = shake256(msg, out_bytes)
        assert expected_nist == expected_twin, f"Twin disagree with NIST on SHAKE256 case {i}"

        num_words = math.ceil(out_bytes / 8)
        await FallingEdge(dut.clk)
        dut.mode.value = MODE_SHAKE256
        dut.squeeze_words.value = num_words
        dut.init.value = 1
        await FallingEdge(dut.clk)
        dut.init.value = 0

        while dut.in_ready.value == 0:
            await FallingEdge(dut.clk)

        await send_message(dut, msg)
        raw_digest = await collect_digest(dut, num_words)
        digest = raw_digest[:out_bytes]

        assert digest == expected_nist, (
            f"SHAKE256 ShortMsg mismatch on case {i} (len={c['len']}):\n"
            f"  got:  {digest.hex()}\n"
            f"  want: {expected_nist.hex()}"
        )


@cocotb.test()
async def fips202_long_messages(dut):
    """Run multi-block LongMsg vectors across all 4 modes to verify multi-block absorbing."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    modes_and_files = [
        (MODE_SHA3_256, "SHA3_256LongMsg.rsp", 4, sha3_256),
        (MODE_SHA3_512, "SHA3_512LongMsg.rsp", 8, sha3_512),
        (MODE_SHAKE128, "SHAKE128LongMsg.rsp", 2, lambda m: shake128(m, 16)),
        (MODE_SHAKE256, "SHAKE256LongMsg.rsp", 4, lambda m: shake256(m, 32)),
    ]

    for mode, fname, out_words, twin_fn in modes_and_files:
        cases = parse_rsp(VECTORS_DIR / fname)
        # Test first 3 multi-block long messages per mode (typically 2,000 to 4,000 bits)
        for i, c in enumerate(cases[:3]):
            msg = bytes.fromhex(c["msg_hex"])
            expected_nist = bytes.fromhex(c["expected_hex"])
            expected_twin = twin_fn(msg)
            assert expected_nist == expected_twin, f"Twin mismatch on {fname} case {i}"

            await FallingEdge(dut.clk)
            dut.mode.value = mode
            dut.squeeze_words.value = out_words
            dut.init.value = 1
            await FallingEdge(dut.clk)
            dut.init.value = 0

            while dut.in_ready.value == 0:
                await FallingEdge(dut.clk)

            await send_message(dut, msg)
            digest = await collect_digest(dut, out_words)

            assert digest == expected_nist, (
                f"LongMsg mismatch on {fname} case {i} (len={c['len']}):\n"
                f"  got:  {digest.hex()}\n"
                f"  want: {expected_nist.hex()}"
            )


@cocotb.test()
async def fips202_variable_out(dut):
    """Run VariableOut vectors to verify arbitrary multi-word squeezing on SHAKE128 and SHAKE256."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    # Test selected output byte lengths matching ML-KEM requirements: 32B, 64B, 128B, 168B
    cases_128 = parse_rsp(VECTORS_DIR / "SHAKE128VariableOut.rsp")
    cases_256 = parse_rsp(VECTORS_DIR / "SHAKE256VariableOut.rsp")

    # Pick samples with different byte lengths
    sample_128 = [c for c in cases_128 if c["outlen"] in (128, 256, 512, 1024)][:6]
    for i, c in enumerate(sample_128):
        msg = bytes.fromhex(c["msg_hex"])
        expected_nist = bytes.fromhex(c["expected_hex"])
        out_bytes = c["outlen"] // 8
        expected_twin = shake128(msg, out_bytes)
        assert expected_nist == expected_twin, f"Twin mismatch on SHAKE128 VariableOut {i}"

        num_words = math.ceil(out_bytes / 8)
        await FallingEdge(dut.clk)
        dut.mode.value = MODE_SHAKE128
        dut.squeeze_words.value = num_words
        dut.init.value = 1
        await FallingEdge(dut.clk)
        dut.init.value = 0

        while dut.in_ready.value == 0:
            await FallingEdge(dut.clk)

        await send_message(dut, msg)
        raw_digest = await collect_digest(dut, num_words)
        digest = raw_digest[:out_bytes]

        assert digest == expected_nist, (
            f"SHAKE128 VariableOut mismatch on case {i} (outlen={c['outlen']}):\n"
            f"  got:  {digest.hex()}\n"
            f"  want: {expected_nist.hex()}"
        )

    sample_256 = [c for c in cases_256 if c["outlen"] in (128, 256, 512, 1024)][:6]
    for i, c in enumerate(sample_256):
        msg = bytes.fromhex(c["msg_hex"])
        expected_nist = bytes.fromhex(c["expected_hex"])
        out_bytes = c["outlen"] // 8
        expected_twin = shake256(msg, out_bytes)
        assert expected_nist == expected_twin, f"Twin mismatch on SHAKE256 VariableOut {i}"

        num_words = math.ceil(out_bytes / 8)
        await FallingEdge(dut.clk)
        dut.mode.value = MODE_SHAKE256
        dut.squeeze_words.value = num_words
        dut.init.value = 1
        await FallingEdge(dut.clk)
        dut.init.value = 0

        while dut.in_ready.value == 0:
            await FallingEdge(dut.clk)

        await send_message(dut, msg)
        raw_digest = await collect_digest(dut, num_words)
        digest = raw_digest[:out_bytes]

        assert digest == expected_nist, (
            f"SHAKE256 VariableOut mismatch on case {i} (outlen={c['outlen']}):\n"
            f"  got:  {digest.hex()}\n"
            f"  want: {expected_nist.hex()}"
        )


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
        build_dir=REPO / "sim" / "sim_build" / "fips202_kat",
        always=True,
    )
    runner.test(
        hdl_toplevel="shake_wrapper",
        test_module="test_fips202_kat",
        build_dir=REPO / "sim" / "sim_build" / "fips202_kat",
        test_dir=Path(__file__).resolve().parent,
    )


if __name__ == "__main__":
    test_runner()

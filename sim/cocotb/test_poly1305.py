"""
cocotb testbench for rtl/crypto/chacha_poly/poly1305.v  (Member D)

Golden oracle: model/chacha_poly.py::poly1305_mac -- every expected tag is
computed at run time, nothing is copied from a previous simulation.

What this adds on top of sim/test_poly1305_tb.v:
  * random messages through the block interface (blk_ready handshake) and
    through the streaming-byte interface, 0..300 bytes
  * carry stress: r with every clampable bit set, all-0xFF messages
  * the exact "chacha_poly" feed pattern: 1-cycle blk_valid pulses 16 clocks
    apart with NO blk_ready check (that module relies on the chunk latency
    being shorter than the spacing)
  * the final conditional subtract (acc in [p, 2^130)) and the carry-out of
    limb 9, which random data essentially never reaches, by depositing a
    chosen loose accumulator and finalizing it

Run directly (no `make` needed, works on Windows):
    python sim/cocotb/test_poly1305.py
or via pytest:
    pytest sim/cocotb/test_poly1305.py
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

from model.chacha_poly import poly1305_mac  # noqa: E402

RC_NONE = 0x0
RC_BAD_TAG = 0x7
P = (1 << 130) - 5
M128 = (1 << 128) - 1

# Longest the DUT may take for a chunk / finalize before we call it hung.
CHUNK_BUDGET = 40
FINAL_BUDGET = 80


def le(b: bytes) -> int:
    return int.from_bytes(b, "little")


class Dut:
    def __init__(self, dut):
        self.dut = dut
        self.verdicts = []
        self.tags = []
        cocotb.start_soon(self._monitor())

    async def _monitor(self):
        d = self.dut
        while True:
            await RisingEdge(d.clk)
            if d.v_poly_valid.value == 1:
                self.verdicts.append((int(d.v_poly_fail.value), int(d.v_poly_reason.value)))
            if d.tag_valid.value == 1:
                self.tags.append(
                    (int(d.tag_out.value).to_bytes(16, "little"),
                     int(d.tag_ok.value), int(d.pt_tag_ok.value))
                )

    async def reset(self):
        d = self.dut
        d.rst.value = 1
        for n in ("key_valid", "msg_valid", "msg_sof", "msg_eof", "blk_valid", "blk_last"):
            getattr(d, n).value = 0
        d.key.value = 0
        d.msg_data.value = 0
        d.blk_data.value = 0
        d.blk_len.value = 0
        d.expected_tag.value = 0
        for _ in range(4):
            await FallingEdge(d.clk)
        d.rst.value = 0
        for _ in range(2):
            await FallingEdge(d.clk)
        self.verdicts.clear()
        self.tags.clear()

    async def load_key(self, key: bytes, expected: bytes):
        d = self.dut
        await FallingEdge(d.clk)
        d.key.value = le(key)
        d.expected_tag.value = le(expected)
        d.key_valid.value = 1
        await FallingEdge(d.clk)
        d.key_valid.value = 0

    async def wait_ready(self, budget=CHUNK_BUDGET):
        d = self.dut
        while d.blk_ready.value != 1:
            await FallingEdge(d.clk)
            budget -= 1
            assert budget > 0, "timeout waiting for blk_ready"

    async def send_blk(self, data: bytes, last: bool):
        """One block through the block interface, honouring blk_ready."""
        d = self.dut
        assert 1 <= len(data) <= 16
        await self.wait_ready()
        await FallingEdge(d.clk)
        d.blk_data.value = le(data)
        d.blk_len.value = len(data)
        d.blk_last.value = 1 if last else 0
        d.blk_valid.value = 1
        await FallingEdge(d.clk)
        d.blk_valid.value = 0
        d.blk_last.value = 0

    async def wait_tag(self, n_before, budget=FINAL_BUDGET + CHUNK_BUDGET):
        d = self.dut
        while len(self.tags) == n_before:
            await FallingEdge(d.clk)
            budget -= 1
            assert budget > 0, "timeout waiting for tag_valid"
        return self.tags[-1]

    async def mac_blocks(self, key, msg, expected=None):
        """Whole message through the block interface; returns (tag, ok, pt_ok)."""
        want = poly1305_mac(msg, key)
        await self.load_key(key, want if expected is None else expected)
        n0 = len(self.tags)
        if len(msg) == 0:
            d = self.dut
            await self.wait_ready()
            await FallingEdge(d.clk)
            d.blk_len.value = 0
            d.blk_last.value = 1
            d.blk_valid.value = 1
            await FallingEdge(d.clk)
            d.blk_valid.value = 0
            d.blk_last.value = 0
        else:
            chunks = [msg[i:i + 16] for i in range(0, len(msg), 16)]
            for i, c in enumerate(chunks):
                await self.send_blk(c, i == len(chunks) - 1)
        res = await self.wait_tag(n0)
        return want, res

    async def mac_stream(self, key, msg, expected=None, gap=0, rng=None):
        """Whole message through the streaming-byte interface."""
        d = self.dut
        want = poly1305_mac(msg, key)
        await self.load_key(key, want if expected is None else expected)
        n0 = len(self.tags)
        for i, byte in enumerate(msg):
            await FallingEdge(d.clk)
            d.msg_valid.value = 1
            d.msg_data.value = byte
            d.msg_sof.value = 1 if i == 0 else 0
            d.msg_eof.value = 1 if i == len(msg) - 1 else 0
            await FallingEdge(d.clk)
            d.msg_valid.value = 0
            d.msg_sof.value = 0
            d.msg_eof.value = 0
            g = gap if rng is None else rng.randint(0, gap)
            for _ in range(g):
                await FallingEdge(d.clk)
        res = await self.wait_tag(n0)
        return want, res


async def start(dut):
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    h = Dut(dut)
    await h.reset()
    return h


def rkey(rng):
    return bytes(rng.randrange(256) for _ in range(32))


def rmsg(rng, n):
    return bytes(rng.randrange(256) for _ in range(n))


def check(h, want, res, label, ok=1):
    tag, tag_ok, pt_ok = res
    assert tag == want, f"{label}: tag {tag.hex()} != model {want.hex()}"
    assert tag_ok == ok and pt_ok == ok, f"{label}: tag_ok={tag_ok} pt_ok={pt_ok}"


@cocotb.test()
async def block_interface_random(dut):
    """Random lengths 0..300 through blk_valid/blk_ready match the model."""
    h = await start(dut)
    rng = random.Random(0xB10C)
    lengths = [0, 1, 2, 15, 16, 17, 31, 32, 33, 64, 100, 255, 256, 300]
    lengths += [rng.randint(0, 300) for _ in range(40)]
    for n in lengths:
        key, msg = rkey(rng), rmsg(rng, n)
        want, res = await h.mac_blocks(key, msg)
        check(h, want, res, f"blk len{n}")
    assert all(v == (0, RC_NONE) for v in h.verdicts)


@cocotb.test()
async def stream_interface_random(dut):
    """Random lengths through the streaming byte port (back-to-back and gapped)."""
    h = await start(dut)
    rng = random.Random(0x57EA)
    lengths = [1, 2, 15, 16, 17, 31, 32, 33, 34, 47, 48, 49, 100]
    lengths += [rng.randint(1, 120) for _ in range(25)]
    for n in lengths:
        key, msg = rkey(rng), rmsg(rng, n)
        for gap in (0, 3):
            want, res = await h.mac_stream(key, msg, gap=gap, rng=rng)
            check(h, want, res, f"stream len{n} gap{gap}")


@cocotb.test()
async def carry_stress(dut):
    """Maximal r and all-ones data: every limb, carry and wrap path is hit."""
    h = await start(dut)
    rng = random.Random(0xCA77)
    keys = [
        b"\xff" * 16 + b"\xff" * 16,
        b"\xff" * 16 + b"\x00" * 16,
        bytes([0xff, 0xff, 0xff, 0x0f] * 4) + rkey(rng)[16:],
        b"\x00" * 32,
    ]
    for key in keys:
        for n in (1, 16, 17, 32, 48, 96, 160):
            for msg in (b"\xff" * n, b"\x00" * n, b"\x80" * n):
                want, res = await h.mac_blocks(key, msg)
                check(h, want, res, f"stress key{key[:4].hex()} len{n} {msg[:1].hex()}")


@cocotb.test()
async def tamper_flags(dut):
    """A wrong expected tag drops with RC_BAD_TAG; a right one passes."""
    h = await start(dut)
    rng = random.Random(0x7A60)
    for n in (1, 16, 40):
        key, msg = rkey(rng), rmsg(rng, n)
        good = poly1305_mac(msg, key)
        bad = bytes([good[0] ^ 1]) + good[1:]
        h.verdicts.clear()
        want, res = await h.mac_blocks(key, msg, expected=bad)
        check(h, want, res, f"tamper len{n}", ok=0)
        await FallingEdge(dut.clk)
        assert h.verdicts == [(1, RC_BAD_TAG)], f"verdict {h.verdicts}"
        h.verdicts.clear()
        want, res = await h.mac_blocks(key, msg)
        check(h, want, res, f"clean len{n}", ok=1)
        await FallingEdge(dut.clk)
        assert h.verdicts == [(0, RC_NONE)], f"verdict {h.verdicts}"


@cocotb.test()
async def chacha_poly_feed_pattern(dut):
    """Blocks pulsed every 16 clocks with no blk_ready check, as chacha_poly does."""
    h = await start(dut)
    rng = random.Random(0xFEED)
    d = dut
    for n in (16, 32, 64, 160, 400, 1024):
        key, msg = rkey(rng), rmsg(rng, n)
        want = poly1305_mac(msg, key)
        await h.load_key(key, want)
        n0 = len(h.tags)
        chunks = [msg[i:i + 16] for i in range(0, len(msg), 16)]
        for i, c in enumerate(chunks):
            await FallingEdge(d.clk)
            d.blk_data.value = le(c)
            d.blk_len.value = len(c)
            d.blk_last.value = 1 if i == len(chunks) - 1 else 0
            d.blk_valid.value = 1
            await FallingEdge(d.clk)
            d.blk_valid.value = 0
            d.blk_last.value = 0
            if i != len(chunks) - 1:
                for _ in range(14):          # 16 clocks between pulses
                    await FallingEdge(d.clk)
        res = await h.wait_tag(n0)
        check(h, want, res, f"paced len{n}")


@cocotb.test()
async def final_reduction_corners(dut):
    """Finalize chosen loose accumulators: carry-out of limb 9 and acc >= p."""
    h = await start(dut)
    d = dut
    rng = random.Random(0xF1A1)

    def lanes(v):  # v given as list of 10 lane ints (each < 2^14)
        out = 0
        for i, x in enumerate(v):
            out |= x << (14 * i)
        return out

    def value(v):
        return sum(x << (13 * i) for i, x in enumerate(v))

    M13 = (1 << 13) - 1
    cases = []
    # canonical-range values at and just above p, and p-1
    cases.append([0x1FFB + 0] + [M13] * 9)                 # == p        -> 0
    cases.append([0x1FFF] + [M13] * 9)                     # == 2^130-1  -> 4
    cases.append([0x1FFA] + [M13] * 9)                     # == p-1      -> p-1
    cases.append([0x1FFB + 3] + [M13] * 9)                 # p+3         -> 3
    # loose lanes that carry out of limb 9 (value >= 2^130)
    cases.append([10756] + [8704] * 9)
    cases.append([16383] * 10)                             # beyond the proven bound, still < 2^131
    cases.append([0] * 9 + [16383])
    cases.append([M13] * 9 + [M13 + 4000])
    for _ in range(300):
        cases.append([rng.randint(0, 10756) for _ in range(10)])
    for _ in range(100):
        cases.append([rng.choice([0, M13, M13 + 1, 8704, 10756]) for _ in range(10)])

    for lv in cases:
        v = value(lv)
        if v >= 1 << 131:
            continue
        s = rng.getrandbits(128)
        key = bytes(16) + s.to_bytes(16, "little")
        want = ((v % P) + s) & M128
        await h.load_key(key, want.to_bytes(16, "little"))
        n0 = len(h.tags)
        # sof with no byte -> S_BUF_WAIT, acc cleared; then deposit acc and
        # eof_seen so the empty-buffer branch falls into finalization.
        await FallingEdge(d.clk)
        d.msg_sof.value = 1
        await FallingEdge(d.clk)
        d.msg_sof.value = 0
        d.acc.value = lanes(lv)
        d.eof_seen.value = 1
        res = await h.wait_tag(n0)
        got = le(res[0])
        assert got == want, f"lanes {lv}: tag {got:032x} != {want:032x}"
        assert res[1] == 1, "tag_ok low for matching expected_tag"


def test_runner():
    """pytest / `python test_poly1305.py` entry: build with iverilog and run."""
    from cocotb.runner import get_runner

    rtl = REPO / "rtl"
    runner = get_runner(os.getenv("SIM", "icarus"))
    runner.build(
        sources=[rtl / "crypto" / "chacha_poly" / "poly1305.v"],
        includes=[rtl / "control"],
        hdl_toplevel="poly1305",
        build_dir=REPO / "sim" / "sim_build" / "poly1305",
        always=True,
    )
    runner.test(
        hdl_toplevel="poly1305",
        test_module="test_poly1305",
        build_dir=REPO / "sim" / "sim_build" / "poly1305",
        test_dir=Path(__file__).resolve().parent,
    )


if __name__ == "__main__":
    test_runner()

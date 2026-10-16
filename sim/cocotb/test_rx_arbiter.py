"""
sim/cocotb/test_rx_arbiter.py
Seam test: the real rx_arbiter feeding the real deframer.

WHAT IT PROVES
  1. A single source passes through byte-exact and at the UART byte pace.
  2. Two sources sending at once: every frame of each source arrives intact and
     in that source's order, and when both have frames waiting the arbiter
     alternates (no starvation).
  3. A source that stalls mid-frame produces RC_FRAME_TIMEOUT from the deframer,
     and a good frame from the OTHER source sent right afterwards is not
     swallowed as the tail of the truncated one (the hold).
  4. A bad CRC and a malformed length still produce their own verdicts.
  5. Overflowing the buffers is counted (drop_a/drop_b, drop_sticky), never silent.
  6. A back-to-back stream from one source (the flood) loses nothing.
"""

import os
import random
import struct
import sys

import cocotb
import pytest
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO)
from model.pipeline import build_wire_frame, RC_CRC_FAIL, RC_FRAME_TIMEOUT, RC_MALFORMED  # noqa: E402

BYTE_CYCLES = 100          # 10 clocks/bit x 10 bits; BAUD_RATE overridden to 10 MHz
PACE = 100                 # floor(10*CLK_HZ/BAUD)
TIMEOUT = 3000


class Mon:
    """Collects deframed frames, verdicts and arbiter output spacing."""

    def __init__(self, dut):
        self.dut = dut
        self.frames, self.verdicts, self.arb_times = [], [], []
        self.cur = bytearray()
        self.t = 0
        cocotb.start_soon(self.run())

    async def run(self):
        d = self.dut
        while True:
            await RisingEdge(d.clk)
            self.t += 1
            if d.arb_valid.value == 1:
                self.arb_times.append(self.t)
            if d.out_valid.value == 1:
                self.cur.append(int(d.out_data.value))
                if d.out_eof.value == 1:
                    self.frames.append(bytes(self.cur))
                    self.cur = bytearray()
            if d.verdict_valid.value == 1:
                v = (int(d.verdict_fail.value), int(d.verdict_code.value))
                self.verdicts.append(v)
                if v[1] == RC_FRAME_TIMEOUT:
                    self.cur = bytearray()      # aborted frame: discard its streamed bytes


async def reset(dut):
    dut.rst.value = 1
    for s in ("a_valid", "b_valid"):
        getattr(dut, s).value = 0
    dut.a_data.value = 0
    dut.b_data.value = 0
    for _ in range(4):
        await RisingEdge(dut.clk)
    dut.rst.value = 0
    for _ in range(4):
        await RisingEdge(dut.clk)


async def send(dut, src, data: bytes, gap_after=0):
    """One byte every BYTE_CYCLES clocks, like a uart_rx at line rate."""
    v, d = getattr(dut, f"{src}_valid"), getattr(dut, f"{src}_data")
    for b in data:
        v.value, d.value = 1, b
        await RisingEdge(dut.clk)
        v.value = 0
        for _ in range(BYTE_CYCLES - 1):
            await RisingEdge(dut.clk)
    for _ in range(gap_after):
        await RisingEdge(dut.clk)


async def settle(dut, cycles):
    for _ in range(cycles):
        await RisingEdge(dut.clk)


def pay(tag, i, n=24):
    return bytes([tag]) + bytes([(i * 7 + j) & 0xFF for j in range(n - 1)])


@cocotb.test()
async def single_source_exact_and_paced(dut):
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset(dut)
    mon = Mon(dut)
    pl = [pay(0xA0, i, 20 + i) for i in range(5)]
    for p in pl:
        await send(dut, "a", build_wire_frame(p))
    await settle(dut, 3000)
    assert mon.frames == pl, "single source not passed byte-exact"
    assert all(v == (0, 0) for v in mon.verdicts) and len(mon.verdicts) == 5, mon.verdicts
    gaps = [b - a for a, b in zip(mon.arb_times, mon.arb_times[1:])]
    assert min(gaps) >= PACE, f"drain faster than the UART byte pace: {min(gaps)}"
    assert int(dut.fwd_a.value) == 5 and int(dut.drop_a.value) == 0


@cocotb.test()
async def two_sources_intact_in_order_and_fair(dut):
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset(dut)
    mon = Mon(dut)
    a = [pay(0xA0, i, 16) for i in range(3)]
    b = [pay(0xB0, i, 16) for i in range(3)]

    async def tx(src, pls):
        for p in pls:
            await send(dut, src, build_wire_frame(p))

    ta = cocotb.start_soon(tx("a", a))
    tb = cocotb.start_soon(tx("b", b))
    await ta
    await tb
    await settle(dut, 20000)
    dut._log.info(f"frames={[ (f[0],f[1]) for f in mon.frames]} drops={int(dut.drop_a.value)},{int(dut.drop_b.value)} fwd={int(dut.fwd_a.value)},{int(dut.fwd_b.value)} verdicts={mon.verdicts}")
    assert sorted(mon.frames) == sorted(a + b), "frame lost or corrupted"
    assert [f for f in mon.frames if f[0] == 0xA0] == a, "A reordered"
    assert [f for f in mon.frames if f[0] == 0xB0] == b, "B reordered"
    order = [f[0] for f in mon.frames]
    assert max(len(list(g)) for g in _runs(order)) <= 2, f"starvation: {order}"
    assert int(dut.drop_a.value) == 0 and int(dut.drop_b.value) == 0


def _runs(xs):
    out, cur = [], []
    for x in xs:
        if cur and cur[-1] != x:
            out.append(cur)
            cur = []
        cur.append(x)
    if cur:
        out.append(cur)
    return out


@cocotb.test()
async def truncated_frame_times_out_and_does_not_eat_the_next(dut):
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset(dut)
    mon = Mon(dut)
    # B promises 100 bytes, sends 20, then goes silent.
    await send(dut, "b", struct.pack(">H", 100) + bytes(range(18)))
    good = pay(0xA5, 1, 30)
    await settle(dut, 500)
    await send(dut, "a", build_wire_frame(good))     # arrives while B is stalled
    await settle(dut, 3 * TIMEOUT + 5000)
    codes = [v for v in mon.verdicts if v[0] == 1]
    assert (1, RC_FRAME_TIMEOUT) in codes, f"no FRAME_TIMEOUT: {mon.verdicts}"
    assert good in mon.frames, "good frame from A was swallowed by the truncated one"
    assert mon.verdicts[-1] == (0, 0)


@cocotb.test()
async def bad_crc_and_malformed_length_still_reported(dut):
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset(dut)
    mon = Mon(dut)
    f = bytearray(build_wire_frame(pay(0xC0, 0, 20)))
    f[-1] ^= 0xFF
    await send(dut, "b", bytes(f))
    await settle(dut, 1000)
    await send(dut, "b", struct.pack(">H", 3) + b"\x00" * 6)   # total_len < 6
    await settle(dut, 3 * TIMEOUT)
    got = [v[1] for v in mon.verdicts if v[0] == 1]
    assert RC_CRC_FAIL in got, mon.verdicts
    assert RC_MALFORMED in got, mon.verdicts


@cocotb.test()
async def overflow_is_counted_not_silent(dut):
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset(dut)
    mon = Mon(dut)
    # Park the drain on a long frame, then push more short frames than the four
    # slots can hold.
    long_frame = build_wire_frame(pay(0xA0, 0, 400))
    shorts = [build_wire_frame(pay(0xB0, i, 12)) for i in range(12)]
    await send(dut, "a", long_frame)          # fully buffered; now it drains for ~40k clocks
    await settle(dut, 200)
    for s_ in shorts:                         # 12 frames land while the drain is busy
        await send(dut, "b", s_)
    await settle(dut, 120000)
    drops = int(dut.drop_a.value) + int(dut.drop_b.value)
    delivered = len(mon.frames)
    assert drops >= 1, "test did not actually overflow the buffers"
    assert delivered + drops == 13, f"{delivered} delivered + {drops} dropped != 13 sent"
    assert int(dut.drop_sticky.value) == 1


@cocotb.test()
async def line_rate_flood_from_one_source_loses_nothing(dut):
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset(dut)
    mon = Mon(dut)
    n = 40
    pls = [pay(0xB0, i, 40) for i in range(n)]
    for p in pls:
        await send(dut, "b", build_wire_frame(p))      # zero gap between frames
    await settle(dut, 6000)
    assert mon.frames == pls
    assert int(dut.drop_b.value) == 0 and int(dut.drop_sticky.value) == 0


@pytest.mark.parametrize("sim_build", ["sim_build_rx_arbiter"])
def test_runner(sim_build):
    from cocotb.runner import get_runner
    proj = REPO
    srcs = [os.path.join(proj, "rtl", "ingress", f) for f in
            ("crc32.v", "deframer.v", "rx_frame_buf.v", "rx_arbiter.v")]
    srcs.append(os.path.join(proj, "sim", "cocotb", "rx_arb_seam_top.v"))
    inc = [os.path.join(proj, "rtl", "control")]
    runner = get_runner("icarus")
    runner.build(verilog_sources=srcs, includes=inc, hdl_toplevel="rx_arb_seam_top",
                 build_dir=os.path.join(proj, "sim", sim_build), always=True)
    runner.test(hdl_toplevel="rx_arb_seam_top", test_module="test_rx_arbiter",
                test_dir=os.path.join(proj, "sim", "cocotb"))


if __name__ == "__main__":
    test_runner("sim_build_rx_arbiter")

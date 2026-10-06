"""
cocotb testbench for rtl/control/drop_engine.v  (Member D)

No Python twin exists for the drop engine in model/, so `EngineModel` below is
the reference.  It is written from docs/Member A/interface_contract.md
section 6 (strobe-based merge, priority order, telemetry exception), NOT from
the RTL, and all expectations are computed from it at run time.

Contract rules mirrored by the model
  * DATA packets wait for CRC, PROTO, CAM, CMS, POLY; HANDSHAKE packets wait
    for CRC, PROTO, CMS.  Reserved type 2'b11 is rejected as MALFORMED.
  * An out-of-band frame-timeout (deframer) fail commits immediately.
  * Dominant reason: CRC > TIMEOUT > MALFORMED > BAD_TAG > SIGNATURE > FLOOD
    > SCAN > KEY_INVALID.
  * Every reason that asserted is counted, EXCEPT SIGNATURE when BAD_TAG also
    asserted (v1.1.0 telemetry exception).
  * Counters saturate at 0xFFFFFFFF.

Timing convention: inputs are driven on the falling edge, so a strobe driven
for "cycle c" is sampled by the c-th rising edge after the packet's sof.

Run:  python sim/cocotb/test_drop_engine.py     (or pytest)
"""

import os
import random
import sys
from pathlib import Path

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import FallingEdge

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

RC_NONE, RC_CRC, RC_TIMEOUT, RC_MALFORMED, RC_SIG, RC_FLOOD, RC_SCAN, \
    RC_BAD_TAG, RC_KEY_INVALID = 0, 1, 2, 3, 4, 5, 6, 7, 8

HS_INIT, DATA, HS_RESP, RESERVED = 0, 1, 2, 3
LANES = ["crc", "deframe", "proto", "cam", "cms", "poly", "kem"]
EXPECTED = {
    DATA: {"crc", "proto", "cam", "cms", "poly"},
    HS_INIT: {"crc", "proto", "cms"},
    HS_RESP: {"crc", "proto", "cms"},
    RESERVED: set(),
}
CNT = ["crc_fail", "frame_timeout", "malformed", "signature", "flood",
       "scan", "bad_tag", "handshake_key_invalid", "total_drops", "total_passed"]
SAT = 0xFFFFFFFF


class EngineModel:
    def __init__(self):
        self.c = {k: 0 for k in CNT}

    def packet(self, ptype, events):
        """
        events: list of (cycle, lane, fail, reason), cycle >= 0 (0 = the sof
        cycle).  Returns (fail, reason) and updates counters.
        """
        reported, flags = set(), set()
        if ptype == RESERVED:
            flags.add("proto")
        done = None
        for c in range(0, 64):
            for (cy, lane, fail, reason) in events:
                if cy != c:
                    continue
                if lane == "deframe":
                    if fail:
                        flags.add("deframe")
                elif lane == "kem":
                    if fail:
                        flags.add("kem")
                else:
                    reported.add(lane)
                    if fail:
                        if lane == "cms":
                            flags.add("scan" if reason == RC_SCAN else "flood")
                        else:
                            flags.add(lane)
            # the engine can only commit from the cycle after sof
            if c >= 1 and (EXPECTED[ptype] <= reported or "deframe" in flags
                           or ptype == RESERVED):
                done = set(flags)
                break
        assert done is not None, "model: packet never committed"
        return self._commit(done)

    def _commit(self, f):
        order = [("crc", RC_CRC), ("deframe", RC_TIMEOUT), ("proto", RC_MALFORMED),
                 ("poly", RC_BAD_TAG), ("cam", RC_SIG), ("flood", RC_FLOOD),
                 ("scan", RC_SCAN), ("kem", RC_KEY_INVALID)]
        reason = RC_NONE
        for name, rc in order:
            if name in f:
                reason = rc
                break
        fail = int(bool(f))
        if fail:
            self._inc("total_drops")
            m = {"crc": "crc_fail", "deframe": "frame_timeout", "proto": "malformed",
                 "flood": "flood", "scan": "scan", "poly": "bad_tag",
                 "kem": "handshake_key_invalid"}
            for name, cnt in m.items():
                if name in f:
                    self._inc(cnt)
            if "cam" in f and "poly" not in f:      # v1.1.0 telemetry exception
                self._inc("signature")
        else:
            self._inc("total_passed")
        return fail, reason

    def _inc(self, k):
        if self.c[k] != SAT:
            self.c[k] += 1


class Dut:
    def __init__(self, dut):
        self.d = dut
        self.drops = []          # (fail, reason) per drop_valid pulse
        cocotb.start_soon(self._mon())

    async def _mon(self):
        d = self.d
        while True:
            await FallingEdge(d.clk)
            if d.drop_valid.value == 1:
                self.drops.append((int(d.drop_fail.value), int(d.drop_reason.value)))

    def idle(self):
        d = self.d
        d.pkt_sof.value = 0
        d.pkt_eof.value = 0
        d.pkt_type.value = 0
        for ln in LANES:
            getattr(d, f"v_{ln if ln != 'deframe' else 'deframe'}_valid").value = 0
            getattr(d, f"v_{ln}_fail").value = 0
            getattr(d, f"v_{ln}_reason").value = 0

    async def reset(self):
        d = self.d
        d.rst.value = 1
        self.idle()
        for _ in range(4):
            await FallingEdge(d.clk)
        d.rst.value = 0
        for _ in range(2):
            await FallingEdge(d.clk)
        self.drops.clear()

    async def run_packet(self, ptype, events, tail=6):
        """Drive sof at cycle 0 plus the scheduled strobes; wait for quiet."""
        d = self.d
        self.drops.clear()
        last = max([cy for cy, *_ in events] + [1])
        for c in range(0, last + 1):
            await FallingEdge(d.clk)
            self.idle()
            if c == 0:
                d.pkt_sof.value = 1
                d.pkt_type.value = ptype
            for (cy, lane, fail, reason) in events:
                if cy == c:
                    getattr(d, f"v_{lane}_valid").value = 1
                    getattr(d, f"v_{lane}_fail").value = fail
                    getattr(d, f"v_{lane}_reason").value = reason
        for _ in range(tail):
            await FallingEdge(d.clk)
            self.idle()
        return list(self.drops)

    def counters(self):
        return {k: int(getattr(self.d, f"cnt_{k}").value) for k in CNT}


async def start(dut):
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    h = Dut(dut)
    await h.reset()
    return h


def check(h, m, ptype, events, label):
    """run one packet on RTL + model and compare verdict and all counters."""
    async def go():
        drops = await h.run_packet(ptype, events)
        exp = m.packet(ptype, events)
        assert drops == [exp], f"{label}: RTL verdict {drops} != model {exp} (type={ptype} events={events})"
        got = h.counters()
        assert got == m.c, f"{label}: counters RTL {got} != model {m.c}"
    return go()


def ev(cycle, lane, fail=0, reason=None):
    if reason is None:
        reason = {"crc": RC_CRC, "deframe": RC_TIMEOUT, "proto": RC_MALFORMED,
                  "cam": RC_SIG, "cms": RC_FLOOD, "poly": RC_BAD_TAG,
                  "kem": RC_KEY_INVALID}[lane] if fail else RC_NONE
    return (cycle, lane, fail, reason)


@cocotb.test()
async def clean_packets_pass(dut):
    """Every type, all lanes pass: one pass verdict, total_passed counts."""
    h = await start(dut)
    m = EngineModel()
    for ptype in (DATA, HS_INIT, HS_RESP):
        events = [ev(i + 1, ln) for i, ln in enumerate(sorted(EXPECTED[ptype]))]
        await check(h, m, ptype, events, f"clean type{ptype}")
    assert m.c["total_passed"] == 3 and m.c["total_drops"] == 0


@cocotb.test()
async def each_single_fault_each_reason(dut):
    """One failing lane at a time -> its reason code, one counter, one drop."""
    h = await start(dut)
    m = EngineModel()
    for ptype in (DATA, HS_INIT):
        for lane in sorted(EXPECTED[ptype]):
            reasons = [RC_FLOOD, RC_SCAN] if lane == "cms" else [None]
            for r in reasons:
                events = [ev(1, ln, 1 if ln == lane else 0, r if ln == lane else None)
                          for ln in sorted(EXPECTED[ptype])]
                await check(h, m, ptype, events, f"type{ptype} {lane} r={r}")


@cocotb.test()
async def priority_order_pairs(dut):
    """Every pair of simultaneous faults resolves by the contract priority."""
    h = await start(dut)
    m = EngineModel()
    fault_lanes = ["crc", "proto", "cam", "cms", "poly"]
    for i, a in enumerate(fault_lanes):
        for b in fault_lanes[i + 1:]:
            events = [ev(1, ln, 1 if ln in (a, b) else 0) for ln in sorted(EXPECTED[DATA])]
            await check(h, m, DATA, events, f"pair {a}+{b}")
    # flood vs scan share the CMS lane, so exercise scan alone beside sig
    events = [ev(1, ln, 1 if ln in ("cam", "cms") else 0,
                 RC_SCAN if ln == "cms" else None) for ln in sorted(EXPECTED[DATA])]
    await check(h, m, DATA, events, "sig+scan")


@cocotb.test()
async def bad_tag_suppresses_signature_count(dut):
    """v1.1.0: BAD_TAG + SIGNATURE counts BAD_TAG only; SIGNATURE alone counts."""
    h = await start(dut)
    m = EngineModel()
    both = [ev(1, "crc"), ev(1, "proto"), ev(1, "cms"), ev(1, "cam", 1), ev(2, "poly", 1)]
    await check(h, m, DATA, both, "tag+sig")
    assert m.c["bad_tag"] == 1 and m.c["signature"] == 0
    sig = [ev(1, "crc"), ev(1, "proto"), ev(1, "cms"), ev(1, "cam", 1), ev(2, "poly")]
    await check(h, m, DATA, sig, "sig only")
    assert m.c["signature"] == 1


@cocotb.test()
async def reserved_type_is_malformed(dut):
    """pkt_type 2'b11 is rejected as MALFORMED without waiting for any lane."""
    h = await start(dut)
    m = EngineModel()
    await check(h, m, RESERVED, [], "reserved")
    assert m.c["malformed"] == 1


@cocotb.test()
async def out_of_band_frame_timeout(dut):
    """A deframer timeout commits immediately even if lanes are still pending."""
    h = await start(dut)
    m = EngineModel()
    await check(h, m, DATA, [ev(3, "deframe", 1), ev(6, "crc"), ev(7, "cam")], "timeout early")
    await check(h, m, HS_INIT, [ev(1, "crc"), ev(1, "proto"), ev(2, "cms"),
                                ev(1, "deframe", 1)], "timeout same cycle")


@cocotb.test()
async def late_lane_delays_the_verdict(dut):
    """No verdict is emitted until the slowest expected lane has reported."""
    h = await start(dut)
    m = EngineModel()
    events = [ev(1, "crc"), ev(2, "proto"), ev(3, "cms"), ev(4, "cam"), ev(25, "poly")]
    drops = await h.run_packet(DATA, events, tail=3)
    assert drops == [(0, RC_NONE)], f"verdict {drops}"
    exp = m.packet(DATA, events)
    assert exp == (0, RC_NONE) and h.counters() == m.c


@cocotb.test()
async def random_packets_match_model(dut):
    """1500 random packets: random lane order, faults, kem and timeouts."""
    h = await start(dut)
    m = EngineModel()
    rng = random.Random(0xD20F)
    for n in range(1500):
        ptype = rng.choice([DATA, DATA, HS_INIT, HS_RESP, RESERVED])
        events = []
        if ptype != RESERVED:
            for ln in sorted(EXPECTED[ptype]):
                fail = int(rng.random() < 0.25)
                reason = None
                if ln == "cms" and fail:
                    reason = rng.choice([RC_FLOOD, RC_SCAN])
                events.append(ev(rng.randint(0, 8), ln, fail, reason))
        if rng.random() < 0.15:
            events.append(ev(rng.randint(0, 8), "kem", 1))
        if rng.random() < 0.10:
            events.append(ev(rng.randint(0, 8), "deframe", 1))
        await check(h, m, ptype, events, f"rand{n}")


@cocotb.test()
async def counters_saturate(dut):
    """32-bit counters stick at 0xFFFFFFFF instead of wrapping."""
    h = await start(dut)
    dut.cnt_total_drops.value = SAT - 1
    dut.cnt_crc_fail.value = SAT - 1
    await FallingEdge(dut.clk)
    m = EngineModel()
    m.c["total_drops"] = SAT - 1
    m.c["crc_fail"] = SAT - 1
    bad = [ev(1, "crc", 1), ev(1, "proto"), ev(1, "cms"), ev(1, "cam"), ev(1, "poly")]
    for i in range(4):
        await check(h, m, DATA, bad, f"sat{i}")
    assert m.c["total_drops"] == SAT and m.c["crc_fail"] == SAT


def test_runner():
    """pytest / `python test_drop_engine.py` entry: build with iverilog and run."""
    from cocotb.runner import get_runner

    rtl = REPO / "rtl"
    runner = get_runner(os.getenv("SIM", "icarus"))
    runner.build(
        sources=[rtl / "control" / "drop_engine.v"],
        includes=[rtl / "control"],
        hdl_toplevel="drop_engine",
        build_dir=REPO / "sim" / "sim_build" / "drop_engine",
        always=True,
    )
    runner.test(
        hdl_toplevel="drop_engine",
        test_module="test_drop_engine",
        build_dir=REPO / "sim" / "sim_build" / "drop_engine",
        test_dir=Path(__file__).resolve().parent,
    )


if __name__ == "__main__":
    test_runner()

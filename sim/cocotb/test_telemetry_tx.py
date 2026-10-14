#==========================================================================
# sim/cocotb/test_telemetry_tx.py
#
# Tests rtl/io/telemetry_tx.v, the periodic counter readout the host displays.
# The decoder on the other end is test-network/wire.py:parse_telemetry, so these
# tests use it directly: if the two ever disagree, this fails rather than the
# demo quietly showing wrong numbers.
#
# Tests:
#   tel_frame_decodes_and_matches   a frame decodes, checksum valid, every
#                                   counter lands in the right field
#   tel_snapshot_is_coherent        counters changing mid-frame do not tear: the
#                                   frame reports one consistent instant
#   tel_periodic                    frames keep coming at the configured period
#   tel_respects_tx_busy            no byte is presented while the transmitter
#                                   is busy, which is how the shared UART stays
#                                   uncorrupted when handshake_tx has priority
#
# Built with PERIOD_MS=1 so a frame arrives quickly; the shipped default is 250
# (demo_config.DISPLAY_REFRESH_S).
#==========================================================================

import os
import sys

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import FallingEdge

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "test-network"))

import wire                                   # noqa: E402

COUNTERS = ["cnt_crc_fail", "cnt_frame_timeout", "cnt_malformed", "cnt_signature",
            "cnt_flood", "cnt_scan", "cnt_bad_tag", "cnt_handshake_key_invalid",
            "cnt_total_drops", "cnt_total_passed", "cnt_lane_timeout",
            "cnt_stray_verdict"]
FIELDS = wire.TELEMETRY_FIELDS      # same order, without the cnt_ prefix


async def reset_dut(dut, values=None, status=(0, 0, 0)):
    dut.rst.value = 1
    for i, c in enumerate(COUNTERS):
        getattr(dut, c).value = 0 if values is None else values[i]
    dut.session_established.value = status[0]
    dut.fifo_overflow.value = status[1]
    dut.kem_busy.value = status[2]
    dut.tx_busy.value = 0
    for _ in range(3):
        await FallingEdge(dut.clk)
    dut.rst.value = 0
    await FallingEdge(dut.clk)


async def capture_bytes(dut, n, max_cycles=400000, busy_cycles=0):
    """Accept bytes on the tx handshake, optionally asserting tx_busy after each
    one to model a real transmitter."""
    out = bytearray()
    for _ in range(max_cycles):
        await FallingEdge(dut.clk)
        if int(dut.tx_valid.value):
            assert int(dut.tx_busy.value) == 0, \
                "a byte was presented while the transmitter was busy"
            out.append(int(dut.tx_data.value))
            if busy_cycles:
                dut.tx_busy.value = 1
                for _ in range(busy_cycles):
                    await FallingEdge(dut.clk)
                dut.tx_busy.value = 0
        if len(out) >= n:
            break
    return bytes(out)


@cocotb.test()
async def tel_frame_decodes_and_matches(dut):
    """One frame, decoded by the host's own parser, with every counter in the
    right field and the checksum valid."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    vals = [(i + 1) * 0x01010101 & 0xFFFFFFFF for i in range(12)]
    await reset_dut(dut, vals, status=(1, 0, 1))

    raw = await capture_bytes(dut, 52)
    assert len(raw) == 52, f"frame is {len(raw)} bytes, expected 52"
    frames, left = wire.parse_telemetry(raw)
    assert frames, (f"the host decoder rejected the frame "
                    f"(checksum sum = {sum(raw) & 0xFF}, expected 0)")
    f = frames[0]
    assert not left, f"{len(left)} trailing bytes"
    for name, want in zip(FIELDS, vals):
        assert f[name] == want, f"{name}: decoded {f[name]:#x}, driven {want:#x}"
    assert f["session_established"] is True
    assert f["fifo_overflow"] is False
    assert f["kem_busy"] is True


@cocotb.test()
async def tel_snapshot_is_coherent(dut):
    """Counters are latched once per frame, so a frame is one instant rather
    than a mix of values from different cycles. Changing every counter while a
    frame is in flight must not change that frame."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    first = [i + 1 for i in range(12)]
    await reset_dut(dut, first)

    out = bytearray()
    changed = False
    for _ in range(400000):
        await FallingEdge(dut.clk)
        if int(dut.tx_valid.value):
            out.append(int(dut.tx_data.value))
            if len(out) == 6 and not changed:
                # tear the counters wide open mid-frame
                for c in COUNTERS:
                    getattr(dut, c).value = 0xDEADBEEF
                changed = True
        if len(out) >= 52:
            break
    assert changed, "never got far enough into a frame to change the counters"
    frames, _ = wire.parse_telemetry(bytes(out))
    assert frames, "frame failed its checksum after a mid-frame counter change"
    f = frames[0]
    for name, want in zip(FIELDS, first):
        assert f[name] == want, (
            f"{name} reported {f[name]:#x} but the frame began with {want}: "
            "the snapshot tore")


@cocotb.test()
async def tel_periodic(dut):
    """Frames keep arriving, so the host display does not go stale."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut, [7] * 12)
    raw = await capture_bytes(dut, 52 * 3)
    frames, _ = wire.parse_telemetry(raw)
    assert len(frames) >= 3, f"only {len(frames)} frames in {len(raw)} bytes"
    for f in frames:
        assert f["total_drops"] == 7


@cocotb.test()
async def tel_respects_tx_busy(dut):
    """pqc_nids_top shares one UART between this module and handshake_tx. A byte
    presented while the transmitter is busy would be dropped or would corrupt a
    handshake frame, so tx_busy must be honoured."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut, [3] * 12)
    raw = await capture_bytes(dut, 52, busy_cycles=5)
    frames, _ = wire.parse_telemetry(raw)
    assert frames, "frame corrupted when the transmitter applied backpressure"
    assert frames[0]["signature"] == 3


# ==============================================================================
# Runner for pytest / command-line execution
# ==============================================================================
import pytest


@pytest.mark.parametrize("sim_build", ["sim_build_telemetry_tx"])
def test_runner(sim_build):
    from cocotb.runner import get_runner

    proj = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    runner = get_runner("icarus")
    runner.build(verilog_sources=[os.path.join(proj, "rtl", "io", "telemetry_tx.v")],
                 includes=[os.path.join(proj, "rtl", "control")],
                 hdl_toplevel="telemetry_tx",
                 parameters={"PERIOD_MS": 1},
                 build_dir=os.path.join(proj, "sim", sim_build), always=True)
    runner.test(hdl_toplevel="telemetry_tx", test_module="test_telemetry_tx",
                test_dir=os.path.join(proj, "sim", "cocotb"))


if __name__ == "__main__":
    test_runner("sim_build_telemetry_tx")

"""
demo_forward/test_msg_fwd.py   (run from repo root: python demo_forward/test_msg_fwd.py)

Unit test for msg_fwd against a stub UART (byte time = 20 clocks).
Proves: pass -> payload + CRLF delivered exactly, and only after the verdict;
fail verdict -> nothing leaves; bad tag -> nothing leaves even on a pass verdict;
a non-DATA verdict (no message) is ignored; two messages back to back;
an oversize payload is discarded and counted.
"""
import os
import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge

HERE = os.path.dirname(os.path.abspath(__file__))
BUSY = 20


async def init(dut):
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    for s in ("pt_valid", "pt_sof", "pt_eof", "pt_tag_ok", "pt_tag_valid",
              "drop_valid", "drop_fail", "tx_busy"):
        getattr(dut, s).value = 0
    dut.pt_data.value = 0
    dut.rst.value = 1
    for _ in range(4):
        await RisingEdge(dut.clk)
    dut.rst.value = 0
    await RisingEdge(dut.clk)
    out = bytearray()

    async def uart():
        left = 0
        while True:
            await RisingEdge(dut.clk)
            if int(dut.tx_valid.value):
                out.append(int(dut.tx_data.value))
                left = BUSY
            dut.tx_busy.value = 1 if left else 0
            if left:
                left -= 1
    cocotb.start_soon(uart())
    return out


async def feed(dut, data, tag_ok=None):
    for i, b in enumerate(data):
        dut.pt_valid.value = 1
        dut.pt_data.value = b
        dut.pt_sof.value = int(i == 0)
        dut.pt_eof.value = int(i == len(data) - 1)
        await RisingEdge(dut.clk)
        dut.pt_valid.value = 0
        dut.pt_sof.value = 0
        dut.pt_eof.value = 0
        await RisingEdge(dut.clk)
    if tag_ok is not None:
        dut.pt_tag_valid.value = 1
        dut.pt_tag_ok.value = int(tag_ok)
        await RisingEdge(dut.clk)
        dut.pt_tag_valid.value = 0


async def verdict(dut, fail):
    dut.drop_valid.value = 1
    dut.drop_fail.value = int(fail)
    await RisingEdge(dut.clk)
    dut.drop_valid.value = 0
    dut.drop_fail.value = 0


async def wait(dut, n):
    for _ in range(n):
        await RisingEdge(dut.clk)


@cocotb.test()
async def pass_delivers_with_crlf(dut):
    out = await init(dut)
    await feed(dut, b"hello bob", tag_ok=True)
    await wait(dut, 30)
    assert bytes(out) == b"", "released before the verdict"
    await verdict(dut, fail=False)
    await wait(dut, 600)
    assert bytes(out) == b"hello bob\r\n"
    assert int(dut.cnt_delivered.value) == 1


@cocotb.test()
async def fail_and_badtag_deliver_nothing(dut):
    out = await init(dut)
    await feed(dut, b"attack ${jndi:", tag_ok=True)
    await verdict(dut, fail=True)
    await feed(dut, b"tampered", tag_ok=False)
    await verdict(dut, fail=False)
    await wait(dut, 600)
    assert bytes(out) == b""
    assert int(dut.cnt_discarded.value) == 2
    assert int(dut.cnt_delivered.value) == 0


@cocotb.test()
async def stray_verdict_ignored_then_two_messages(dut):
    out = await init(dut)
    await verdict(dut, fail=False)
    await feed(dut, b"one", tag_ok=True)
    await verdict(dut, fail=False)
    await wait(dut, 400)
    await feed(dut, b"two!", tag_ok=True)
    await verdict(dut, fail=False)
    await wait(dut, 500)
    assert bytes(out) == b"one\r\ntwo!\r\n"


@cocotb.test()
async def oversize_is_discarded(dut):
    out = await init(dut)
    await feed(dut, bytes(range(256)) * 3, tag_ok=True)
    await verdict(dut, fail=False)
    await wait(dut, 300)
    assert bytes(out) == b""
    assert int(dut.cnt_oversize.value) == 1


def test_runner():
    from cocotb.runner import get_runner
    r = get_runner("icarus")
    r.build(verilog_sources=[os.path.join(HERE, "msg_fwd.v")],
            hdl_toplevel="msg_fwd",
            build_dir=os.path.join(HERE, "sim_build_msg_fwd"), always=True)
    r.test(hdl_toplevel="msg_fwd", test_module="test_msg_fwd", test_dir=HERE)


if __name__ == "__main__":
    test_runner()

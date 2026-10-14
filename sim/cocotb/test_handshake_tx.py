#==========================================================================
# sim/cocotb/test_handshake_tx.py
#
# Tests rtl/io/handshake_tx.v, which transmits the ML-KEM ciphertext reply.
#
# Without this reply the handshake is one-sided: the initiator can never derive
# the shared secret, so no data packet can ever decrypt and the demo cannot run.
# The frame has to be byte-exact against what deframer.v decodes, so these tests
# rebuild the expected 816 bytes in Python and compare the whole frame.
#
# Tests:
#   hstx_frame_is_byte_exact        every byte, against an independent build
#   hstx_crc_and_ip_checksum        the receiver's own CRC-32 accepts it, and
#                                   the IPv4 header checksum is valid
#   hstx_busy_covers_the_last_byte  busy must not drop before uart_tx has taken
#                                   the final byte -- it did, and the frame went
#                                   out one byte short
#   hstx_back_to_back_replies       two handshakes in a row both transmit fully
#==========================================================================

import os
import sys

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import FallingEdge

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO)

from model.pipeline import compute_crc32          # noqa: E402

CT_BYTES, HDR_BYTES, TOTAL_LEN = 768, 42, 816
PORT_HS_INIT, PORT_HS_RESP = 51001, 51002

RX_ETH_SRC = 0x001122334455      # the initiator
RX_ETH_DST = 0xAABBCCDDEEFF      # us
RX_IP_SRC = 0x0A000001
RX_IP_DST = 0x0A0000FF


def ip_checksum(hdr: bytes) -> int:
    t = 0
    for i in range(0, len(hdr), 2):
        t += int.from_bytes(hdr[i:i + 2], "big")
    while t >> 16:
        t = (t & 0xFFFF) + (t >> 16)
    return (~t) & 0xFFFF


def expected_frame(ct: bytes, ip_id: int) -> bytes:
    """Independent build of the frame handshake_tx should produce. Addresses are
    the received ones, reversed, so the reply reaches the initiator."""
    eth = RX_ETH_SRC.to_bytes(6, "big") + RX_ETH_DST.to_bytes(6, "big") + b"\x08\x00"
    ip_len = 20 + 8 + CT_BYTES
    ip_nc = (b"\x45\x00" + ip_len.to_bytes(2, "big") + ip_id.to_bytes(2, "big")
             + b"\x00\x00" + bytes([64, 17]) + b"\x00\x00"
             + RX_IP_DST.to_bytes(4, "big") + RX_IP_SRC.to_bytes(4, "big"))
    ip = ip_nc[:10] + ip_checksum(ip_nc).to_bytes(2, "big") + ip_nc[12:]
    udp = (PORT_HS_INIT.to_bytes(2, "big") + PORT_HS_RESP.to_bytes(2, "big")
           + (8 + CT_BYTES).to_bytes(2, "big") + b"\x00\x00")
    payload = eth + ip + udp + ct
    assert len(payload) == HDR_BYTES + CT_BYTES
    return (TOTAL_LEN.to_bytes(2, "big") + payload
            + compute_crc32(payload).to_bytes(4, "big"))


async def reset_dut(dut):
    dut.rst.value = 1
    dut.send_req.value = 0
    dut.tx_busy.value = 0
    dut.rx_eth_src_mac.value = RX_ETH_SRC
    dut.rx_eth_dst_mac.value = RX_ETH_DST
    dut.rx_ip_src_addr.value = RX_IP_SRC
    dut.rx_ip_dst_addr.value = RX_IP_DST
    dut.c_ram_rdata.value = 0
    for _ in range(3):
        await FallingEdge(dut.clk)
    dut.rst.value = 0
    await FallingEdge(dut.clk)


async def serve_c_ram(dut, ct: bytes):
    """Model mlkem_top's c_ram: 96 words of 64 bits, bytes little-endian within
    a word, read combinationally from c_ram_rd_addr."""
    while True:
        a = int(dut.c_ram_rd_addr.value)
        dut.c_ram_rdata.value = int.from_bytes(ct[8 * a:8 * a + 8], "little")
        await FallingEdge(dut.clk)


async def collect(dut, max_cycles=20000, tx_busy_cycles=0):
    """Accept bytes on the tx handshake and return them, with busy observed on
    the cycle each byte was handed over."""
    out, busy_seen = bytearray(), []
    for _ in range(max_cycles):
        await FallingEdge(dut.clk)
        if int(dut.tx_valid.value):
            out.append(int(dut.tx_data.value))
            busy_seen.append(int(dut.busy.value))
            if tx_busy_cycles:
                dut.tx_busy.value = 1
                for _ in range(tx_busy_cycles):
                    await FallingEdge(dut.clk)
                dut.tx_busy.value = 0
        if len(out) >= TOTAL_LEN:
            # let busy settle after the final byte
            for _ in range(tx_busy_cycles + 4):
                await FallingEdge(dut.clk)
            break
    return bytes(out), busy_seen


CT = bytes(((i * 31 + 7) & 0xFF) for i in range(CT_BYTES))


@cocotb.test()
async def hstx_frame_is_byte_exact(dut):
    """The whole 816-byte frame, byte for byte, against an independent build."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)
    cocotb.start_soon(serve_c_ram(dut, CT))

    dut.send_req.value = 1
    await FallingEdge(dut.clk)
    dut.send_req.value = 0

    got, _ = await collect(dut)
    exp = expected_frame(CT, ip_id=1)
    assert len(got) == TOTAL_LEN, f"sent {len(got)} bytes, expected {TOTAL_LEN}"
    if got != exp:
        for i, (a, b) in enumerate(zip(got, exp)):
            if a != b:
                raise AssertionError(
                    f"first difference at byte {i}: sent {a:#04x}, expected {b:#04x}")
    assert got == exp


@cocotb.test()
async def hstx_crc_and_ip_checksum(dut):
    """deframer.v's own CRC-32 must accept the frame, and the IPv4 header
    checksum must be valid so the demo's packet captures are clean."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)
    cocotb.start_soon(serve_c_ram(dut, CT))

    dut.send_req.value = 1
    await FallingEdge(dut.clk)
    dut.send_req.value = 0
    got, _ = await collect(dut)

    assert int.from_bytes(got[0:2], "big") == TOTAL_LEN, "length prefix wrong"
    payload, trailer = got[2:2 + 810], got[2 + 810:]
    assert compute_crc32(payload) == int.from_bytes(trailer, "big"), \
        "the CRC-32 trailer does not cover the payload the way deframer.v computes it"
    assert ip_checksum(payload[14:34]) == 0, "IPv4 header checksum is wrong"
    assert int.from_bytes(payload[36:38], "big") == PORT_HS_RESP, \
        "destination port must classify the reply as HS_RESP"
    assert payload[42:] == CT, "ciphertext body does not match c_ram"


@cocotb.test()
async def hstx_busy_covers_the_last_byte(dut):
    """busy gates the shared UART in pqc_nids_top. It used to clear in the same
    cycle as the final tx_valid, handing the transmitter back to telemetry_tx
    before uart_tx had taken the byte -- measured as 815 of 816 bytes on the
    wire. busy must still be high for every byte, including the last."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)
    cocotb.start_soon(serve_c_ram(dut, CT))

    dut.send_req.value = 1
    await FallingEdge(dut.clk)
    dut.send_req.value = 0
    got, busy_seen = await collect(dut, tx_busy_cycles=2)

    assert len(got) == TOTAL_LEN, f"only {len(got)} of {TOTAL_LEN} bytes sent"
    assert all(busy_seen), (
        f"busy was low while handing over byte "
        f"{busy_seen.index(0)} of {len(busy_seen)}")
    assert int(dut.busy.value) == 0, "busy never released after the frame"


@cocotb.test()
async def hstx_back_to_back_replies(dut):
    """Two handshakes in a row: both frames go out in full, and the IPv4
    identification field advances so the two are distinguishable in a capture."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)
    cocotb.start_soon(serve_c_ram(dut, CT))

    ids = []
    for n in range(2):
        # busy means "transmitting"; send_req is only honoured in S_IDLE, so a
        # caller must wait for busy to clear between frames.
        for _ in range(500):
            if int(dut.busy.value) == 0:
                break
            await FallingEdge(dut.clk)
        assert int(dut.busy.value) == 0, f"reply {n}: still busy from the last frame"
        dut.send_req.value = 1
        await FallingEdge(dut.clk)
        dut.send_req.value = 0
        got, _ = await collect(dut)
        assert len(got) == TOTAL_LEN, f"reply {n}: {len(got)} bytes"
        payload = got[2:2 + 810]
        assert compute_crc32(payload) == int.from_bytes(got[2 + 810:], "big"), \
            f"reply {n}: bad CRC"
        ids.append(int.from_bytes(payload[18:20], "big"))
    assert ids[0] != ids[1], f"IPv4 id did not advance between replies: {ids}"


# ==============================================================================
# Runner for pytest / command-line execution
# ==============================================================================
import pytest


@pytest.mark.parametrize("sim_build", ["sim_build_handshake_tx"])
def test_runner(sim_build):
    from cocotb.runner import get_runner

    proj = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    runner = get_runner("icarus")
    runner.build(verilog_sources=[os.path.join(proj, "rtl", "io", "handshake_tx.v"),
                                  os.path.join(proj, "rtl", "ingress", "crc32.v")],
                 includes=[os.path.join(proj, "rtl", "control"),
                           os.path.join(proj, "rtl", "ingress")],
                 hdl_toplevel="handshake_tx",
                 build_dir=os.path.join(proj, "sim", sim_build), always=True)
    runner.test(hdl_toplevel="handshake_tx", test_module="test_handshake_tx",
                test_dir=os.path.join(proj, "sim", "cocotb"))


if __name__ == "__main__":
    test_runner("sim_build_handshake_tx")

#==========================================================================
# sim/cocotb/test_seam3_aead_session.py
#
# Seam-3 joint test: REAL session_mgr.v -> REAL aead_framer.v -> REAL
# chacha_poly.v, with no model of any of them in the datapath (the C17
# pattern). Expected values come from model/chacha_poly.py, which self-tests
# against the published RFC 8439 vectors.
#
# Tests:
#   seam3_aead_roundtrip             a DATA packet decrypts to the right
#                                    plaintext with a verifying tag
#   seam3_tampered_ciphertext_fails  one flipped byte -> RC_BAD_TAG
#   seam3_rate_independence          identical results at 1, 6 and 333 cycles
#                                    per byte -- the FIFO fix. Without it
#                                    chacha_poly loses payload bytes, because
#                                    the contract's packet bus cannot stall.
#   seam3_nonce_advances             nonce_adv is pulsed and the session's
#                                    counter actually moves, so no two packets
#                                    in a session share a nonce
#   seam3_no_session_still_verdicts  DATA with no session produces exactly one
#                                    poly verdict, so drop_engine cannot stall
#   seam3_short_payload_rejected     a payload too short to hold a tag fails
#   seam3_aad_binds_the_five_tuple   a ciphertext replayed with a rewritten
#                                    source address fails the tag
#==========================================================================

import os
import sys

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import FallingEdge

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO)

from model.chacha_poly import chacha20_poly1305_encrypt  # noqa: E402

RC_NONE, RC_BAD_TAG = 0x0, 0x7
PKT_DATA, PKT_HS_INIT = 0b01, 0b00
SID = 1
IP_SRC, IP_DST = 0x0A000001, 0x0A0000FF
SP, DP = 40000, 51010


def aad_bytes(ip_src=IP_SRC, ip_dst=IP_DST, sport=SP, dport=DP):
    """Must match aead_framer.v: src_ip || dst_ip || src_port || dst_port,
    each big-endian on the wire, byte 0 landing at aad_data[7:0]."""
    return (ip_src.to_bytes(4, "big") + ip_dst.to_bytes(4, "big")
            + sport.to_bytes(2, "big") + dport.to_bytes(2, "big"))


async def reset_dut(dut):
    dut.rst.value = 1
    for s in ("hdr_valid", "packet_type", "payload_len", "session_id",
              "ip_src_addr", "ip_dst_addr", "l4_src_port", "l4_dst_port",
              "pb_valid", "pb_sof", "pb_eof", "pb_data",
              "kem_done", "kem_session_id", "kem_shared_secret",
              "lk_req_tb", "lk_id_tb"):
        getattr(dut, s).value = 0
    for _ in range(3):
        await FallingEdge(dut.clk)
    dut.rst.value = 0
    await FallingEdge(dut.clk)


async def establish(dut, key_int, sid=SID):
    dut.kem_session_id.value = sid
    dut.kem_shared_secret.value = key_int
    dut.kem_done.value = 1
    await FallingEdge(dut.clk)
    dut.kem_done.value = 0
    await FallingEdge(dut.clk)


async def read_nonce(dut, sid=SID):
    dut.lk_id_tb.value = sid
    dut.lk_req_tb.value = 1
    await FallingEdge(dut.clk)
    dut.lk_req_tb.value = 0
    n = int(dut.lk_nonce_tb.value)
    await FallingEdge(dut.clk)
    return n


class Capture:
    """Collects the plaintext stream and the poly verdict for one packet."""

    def __init__(self, dut):
        self.dut = dut
        self.pt = bytearray()
        self.verdicts = []
        self.tag_ok = None
        self.nonce_adv_pulses = 0
        cocotb.start_soon(self._mon())

    async def _mon(self):
        d = self.dut
        while True:
            await FallingEdge(d.clk)
            if int(d.pt_valid.value):
                self.pt.append(int(d.pt_data.value))
            if int(d.pt_tag_valid.value):
                self.tag_ok = int(d.pt_tag_ok.value)
            if int(d.v_poly_valid.value):
                self.verdicts.append((int(d.v_poly_fail.value),
                                      int(d.v_poly_reason.value)))
            if int(d.nonce_adv_o.value):
                self.nonce_adv_pulses += 1


async def send_data_packet(dut, payload, gap=0, sid=SID, ip_src=IP_SRC,
                           ptype=PKT_DATA, claimed_len=None, timeout=60000):
    """Present the header context, then stream the payload with `gap` idle
    cycles between bytes. Returns a Capture once a poly verdict appears."""
    cap = Capture(dut)
    dut.packet_type.value = ptype
    dut.payload_len.value = len(payload) if claimed_len is None else claimed_len
    dut.session_id.value = sid
    dut.ip_src_addr.value = ip_src
    dut.ip_dst_addr.value = IP_DST
    dut.l4_src_port.value = SP
    dut.l4_dst_port.value = DP
    dut.hdr_valid.value = 1
    await FallingEdge(dut.clk)
    dut.hdr_valid.value = 0
    await FallingEdge(dut.clk)

    for i, b in enumerate(payload):
        dut.pb_valid.value = 1
        dut.pb_data.value = b
        dut.pb_sof.value = 1 if i == 0 else 0
        dut.pb_eof.value = 1 if i == len(payload) - 1 else 0
        await FallingEdge(dut.clk)
        dut.pb_valid.value = 0
        dut.pb_sof.value = 0
        dut.pb_eof.value = 0
        for _ in range(gap):
            await FallingEdge(dut.clk)

    for n in range(timeout):
        if cap.verdicts:
            for _ in range(4):
                await FallingEdge(dut.clk)
            return cap
        await FallingEdge(dut.clk)
    raise TimeoutError("no poly verdict")


KEY = bytes(range(32))
KEY_INT = int.from_bytes(KEY, "little")


def encrypt(plaintext, nonce_int, aad=None):
    """Produce the on-wire payload (ciphertext || tag) for `plaintext`."""
    nonce = nonce_int.to_bytes(12, "little")
    ct, tag = chacha20_poly1305_encrypt(KEY, nonce, aad if aad is not None else aad_bytes(),
                                        plaintext)
    return ct + tag, ct, tag


@cocotb.test()
async def seam3_aead_roundtrip(dut):
    """A DATA packet decrypts to the right plaintext and its tag verifies."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)
    await establish(dut, KEY_INT)

    pt = b"GET /index.html HTTP/1.1\r\nHost: demo\r\n\r\n"
    nonce = await read_nonce(dut)
    assert nonce == 0, f"fresh session nonce should be 0, got {nonce}"
    payload, ct, tag = encrypt(pt, nonce)

    cap = await send_data_packet(dut, payload)
    assert cap.verdicts == [(0, RC_NONE)], f"verdicts {cap.verdicts}"
    assert bytes(cap.pt) == pt, f"plaintext mismatch: {bytes(cap.pt)!r}"
    assert cap.tag_ok == 1, "pt_tag_ok low on a valid packet"
    assert int(dut.fifo_overflow.value) == 0


@cocotb.test()
async def seam3_tampered_ciphertext_fails(dut):
    """Flipping one ciphertext byte must fail the tag with RC_BAD_TAG."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)
    await establish(dut, KEY_INT)

    pt = b"A" * 80
    payload, ct, tag = encrypt(pt, await read_nonce(dut))
    bad = bytearray(payload)
    bad[5] ^= 0x01
    cap = await send_data_packet(dut, bytes(bad))
    assert cap.verdicts == [(1, RC_BAD_TAG)], f"verdicts {cap.verdicts}"
    assert cap.tag_ok == 0, "pt_tag_ok high on a tampered packet"


@cocotb.test()
async def seam3_rate_independence(dut):
    """The same packet must give the same result at 1, 6 and 333 cycles per
    byte. chacha_poly alone drops payload bytes when driven faster than it can
    accept them; aead_framer's FIFO is what makes this hold."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    pt = bytes((i * 7) & 0xFF for i in range(200))
    for gap in (0, 5, 332):
        await reset_dut(dut)
        await establish(dut, KEY_INT)
        payload, _, _ = encrypt(pt, await read_nonce(dut))
        cap = await send_data_packet(dut, payload, gap=gap)
        assert cap.verdicts == [(0, RC_NONE)], f"gap={gap}: verdicts {cap.verdicts}"
        assert bytes(cap.pt) == pt, (
            f"gap={gap}: {len(cap.pt)} of {len(pt)} plaintext bytes recovered")
        assert int(dut.fifo_overflow.value) == 0, f"gap={gap}: FIFO overflowed"
        dut._log.info(f"{gap+1} cycles/byte: {len(cap.pt)}/{len(pt)} bytes, tag OK")


@cocotb.test()
async def seam3_nonce_advances(dut):
    """nonce_adv must be pulsed once per packet and the session counter must
    move, so two packets in a session never share a nonce. Nothing drove this
    port before, which meant every packet reused nonce 0."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)
    await establish(dut, KEY_INT)

    seen = []
    for n in range(3):
        nonce = await read_nonce(dut)
        seen.append(nonce)
        payload, _, _ = encrypt(f"packet-{n}".encode() * 4, nonce)
        cap = await send_data_packet(dut, payload)
        assert cap.verdicts == [(0, RC_NONE)], f"packet {n}: {cap.verdicts}"
        assert cap.nonce_adv_pulses == 1, (
            f"packet {n}: nonce_adv pulsed {cap.nonce_adv_pulses} times")
    assert seen == [0, 1, 2], f"nonce did not advance: {seen}"


@cocotb.test()
async def seam3_no_session_still_verdicts(dut):
    """A DATA packet with no established session must still produce exactly one
    poly verdict. drop_engine waits for the poly lane before committing a DATA
    packet, so a missing verdict would stall that packet forever."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)
    # no establish() -- session table is empty

    payload, _, _ = encrypt(b"Z" * 32, 0)
    cap = await send_data_packet(dut, payload, sid=0)
    assert cap.verdicts == [(1, RC_BAD_TAG)], f"verdicts {cap.verdicts}"
    assert int(dut.no_session_drop.value) == 0  # strobe already retired

    # session id on the bus but the table has nothing in that slot
    await reset_dut(dut)
    cap = await send_data_packet(dut, payload, sid=2)
    assert cap.verdicts == [(1, RC_BAD_TAG)], f"verdicts {cap.verdicts}"


@cocotb.test()
async def seam3_short_payload_rejected(dut):
    """A payload shorter than the 16-byte tag cannot be authenticated."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)
    await establish(dut, KEY_INT)
    for n in (0, 1, 15):
        cap = await send_data_packet(dut, bytes(n) if n else b"", claimed_len=n)
        assert cap.verdicts == [(1, RC_BAD_TAG)], f"len {n}: {cap.verdicts}"


@cocotb.test()
async def seam3_aad_binds_the_five_tuple(dut):
    """The AAD covers the 5-tuple, so a validly-tagged ciphertext replayed with a
    rewritten source address must fail. This is what the AAD is for."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)
    await establish(dut, KEY_INT)

    pt = b"transfer 100 to alice"
    payload, _, _ = encrypt(pt, await read_nonce(dut), aad=aad_bytes(ip_src=IP_SRC))
    # same bytes, claimed to come from a different host
    cap = await send_data_packet(dut, payload, ip_src=0x0A0000AB)
    assert cap.verdicts == [(1, RC_BAD_TAG)], (
        f"replay under a rewritten source address was accepted: {cap.verdicts}")


# ==============================================================================
# Runner for pytest / command-line execution
# ==============================================================================
import pytest


@pytest.mark.parametrize("sim_build", ["sim_build_seam3_aead_session"])
def test_runner(sim_build):
    from cocotb.runner import get_runner

    proj_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    sources = [
        os.path.join(proj_path, "rtl", "control", "session_mgr.v"),
        os.path.join(proj_path, "rtl", "crypto", "chacha_poly", "aead_framer.v"),
        os.path.join(proj_path, "rtl", "crypto", "chacha_poly", "chacha20.v"),
        os.path.join(proj_path, "rtl", "crypto", "chacha_poly", "poly1305.v"),
        os.path.join(proj_path, "rtl", "crypto", "chacha_poly", "chacha_poly.v"),
        os.path.join(proj_path, "sim", "seam3_aead_session_top.v"),
    ]
    includes = [os.path.join(proj_path, "rtl", "control"),
                os.path.join(proj_path, "rtl", "crypto", "chacha_poly")]
    runner = get_runner("icarus")
    runner.build(verilog_sources=sources, includes=includes,
                 hdl_toplevel="seam3_aead_session_top",
                 build_dir=os.path.join(proj_path, "sim", sim_build), always=True)
    runner.test(hdl_toplevel="seam3_aead_session_top",
                test_module="test_seam3_aead_session",
                test_dir=os.path.join(proj_path, "sim", "cocotb"))


if __name__ == "__main__":
    test_runner("sim_build_seam3_aead_session")

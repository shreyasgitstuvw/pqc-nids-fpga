#==========================================================================
# sim/cocotb/test_seam1_ingress_session.py
#
# Seam-1 joint test: the REAL parser.v -> REAL session_lookup.v -> REAL
# session_mgr.v, with no model of any of them (the C17 pattern).
#
# The property under test is the one that was broken before session_lookup.v
# existed: a handshake packet arriving on the packet bus must resolve to a
# session id that session_mgr.v accepts, so the ML-KEM shared secret is actually
# stored and the session reaches ESTABLISHED. parser.v's own session_id output is
# a stub that always drives 0, and session_mgr.v rejects 0 as out of range, so
# with parser.v wired straight to session_mgr.v no session could ever establish
# and nothing downstream of the cipher could function.
#
# Tests:
#   seam1_handshake_establishes_session   the chain that used to be dead
#   seam1_regression_parser_id_is_dead    proves the old wiring stores nothing
#   seam1_data_packet_resolves_to_session DATA from an established peer resolves
#   seam1_session_id_stable_before_sof    session_id settles before the payload
#                                         streams, as contract section 3 requires
#   seam1_three_peers_independent         three concurrent sessions stay separate
#   seam1_udp_data_passes_the_validator   a well-formed UDP DATA packet is NOT
#                                         rejected as malformed -- parser.v used
#                                         to publish the raw UDP Length field as
#                                         l4_length, which includes the payload,
#                                         so protocol_validator's length sum
#                                         double-counted it
#==========================================================================

import os
import sys

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import FallingEdge

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO)

from model.pipeline import PORT_HS_INIT, PORT_HS_RESP, PORT_DATA  # noqa: E402

ST_IDLE, ST_ESTAB, ST_REJECT = 0, 2, 3


def build_packet(src_ip, dst_port, payload, protocol=17, src_port=40000):
    """Minimal Ethernet/IPv4/UDP frame, big-endian per contract section 1."""
    eth = bytes.fromhex("aabbccddeeff") + bytes.fromhex("112233445566") + b"\x08\x00"
    l4 = (src_port.to_bytes(2, "big") + dst_port.to_bytes(2, "big")
          + (8 + len(payload)).to_bytes(2, "big") + b"\x00\x00")
    total = 20 + len(l4) + len(payload)
    ip = (b"\x45\x00" + total.to_bytes(2, "big") + b"\x00\x01\x00\x00\x40"
          + bytes([protocol]) + b"\x00\x00"
          + src_ip.to_bytes(4, "big") + bytes.fromhex("0a0000ff"))
    return eth + ip + l4 + payload


async def reset_dut(dut):
    dut.rst.value = 1
    for sig in ("in_valid", "in_data", "in_sof", "in_eof", "kem_done",
                "kem_shared_secret", "kem_key_invalid", "lk_req", "lk_id",
                "nonce_adv", "nonce_adv_id", "clear_req", "clear_id"):
        getattr(dut, sig).value = 0
    for _ in range(3):
        await FallingEdge(dut.clk)
    dut.rst.value = 0
    await FallingEdge(dut.clk)


async def send(dut, frame, watch_sof=False):
    """Stream one frame into parser.v. Returns the session_id seen at out_sof."""
    sid_at_sof = None
    for i, b in enumerate(frame):
        dut.in_valid.value = 1
        dut.in_data.value = b
        dut.in_sof.value = 1 if i == 0 else 0
        dut.in_eof.value = 1 if i == len(frame) - 1 else 0
        await FallingEdge(dut.clk)
        if watch_sof and int(dut.out_sof.value) == 1 and sid_at_sof is None:
            sid_at_sof = int(dut.session_id.value)
    dut.in_valid.value = 0
    dut.in_sof.value = 0
    dut.in_eof.value = 0
    for _ in range(4):
        await FallingEdge(dut.clk)
        if watch_sof and int(dut.out_sof.value) == 1 and sid_at_sof is None:
            sid_at_sof = int(dut.session_id.value)
    return sid_at_sof


async def kem_complete(dut, key):
    """Pulse kem_done with the id session_lookup resolved, as mlkem_top would."""
    dut.kem_shared_secret.value = key
    dut.kem_done.value = 1
    await FallingEdge(dut.clk)
    dut.kem_done.value = 0
    await FallingEdge(dut.clk)


async def lookup(dut, sid):
    dut.lk_id.value = sid
    dut.lk_req.value = 1
    await FallingEdge(dut.clk)
    dut.lk_req.value = 0
    assert int(dut.lk_valid.value) == 1, "lk_valid must answer lk_req next cycle"
    out = (int(dut.lk_state.value), int(dut.lk_ok.value), int(dut.lk_key.value))
    await FallingEdge(dut.clk)
    return out


IP_A, IP_B, IP_C = 0x0A000001, 0x0A000002, 0x0A000003
KEY_A = 0xA5A5 << 200 | 0x1234
KEY_B = 0xB6B6 << 200 | 0x5678


@cocotb.test()
async def seam1_handshake_establishes_session(dut):
    """A handshake packet resolves to a usable id and the key lands in the table.
    This is the chain that was dead before session_lookup.v existed."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    await send(dut, build_packet(IP_A, PORT_HS_INIT, b"\xAA" * 800))
    sid = int(dut.session_id.value)
    assert sid == 1, f"handshake resolved to session_id {sid}, expected 1"
    assert int(dut.packet_type.value) == 0b00
    assert int(dut.sid_allocated.value) == 0  # strobe already retired

    await kem_complete(dut, KEY_A)
    state, ok, key = await lookup(dut, sid)
    assert state == ST_ESTAB, f"session not ESTABLISHED (state={state})"
    assert ok == 1, "lk_ok low on a freshly keyed session"
    assert key == KEY_A, "shared secret not stored"


@cocotb.test()
async def seam1_regression_parser_id_is_dead(dut):
    """The old wiring, reproduced: drive kem_done with session id 0 -- which is
    all parser.v ever emits -- and nothing is stored. This is why the module is
    needed, kept as a regression so the chain cannot silently revert."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    # No handshake, so session_lookup holds 0 -- exactly parser.v's stub value.
    assert int(dut.session_id.value) == 0
    await kem_complete(dut, KEY_A)
    for sid in (0, 1, 2, 3):
        state, ok, key = await lookup(dut, sid)
        assert state != ST_ESTAB, f"id {sid} established from a session_id of 0"
        assert key == 0, f"id {sid} stored key material from a session_id of 0"


@cocotb.test()
async def seam1_data_packet_resolves_to_session(dut):
    """After the handshake, a DATA packet from the same peer resolves to the same
    id, so the AEAD framer can fetch that session's key."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    await send(dut, build_packet(IP_A, PORT_HS_INIT, b"\xAA" * 800))
    await kem_complete(dut, KEY_A)

    await send(dut, build_packet(IP_A, PORT_DATA, b"payload-bytes" * 4, protocol=6))
    assert int(dut.packet_type.value) == 0b01, "DATA port did not classify as DATA"
    sid = int(dut.session_id.value)
    assert sid == 1, f"DATA from the handshaken peer resolved to {sid}"
    state, ok, key = await lookup(dut, sid)
    assert (state, ok, key) == (ST_ESTAB, 1, KEY_A)

    # DATA from a peer that never handshook must resolve to 0
    await send(dut, build_packet(IP_C, PORT_DATA, b"x" * 16, protocol=6))
    assert int(dut.session_id.value) == 0, "unestablished peer resolved to a session"


@cocotb.test()
async def seam1_session_id_stable_before_sof(dut):
    """Contract section 3 requires the header fields to be stable for the whole
    packet presentation. Check session_id is already correct on the out_sof
    cycle, i.e. the one-cycle lookup lands before the payload streams."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    await send(dut, build_packet(IP_A, PORT_HS_INIT, b"\xAA" * 64))
    await kem_complete(dut, KEY_A)

    sid_at_sof = await send(dut, build_packet(IP_A, PORT_DATA, b"Z" * 64, protocol=6),
                            watch_sof=True)
    assert sid_at_sof is not None, "never observed out_sof"
    assert sid_at_sof == 1, f"session_id was {sid_at_sof} on the out_sof cycle, expected 1"


@cocotb.test()
async def seam1_three_peers_independent(dut):
    """Three peers hold three separate sessions with three separate keys."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    keys = {}
    for ip, k in ((IP_A, KEY_A), (IP_B, KEY_B), (IP_C, 0xCCCC << 180 | 0x99)):
        await send(dut, build_packet(ip, PORT_HS_RESP, b"\x55" * 768))
        sid = int(dut.session_id.value)
        assert sid in (1, 2, 3), f"{ip:#x} resolved to {sid}"
        await kem_complete(dut, k)
        keys[sid] = k

    assert len(keys) == 3, f"peers collided onto {len(keys)} slots"
    for sid, k in keys.items():
        state, ok, key = await lookup(dut, sid)
        assert (state, ok) == (ST_ESTAB, 1), f"session {sid} not established"
        assert key == k, f"session {sid} holds the wrong key"


# ==============================================================================
# Runner for pytest / command-line execution

@cocotb.test()
async def seam1_udp_data_passes_the_validator(dut):
    """A well-formed UDP DATA packet must pass protocol_validator. parser.v
    published the raw UDP Length field (header + payload) as l4_length, while
    the validator sums 20 + l4_length + payload_len, so the payload was counted
    twice and every UDP packet carrying a payload was rejected as RC_MALFORMED.
    The parser now publishes the L4 header length for both protocols."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    verdicts = []

    async def mon():
        while True:
            await FallingEdge(dut.clk)
            if int(dut.v_proto_valid.value):
                verdicts.append((int(dut.v_proto_fail.value),
                                 int(dut.v_proto_reason.value),
                                 int(dut.l4_length.value)))

    cocotb.start_soon(mon())

    async def one(payload, protocol, label):
        verdicts.clear()
        await send(dut, build_packet(IP_A, PORT_DATA, payload, protocol=protocol))
        assert verdicts, f"{label}: protocol_validator never strobed"
        return verdicts[-1]

    for n in (1, 16, 100, 400):
        fail, reason, l4len = await one(b"U" * n, 17, f"UDP payload {n}")
        assert l4len == 8, f"UDP payload {n}: l4_length {l4len}, expected the 8-byte header"
        assert fail == 0, f"UDP payload {n}: validator said malformed (reason {reason:#x})"

    fail, reason, l4len = await one(b"T" * 100, 6, "TCP payload 100")
    assert l4len == 20, f"TCP l4_length {l4len}, expected the 20-byte header"
    assert fail == 0, f"TCP DATA rejected (reason {reason:#x})"

    fail, reason, _ = await one(b"X" * 32, 1, "ICMP")
    assert fail == 1, "ICMP should be rejected"
    assert reason == 0x3, f"ICMP reason {reason:#x}, expected RC_MALFORMED"

# ==============================================================================
import pytest


@pytest.mark.parametrize("sim_build", ["sim_build_seam1_ingress_session"])
def test_runner(sim_build):
    from cocotb.runner import get_runner

    proj_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    sources = [
        os.path.join(proj_path, "rtl", "ingress", "parser.v"),
        os.path.join(proj_path, "rtl", "control", "session_lookup.v"),
        os.path.join(proj_path, "rtl", "control", "session_mgr.v"),
        os.path.join(proj_path, "rtl", "detect", "protocol_validator.v"),
        os.path.join(proj_path, "sim", "seam1_ingress_session_top.v"),
    ]
    includes = [os.path.join(proj_path, "rtl", "control"),
                os.path.join(proj_path, "rtl", "ingress"),
                os.path.join(proj_path, "rtl", "detect")]
    runner = get_runner("icarus")
    runner.build(verilog_sources=sources, includes=includes,
                 hdl_toplevel="seam1_ingress_session_top",
                 build_dir=os.path.join(proj_path, "sim", sim_build), always=True)
    runner.test(hdl_toplevel="seam1_ingress_session_top",
                test_module="test_seam1_ingress_session",
                test_dir=os.path.join(proj_path, "sim", "cocotb"))


if __name__ == "__main__":
    test_runner("sim_build_seam1_ingress_session")

#==========================================================================
# sim/cocotb/test_session_lookup.py
#
# Tests rtl/control/session_lookup.v against a reference model written from
# the module's documented policy (interface_contract.md section 3 for the
# packet-bus session_id field, section 5 / session_mgr.v decision 1 for the
# usable id range 1..3).
#
# Tests:
#   lookup_allocate_and_hit        3 peers get ids 1,2,3; their DATA packets
#                                  resolve to the same ids; re-handshake reuses
#   lookup_unknown_data_is_zero    DATA from an unestablished peer -> 0, and a
#                                  reserved packet_type -> 0
#   lookup_eviction_round_robin    a 4th peer evicts round-robin, and the
#                                  evicted peer's DATA then misses
#   lookup_clear_frees_slot        clear_req invalidates a slot and the freed
#                                  slot is reused before any eviction
#   lookup_stability_and_strobes   session_id holds between hdr_valid strobes,
#                                  sid_valid is exactly one cycle
#   lookup_random_vs_model         400 random operations against the model
#==========================================================================

import os
import random
import sys

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import FallingEdge, RisingEdge

PKT_HS_INIT, PKT_DATA, PKT_HS_RESP, PKT_RESERVED = 0b00, 0b01, 0b10, 0b11
SLOTS = 3


class LookupModel:
    """Reference model of session_lookup.v's documented allocation policy."""

    def __init__(self):
        self.key = [None] * SLOTS       # None = unoccupied
        self.victim = 0
        self.sid = 0                    # held output

    def clear(self, cid):
        if 1 <= cid <= SLOTS:
            self.key[cid - 1] = None

    def header(self, ptype, src_ip):
        hit = next((i for i, k in enumerate(self.key) if k == src_ip), None)
        free = next((i for i, k in enumerate(self.key) if k is None), None)
        allocated = evicted = False
        if ptype in (PKT_HS_INIT, PKT_HS_RESP):
            if hit is not None:
                slot = hit
            elif free is not None:
                slot, allocated = free, True
            else:
                slot, allocated, evicted = self.victim, True, True
                self.victim = (self.victim + 1) % SLOTS
            self.key[slot] = src_ip
            self.sid = slot + 1
            return self.sid, hit is not None, allocated, evicted
        if ptype == PKT_DATA and hit is not None:
            self.sid = hit + 1
            return self.sid, True, False, False
        self.sid = 0
        return 0, False, False, False


async def reset_dut(dut):
    dut.rst.value = 1
    dut.hdr_valid.value = 0
    dut.ip_src_addr.value = 0
    dut.packet_type.value = 0
    dut.clear_req.value = 0
    dut.clear_id.value = 0
    for _ in range(3):
        await FallingEdge(dut.clk)
    dut.rst.value = 0
    await FallingEdge(dut.clk)


async def header(dut, ptype, src_ip):
    """Drive one hdr_valid strobe; return (session_id, hit, allocated, evicted)."""
    dut.packet_type.value = ptype
    dut.ip_src_addr.value = src_ip
    dut.hdr_valid.value = 1
    # Inputs are driven on the falling edge; the DUT samples them on the rising
    # edge in between, so its registered outputs are readable at the next
    # falling edge.
    await FallingEdge(dut.clk)
    dut.hdr_valid.value = 0
    assert int(dut.sid_valid.value) == 1, "sid_valid must strobe one cycle after hdr_valid"
    out = (int(dut.session_id.value), int(dut.sid_hit.value),
           int(dut.sid_allocated.value), int(dut.sid_evicted.value))
    await FallingEdge(dut.clk)
    assert int(dut.sid_valid.value) == 0, "sid_valid must be exactly one cycle"
    return out


async def clear(dut, cid):
    dut.clear_id.value = cid
    dut.clear_req.value = 1
    await FallingEdge(dut.clk)
    dut.clear_req.value = 0
    await FallingEdge(dut.clk)


IP_A, IP_B, IP_C, IP_D = 0x0A000001, 0x0A000002, 0x0A000003, 0x0A000004


@cocotb.test()
async def lookup_allocate_and_hit(dut):
    """Three peers handshake and get ids 1,2,3; their DATA resolves to the same
    ids; a repeat handshake reuses the slot rather than allocating."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)
    for ip, want in ((IP_A, 1), (IP_B, 2), (IP_C, 3)):
        sid, hit, alloc, evict = await header(dut, PKT_HS_INIT, ip)
        assert (sid, hit, alloc, evict) == (want, 0, 1, 0), (ip, sid, hit, alloc, evict)
    for ip, want in ((IP_A, 1), (IP_B, 2), (IP_C, 3)):
        sid, hit, alloc, _ = await header(dut, PKT_DATA, ip)
        assert (sid, hit, alloc) == (want, 1, 0), f"DATA from {ip:#x} -> {sid}"
    # HS_RESP from a peer that already holds a slot must reuse it
    sid, hit, alloc, evict = await header(dut, PKT_HS_RESP, IP_B)
    assert (sid, hit, alloc, evict) == (2, 1, 0, 0)


@cocotb.test()
async def lookup_unknown_data_is_zero(dut):
    """DATA from an unestablished peer resolves to 0, and so does a reserved type.
    0 is what session_mgr rejects as out of range, which is the correct outcome."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)
    sid, hit, _, _ = await header(dut, PKT_DATA, IP_A)
    assert (sid, hit) == (0, 0), f"unknown DATA gave {sid}"
    await header(dut, PKT_HS_INIT, IP_A)
    sid, _, _, _ = await header(dut, PKT_RESERVED, IP_A)
    assert sid == 0, f"reserved type gave {sid}"
    sid, hit, _, _ = await header(dut, PKT_DATA, IP_D)
    assert (sid, hit) == (0, 0)


@cocotb.test()
async def lookup_eviction_round_robin(dut):
    """With all three slots live, a fourth peer evicts round-robin starting at
    slot 0, and the evicted peer's DATA then misses."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)
    for ip in (IP_A, IP_B, IP_C):
        await header(dut, PKT_HS_INIT, ip)
    sid, hit, alloc, evict = await header(dut, PKT_HS_INIT, IP_D)
    assert (sid, hit, alloc, evict) == (1, 0, 1, 1), (sid, hit, alloc, evict)
    sid, hit, _, _ = await header(dut, PKT_DATA, IP_A)
    assert (sid, hit) == (0, 0), "evicted peer still resolves"
    sid, _, _, _ = await header(dut, PKT_DATA, IP_D)
    assert sid == 1
    # next eviction takes slot 1
    sid, _, _, evict = await header(dut, PKT_HS_INIT, IP_A)
    assert (sid, evict) == (2, 1), (sid, evict)


@cocotb.test()
async def lookup_clear_frees_slot(dut):
    """clear_req invalidates a slot, and the freed slot is reused before any
    eviction happens."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)
    for ip in (IP_A, IP_B, IP_C):
        await header(dut, PKT_HS_INIT, ip)
    await clear(dut, 2)
    sid, hit, _, _ = await header(dut, PKT_DATA, IP_B)
    assert (sid, hit) == (0, 0), "cleared session still resolves"
    sid, hit, alloc, evict = await header(dut, PKT_HS_INIT, IP_D)
    assert (sid, alloc, evict) == (2, 1, 0), f"freed slot not reused: {sid} evict={evict}"


@cocotb.test()
async def lookup_stability_and_strobes(dut):
    """session_id is held stable between hdr_valid strobes -- contract section 3
    requires the header fields to be stable for the whole packet."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)
    sid, _, _, _ = await header(dut, PKT_HS_INIT, IP_A)
    assert sid == 1
    for _ in range(40):
        await FallingEdge(dut.clk)
        assert int(dut.session_id.value) == 1, "session_id changed between packets"
        assert int(dut.sid_valid.value) == 0


@cocotb.test()
async def lookup_random_vs_model(dut):
    """400 random operations checked against the reference model."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)
    rng = random.Random(0xA11CE)
    model = LookupModel()
    ips = [0x0A000000 + i for i in range(1, 7)]
    for n in range(400):
        if rng.random() < 0.08:
            cid = rng.randrange(0, 5)
            await clear(dut, cid)
            model.clear(cid)
            continue
        ptype = rng.choice([PKT_HS_INIT, PKT_HS_RESP, PKT_DATA, PKT_DATA, PKT_RESERVED])
        ip = rng.choice(ips)
        got = await header(dut, ptype, ip)
        exp = model.header(ptype, ip)
        assert got == exp, f"op {n} type={ptype} ip={ip:#x}: RTL {got} != model {exp}"


# ==============================================================================
# Runner for pytest / command-line execution
# ==============================================================================
import pytest


@pytest.mark.parametrize("sim_build", ["sim_build_session_lookup"])
def test_runner(sim_build):
    from cocotb.runner import get_runner

    proj_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    sources = [os.path.join(proj_path, "rtl", "control", "session_lookup.v")]
    includes = [os.path.join(proj_path, "rtl", "control")]
    runner = get_runner("icarus")
    runner.build(verilog_sources=sources, includes=includes, hdl_toplevel="session_lookup",
                 build_dir=os.path.join(proj_path, "sim", sim_build), always=True)
    runner.test(hdl_toplevel="session_lookup", test_module="test_session_lookup",
                test_dir=os.path.join(proj_path, "sim", "cocotb"))


if __name__ == "__main__":
    test_runner("sim_build_session_lookup")

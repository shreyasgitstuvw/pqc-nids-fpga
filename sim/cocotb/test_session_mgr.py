"""
cocotb testbench for rtl/control/session_mgr.v  (Member D)

There is no pre-existing Python twin for the session table (model/ has none),
so the reference model lives here as `SessionModel`.  It is written from
docs/Member A/interface_contract.md section 5, NOT from the RTL, and every
expected value is computed by it at run time.

Rules under test (contract sec 5 / AGENTS.md @control):
  * kem_done writes the key and sets ESTABLISHED unconditionally.
  * REJECTED is reachable ONLY through kem_key_invalid, never via kem_done.
  * A genuine key and a decoy key are indistinguishable at every observable
    output except the key value itself (state / ok / nonce / strobe timing).
  * Session id 0 and ids >= 4 are out of range (see session_mgr.v decision 1).

Run:  python sim/cocotb/test_session_mgr.py     (or pytest)
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

IDLE, ESTAB, REJECT = 0, 2, 3
MAXN = (1 << 64) - 1


class SessionModel:
    """Contract-derived reference: ids 1..3 usable, 4 storage entries."""

    def __init__(self):
        self.t = {}  # idx -> dict(state, key, nonce)

    @staticmethod
    def valid(sid):
        return 1 <= sid <= 3

    def kem_done(self, sid, key):
        if self.valid(sid):
            self.t[sid] = dict(state=ESTAB, key=key, nonce=0)

    def kem_invalid(self, sid):
        if self.valid(sid):
            self.t[sid] = dict(state=REJECT, key=0, nonce=0)

    def adv(self, sid):
        e = self.t.get(sid)
        if self.valid(sid) and e and e["state"] == ESTAB and e["nonce"] != MAXN:
            e["nonce"] += 1

    def lookup(self, sid):
        """-> (ok, key, nonce, state)"""
        e = self.t.get(sid) if self.valid(sid) else None
        if e is None:
            return (0, 0, 0, IDLE)
        ok = int(e["state"] == ESTAB and e["nonce"] != MAXN)
        return (ok, e["key"], e["nonce"], e["state"])


class Dut:
    def __init__(self, dut):
        self.d = dut
        self.valid_seen = 0   # lk_valid pulses observed
        cocotb.start_soon(self._mon())

    async def _mon(self):
        while True:
            await FallingEdge(self.d.clk)
            if self.d.lk_valid.value == 1:
                self.valid_seen += 1

    async def reset(self):
        d = self.d
        d.rst.value = 1
        d.kem_done.value = 0
        d.kem_session_id.value = 0
        d.kem_shared_secret.value = 0
        d.kem_key_invalid.value = 0
        d.lk_req.value = 0
        d.lk_id.value = 0
        d.nonce_adv.value = 0
        d.nonce_adv_id.value = 0
        for _ in range(4):
            await FallingEdge(d.clk)
        d.rst.value = 0
        for _ in range(2):
            await FallingEdge(d.clk)

    async def kem_done(self, sid, key):
        d = self.d
        await FallingEdge(d.clk)
        d.kem_done.value = 1
        d.kem_session_id.value = sid
        d.kem_shared_secret.value = key
        await FallingEdge(d.clk)
        d.kem_done.value = 0

    async def kem_invalid(self, sid):
        d = self.d
        await FallingEdge(d.clk)
        d.kem_key_invalid.value = 1
        d.kem_session_id.value = sid
        await FallingEdge(d.clk)
        d.kem_key_invalid.value = 0

    async def adv(self, sid):
        d = self.d
        await FallingEdge(d.clk)
        d.nonce_adv.value = 1
        d.nonce_adv_id.value = sid
        await FallingEdge(d.clk)
        d.nonce_adv.value = 0

    async def lookup(self, sid):
        """One request.  lk_valid must be a 1-cycle strobe one cycle later."""
        d = self.d
        before = self.valid_seen
        await FallingEdge(d.clk)
        d.lk_req.value = 1
        d.lk_id.value = sid
        await FallingEdge(d.clk)          # answer is visible now
        d.lk_req.value = 0
        assert d.lk_valid.value == 1, "lk_valid not high one cycle after lk_req"
        res = (int(d.lk_ok.value), int(d.lk_key.value),
               int(d.lk_nonce.value), int(d.lk_state.value))
        await FallingEdge(d.clk)
        assert d.lk_valid.value == 0, "lk_valid must be a 1-cycle strobe"
        return res


async def start(dut):
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    h = Dut(dut)
    await h.reset()
    return h


def rkey(rng):
    return rng.getrandbits(256)


def expect(model, sid, got, label):
    ok, key, nonce, state = got
    m_ok, m_key, m_nonce, m_state = model.lookup(sid)
    # RTL exposes the 96-bit ChaCha nonce = {32'h0, counter64}
    assert (ok, key, nonce, state) == (m_ok, m_key, m_nonce, m_state), (
        f"{label}: id={sid} RTL(ok={ok},state={state},nonce={nonce},key={key:#x}) "
        f"!= model(ok={m_ok},state={m_state},nonce={m_nonce},key={m_key:#x})")


@cocotb.test()
async def reset_state_is_idle(dut):
    """After reset every id looks IDLE with a zero key and no ok."""
    h = await start(dut)
    m = SessionModel()
    for sid in (0, 1, 2, 3, 4, 0x0101):
        expect(m, sid, await h.lookup(sid), "reset")


@cocotb.test()
async def random_ops_match_model(dut):
    """4000 random operations (no kem_invalid) vs the contract model."""
    h = await start(dut)
    m = SessionModel()
    rng = random.Random(0x5E55)
    ids = [0, 1, 2, 3, 4, 5, 0x0101, 0xFFFF]
    for n in range(4000):
        op = rng.choice(["done", "adv", "adv", "look", "look"])
        sid = rng.choice(ids)
        if op == "done":
            k = rkey(rng)
            await h.kem_done(sid, k)
            m.kem_done(sid, k)
        elif op == "adv":
            await h.adv(sid)
            m.adv(sid)
        else:
            expect(m, sid, await h.lookup(sid), f"op{n}")
            # REJECTED must be unreachable without kem_key_invalid
            assert m.lookup(sid)[3] != REJECT
    for sid in ids:
        expect(m, sid, await h.lookup(sid), "final")


@cocotb.test()
async def structural_failure_is_the_only_way_to_rejected(dut):
    """kem_key_invalid -> REJECTED, key zeroised, ok=0; kem_done recovers."""
    h = await start(dut)
    m = SessionModel()
    rng = random.Random(11)
    for sid in (1, 2, 3):
        k = rkey(rng)
        await h.kem_done(sid, k)
        m.kem_done(sid, k)
        await h.adv(sid); m.adv(sid)
        await h.kem_invalid(sid)
        m.kem_invalid(sid)
        got = await h.lookup(sid)
        expect(m, sid, got, "after invalid")
        assert got[3] == REJECT and got[0] == 0 and got[1] == 0
        await h.adv(sid); m.adv(sid)            # must not move a REJECTED nonce
        expect(m, sid, await h.lookup(sid), "adv on rejected")
        k2 = rkey(rng)
        await h.kem_done(sid, k2)               # re-key after rejection
        m.kem_done(sid, k2)
        expect(m, sid, await h.lookup(sid), "re-keyed")
    # invalid on an out-of-range id must not touch any real session
    await h.kem_invalid(0)
    await h.kem_invalid(4)
    m.kem_invalid(0); m.kem_invalid(4)
    for sid in (1, 2, 3):
        expect(m, sid, await h.lookup(sid), "oob invalid")


@cocotb.test()
async def genuine_and_decoy_are_indistinguishable(dut):
    """
    Implicit-rejection rule.  Replay the identical operation schedule twice
    with completely different secrets (stand-ins for genuine vs decoy keys).
    Every observable other than the key bits must be bit-for-bit identical.
    """
    traces = []
    for run in range(2):
        h = await start(dut)
        await h.reset()
        rng_ops = random.Random(0xABCD)          # same schedule both runs
        rng_key = random.Random(1000 + run)      # different secrets per run
        trace = []
        for n in range(600):
            op = rng_ops.choice(["done", "adv", "look", "look"])
            sid = rng_ops.choice([1, 2, 3])
            if op == "done":
                await h.kem_done(sid, rkey(rng_key))
            elif op == "adv":
                await h.adv(sid)
            else:
                ok, key, nonce, state = await h.lookup(sid)
                trace.append((sid, ok, nonce, state))   # key deliberately excluded
        traces.append(trace)
    assert traces[0] == traces[1], "observable behaviour depends on the secret"
    assert all(s != REJECT for _, _, _, s in traces[0])


@cocotb.test()
async def nonce_exhaustion_refuses_use(dut):
    """Counter at all-ones: lk_ok drops to 0 and the counter never wraps."""
    h = await start(dut)
    await h.kem_done(1, 0x1234)
    # Jump the counter close to the limit (backdoor write to the RTL array).
    dut.nonce[1].value = MAXN - 2
    await FallingEdge(dut.clk)
    seen = []
    for _ in range(5):
        ok, key, nonce, state = await h.lookup(1)
        seen.append((ok, nonce))
        await h.adv(1)
    assert seen[0] == (1, MAXN - 2) and seen[1] == (1, MAXN - 1)
    assert seen[2] == (0, MAXN), f"exhausted counter must report ok=0, got {seen[2]}"
    assert seen[3] == (0, MAXN) and seen[4] == (0, MAXN), "nonce wrapped / reused"


def test_runner():
    """pytest / `python test_session_mgr.py` entry: build with iverilog and run."""
    from cocotb.runner import get_runner

    rtl = REPO / "rtl"
    runner = get_runner(os.getenv("SIM", "icarus"))
    runner.build(
        sources=[rtl / "control" / "session_mgr.v"],
        includes=[rtl / "control"],
        hdl_toplevel="session_mgr",
        build_dir=REPO / "sim" / "sim_build" / "session_mgr",
        always=True,
    )
    runner.test(
        hdl_toplevel="session_mgr",
        test_module="test_session_mgr",
        build_dir=REPO / "sim" / "sim_build" / "session_mgr",
        test_dir=Path(__file__).resolve().parent,
    )


if __name__ == "__main__":
    test_runner()

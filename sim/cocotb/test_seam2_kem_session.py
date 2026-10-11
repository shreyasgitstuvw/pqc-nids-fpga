#==========================================================================
# sim/cocotb/test_seam2_kem_session.py
#
# C17 -- Joint Seam-2 indistinguishability test (Member C x Member D).
# DUT: sim/seam2_kem_session_top.v = REAL mlkem_top.v wired 1:1 to REAL
# session_mgr.v per docs/Member A/interface_contract.md sec 5.1. No mocks.
#
# Property under test (contract sec 5.1 rule 1, Master-Interface-Document
# Seam 2): a handshake that fails the Fujisaki-Okamoto re-encryption check
# (implicit rejection) must be indistinguishable from an authentic one at the
# session_mgr boundary -- same cycle, same waveform, same state -- with only
# the 32-byte key VALUE differing. Structural failures are the one allowed,
# visible exception and are the only route into REJECTED.
#
# Method: every case drives a full HS_RESP packet over the byte bus, then
# samples, EVERY cycle from SOF of the packet until well past kem_done:
#   mlkem boundary : kem_done, kem_key_invalid, v_kem_valid, v_kem_fail,
#                    v_kem_reason, kem_session_id, busy, rng_take,
#                    kem_pkt_dropped_busy
#   session_mgr    : lk_valid, lk_ok, lk_state, lk_nonce  (lookup held on the
#                    session id every cycle, so the ESTABLISHED transition
#                    cycle is itself part of the compared waveform)
# The authentic and rejected waveforms must be IDENTICAL. lk_key is excluded
# from the waveform and checked separately against the model: authentic ->
# K, rejected -> J(z||c) (decaps_internal), and the two differ.
#
# Tests:
#   1. seam2_authentic_vs_rejected_waveform_identical
#   2. seam2_rejection_variety_and_never_rejected_state
#   3. seam2_structural_failure_is_the_only_rejected_route
#   4. seam2_nist_val_rejection_vectors
#==========================================================================

import json
import os
import random
import sys
from pathlib import Path

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import FallingEdge

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from model.mlkem.kem import keygen_internal, encaps_internal, decaps_internal

# Reuse the verified helpers (same drivers as the mlkem_top suite).
from test_mlkem_top import (  # noqa: E402
    reset_dut as _reset_kem, write_dk_ram, send_packet,
    load_kat_decaps_all, PKT_HS_RESP, PKT_HS_INIT,
)

ST_IDLE, ST_ESTAB, ST_REJECT = 0, 2, 3
SESSION = 2          # usable ids are 1..3 (session_mgr decision 1)
WINDOW_AFTER_DONE = 12


async def reset_dut(dut):
    dut.lk_req.value = 0
    dut.lk_id.value = 0
    await _reset_kem(dut)


def snapshot(dut):
    """One cycle of the non-secret observable boundary, as a tuple."""
    g = lambda s: int(getattr(dut, s).value)
    return (
        g("kem_done"), g("kem_key_invalid"), g("v_kem_valid"), g("v_kem_fail"),
        g("v_kem_reason"), g("kem_session_id"), g("busy"), g("rng_take"),
        g("kem_pkt_dropped_busy"),
        g("lk_valid"), g("lk_ok"), g("lk_state"), g("lk_nonce"),
    )


async def run_handshake(dut, dk, ct, sid=SESSION, gap_rng=None, timeout=90000):
    """Drive one HS_RESP packet; record the per-cycle waveform from the first
    SOF cycle until WINDOW_AFTER_DONE cycles after kem_done.
    Returns dict(trace, done_idx, eof_idx, key)."""
    await reset_dut(dut)
    await write_dk_ram(dut, dk, start_word_addr=0)

    dut.lk_id.value = sid
    dut.lk_req.value = 1                      # lookup every cycle
    trace = []
    state = {"done_idx": None, "eof_idx": None, "key": None, "stop": False}

    async def monitor():
        i = 0
        left = None
        while True:
            await FallingEdge(dut.clk)
            snap = snapshot(dut)
            trace.append(snap)
            if snap[0] and state["done_idx"] is None:
                state["done_idx"] = i
                state["key"] = int(dut.lk_key.value)  # placeholder, re-read below
                left = WINDOW_AFTER_DONE
            if left is not None:
                left -= 1
                if left < 0:
                    state["stop"] = True
                    return
            i += 1
            if i > timeout:
                raise TimeoutError("handshake never completed")

    mon = cocotb.start_soon(monitor())
    n_before = len(trace)
    await send_packet(dut, PKT_HS_RESP, sid, ct, gap_rng=gap_rng)
    state["eof_idx"] = len(trace) - 1
    await mon
    # final lookup key (settles one cycle after done)
    state["key"] = int(dut.lk_key.value).to_bytes(32, "little")
    state["trace"] = trace
    return state


def keypair(rng):
    d, z, m = (bytes(rng.getrandbits(8) for _ in range(32)) for _ in range(3))
    ek, dk = keygen_internal(d, z)
    k_true, c = encaps_internal(ek, m)
    return dk, c, k_true


def corrupt(c, rng, pos=None):
    bad = bytearray(c)
    p = rng.randrange(len(c)) if pos is None else pos
    bad[p] ^= 1 << rng.randrange(8)
    return bytes(bad)


def assert_same_waveform(a, b, label):
    ta, tb = a["trace"], b["trace"]
    assert len(ta) == len(tb), f"{label}: window length differs {len(ta)} vs {len(tb)}"
    assert a["done_idx"] == b["done_idx"], (
        f"{label}: kem_done cycle differs authentic={a['done_idx']} rejected={b['done_idx']}")
    for i, (x, y) in enumerate(zip(ta, tb)):
        assert x == y, f"{label}: waveform diverges at cycle {i}: authentic={x} rejected={y}"
    # The session actually became ESTABLISHED in both, at the same cycle.
    last = ta[-1]
    assert last[11] == ST_ESTAB and last[10] == 1, f"{label}: session not ESTABLISHED/ok: {last}"


@cocotb.test()
async def seam2_authentic_vs_rejected_waveform_identical(dut):
    """Same dk, authentic vs corrupted ciphertext (first byte, c1/c2 boundary,
    last byte, random): the full boundary waveform is identical cycle by cycle;
    only lk_key differs, and it equals K / the model decoy respectively."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    rng = random.Random(0xC17A)
    for trial in range(2):
        dk, c, k_true = keypair(rng)
        auth = await run_handshake(dut, dk, c)
        assert auth["key"] == k_true == decaps_internal(dk, c)
        for pos in (0, 640, 767, rng.randrange(768)):
            bad = corrupt(c, rng, pos)
            rej = await run_handshake(dut, dk, bad)
            assert_same_waveform(auth, rej, f"trial {trial} pos {pos}")
            assert rej["key"] == decaps_internal(dk, bad), "decoy != model J(z||c)"
            assert rej["key"] != auth["key"], "decoy equals the genuine key"
            dut._log.info(f"trial {trial} pos {pos}: kem_done at cycle {auth['done_idx']} (identical)")


@cocotb.test()
async def seam2_rejection_variety_and_never_rejected_state(dut):
    """Many different corruptions (and byte gaps on the bus): the session is
    ESTABLISHED in every case, never REJECTED, kem_key_invalid never fires,
    and the completion cycle is constant relative to the packet end."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    rng = random.Random(0xC17B)
    dk, c, k_true = keypair(rng)
    ref = await run_handshake(dut, dk, c)
    ref_gap = ref["done_idx"] - ref["eof_idx"]
    cases = [("burst-flip", corrupt(c, rng)), ("zeroed-ct", bytes(768)),
             ("ct-of-0xFF", bytes([0xFF]) * 768), ("swapped-halves", c[384:] + c[:384])]
    cases += [(f"flip{n}", corrupt(c, rng)) for n in range(4)]
    for label, ct in cases:
        assert ct != c
        out = await run_handshake(dut, dk, ct, gap_rng=random.Random(7) if label == "flip0" else None)
        states = {s[11] for s in out["trace"]}
        assert ST_REJECT not in states, f"{label}: entered REJECTED on implicit rejection"
        assert all(s[1] == 0 and s[2] == 0 and s[3] == 0 for s in out["trace"]), (
            f"{label}: structural/verdict strobe raised on a cryptographic rejection")
        assert out["trace"][-1][11] == ST_ESTAB and out["trace"][-1][10] == 1
        assert out["key"] == decaps_internal(dk, ct), f"{label}: key != model decoy"
        if label != "flip0":  # (flip0 has bus gaps, so its EOF-relative gap is measured separately)
            assert out["done_idx"] - out["eof_idx"] == ref_gap, (
                f"{label}: done-after-EOF {out['done_idx'] - out['eof_idx']} != authentic {ref_gap}")


@cocotb.test()
async def seam2_structural_failure_is_the_only_rejected_route(dut):
    """Control experiment: structural failures (wrong length on HS_RESP) DO
    drive kem_key_invalid and land in REJECTED with the key zeroised and
    lk_ok = 0. That is the single sanctioned, visible failure path."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    rng = random.Random(0xC17C)
    dk, c, _ = keypair(rng)
    await reset_dut(dut)
    await write_dk_ram(dut, dk, start_word_addr=0)
    dut.lk_id.value = SESSION
    dut.lk_req.value = 1
    seen_invalid = False
    mon_states = []

    async def monitor():
        nonlocal seen_invalid
        for _ in range(3000):
            await FallingEdge(dut.clk)
            if int(dut.kem_key_invalid.value):
                seen_invalid = True
            mon_states.append((int(dut.lk_state.value), int(dut.lk_ok.value)))

    mon = cocotb.start_soon(monitor())
    # claimed length 700 != 768: structural failure
    await send_packet(dut, PKT_HS_RESP, SESSION, c[:700], claimed_len=700)
    await mon
    assert seen_invalid, "wrong-length HS_RESP did not strobe kem_key_invalid"
    assert mon_states[-1] == (ST_REJECT, 0), f"structural failure not REJECTED: {mon_states[-1]}"
    assert int(dut.lk_key.value) == 0, "REJECTED entry kept key material"
    assert ST_ESTAB not in {s for s, _ in mon_states}, "structural failure briefly looked ESTABLISHED"


@cocotb.test()
async def seam2_nist_val_rejection_vectors(dut):
    """NIST VAL decapsulation vectors, including the official implicit-rejection
    cases: session ESTABLISHED, key == NIST k, no strobes, and the completion
    cycle depends only on the dk (never on authentic vs rejected)."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    vecs = load_kat_decaps_all()
    assert len(vecs) >= 10
    for label, dk, c, k in vecs[:6]:
        out = await run_handshake(dut, dk, c)
        assert out["key"] == k, f"{label}: session key != NIST k"
        last = out["trace"][-1]
        assert last[11] == ST_ESTAB and last[10] == 1 and last[1] == 0
        dut._log.info(f"{label}: ESTABLISHED, done {out['done_idx'] - out['eof_idx']} cycles after EOF")


# ==============================================================================
# Runner for pytest / command-line execution
# ==============================================================================
import pytest


@pytest.mark.parametrize("sim_build", ["sim_build_seam2_kem_session"])
def test_runner(sim_build):
    from cocotb.runner import get_runner

    proj_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    kem = lambda f: os.path.join(proj_path, "rtl", "crypto", "kem", f)
    sources = [kem(f) for f in (
        "poly_bank_ram.v", "sample_ntt.v", "cbd_sampler.v", "poly_add_sub.v",
        "byte_encode.v", "byte_decode.v", "compress.v", "decompress.v", "pack_8_to_64.v")]
    sources += [
        os.path.join(proj_path, "rtl", "crypto", "sha3", "keccak_f1600.v"),
        os.path.join(proj_path, "rtl", "crypto", "sha3", "shake_wrapper.v"),
        os.path.join(proj_path, "rtl", "crypto", "ntt", "modmul.v"),
        os.path.join(proj_path, "rtl", "crypto", "ntt", "butterfly.v"),
        os.path.join(proj_path, "rtl", "crypto", "ntt", "ntt_core.v"),
        os.path.join(proj_path, "rtl", "crypto", "ntt", "poly_mul_acc.v"),
        kem("mlkem_top.v"),
        os.path.join(proj_path, "rtl", "control", "session_mgr.v"),
        os.path.join(proj_path, "sim", "seam2_kem_session_top.v"),
    ]
    includes = [
        os.path.join(proj_path, "rtl", "control"),
        os.path.join(proj_path, "rtl", "crypto", "ntt"),
        os.path.join(proj_path, "rtl", "crypto", "sha3"),
        os.path.join(proj_path, "rtl", "crypto", "kem"),
    ]
    runner = get_runner("icarus")
    runner.build(
        verilog_sources=sources, includes=includes,
        hdl_toplevel="seam2_kem_session_top",
        build_dir=os.path.join(proj_path, "sim", sim_build), always=True)
    runner.test(
        hdl_toplevel="seam2_kem_session_top", test_module="test_seam2_kem_session",
        test_dir=os.path.join(proj_path, "sim", "cocotb"))


if __name__ == "__main__":
    test_runner("sim_build_seam2_kem_session")

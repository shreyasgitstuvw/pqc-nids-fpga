"""
cocotb testbench for rtl/crypto/chacha_poly/chacha_poly.v  (Member D)

The Python twin is model/chacha_poly.py.  Every expected value here (ciphertext,
tag, plaintext) is computed by that twin at run time -- nothing is copied from
a previous simulation run.

Byte order on the DUT ports (matches sim/test_chacha_poly_tb.v):
    key / nonce / aad_data / expected_tag are little-endian integers, i.e.
    byte 0 of the byte string sits in bits [7:0].

Run directly (no `make` needed, works on Windows):
    python sim/cocotb/test_chacha_poly.py
or via pytest:
    pytest sim/cocotb/test_chacha_poly.py
"""

import os
import random
import sys
from pathlib import Path

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import FallingEdge, RisingEdge

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from model.chacha_poly import (  # noqa: E402
    chacha20_poly1305_decrypt,
    chacha20_poly1305_encrypt,
)

RC_NONE = 0x0
RC_BAD_TAG = 0x7

# A packet must finish well inside this many cycles or something is hung.
# 1 OTK block + 1 block per 64 B + finalisation; generous upper bound.
def _timeout_cycles(n_bytes):
    return 400 + 120 * ((n_bytes + 63) // 64)


def le(b: bytes) -> int:
    return int.from_bytes(b, "little")


class Dut:
    """Thin driver/monitor around the chacha_poly ports."""

    def __init__(self, dut):
        self.dut = dut
        self.pt = []          # plaintext bytes captured while pt_valid
        self.pt_sof_seen = []  # indices at which pt_sof was high
        self.pt_eof_seen = []  # indices at which pt_eof was high
        self.verdicts = []    # (fail, reason) for every v_poly_valid strobe
        self.done_count = 0
        cocotb.start_soon(self._monitor())

    async def _monitor(self):
        d = self.dut
        while True:
            await RisingEdge(d.clk)
            if d.pt_valid.value == 1:
                if d.pt_sof.value == 1:
                    self.pt_sof_seen.append(len(self.pt))
                if d.pt_eof.value == 1:
                    self.pt_eof_seen.append(len(self.pt))
                self.pt.append(int(d.pt_data.value))
            if d.v_poly_valid.value == 1:
                self.verdicts.append(
                    (int(d.v_poly_fail.value), int(d.v_poly_reason.value))
                )
            if d.done.value == 1:
                self.done_count += 1

    async def reset(self):
        d = self.dut
        d.rst.value = 1
        d.key_valid.value = 0
        d.key.value = 0
        d.nonce.value = 0
        d.aad_data.value = 0
        d.aad_len.value = 0
        d.ct_valid.value = 0
        d.ct_data.value = 0
        d.ct_sof.value = 0
        d.ct_eof.value = 0
        d.expected_tag.value = 0
        for _ in range(4):
            await FallingEdge(d.clk)
        d.rst.value = 0
        for _ in range(2):
            await FallingEdge(d.clk)

    async def run_packet(self, key, nonce, aad, ct, tag):
        """Drive one packet.  Returns (tag_out, tag_ok, pt_tag_ok) at `done`."""
        d = self.dut
        assert len(aad) <= 16
        assert len(ct) >= 1
        self.pt.clear()
        self.pt_sof_seen.clear()
        self.pt_eof_seen.clear()
        self.verdicts.clear()
        done_before = self.done_count

        await FallingEdge(d.clk)
        d.key.value = le(key)
        d.nonce.value = le(nonce)
        d.aad_data.value = le(aad)
        d.aad_len.value = len(aad)
        d.expected_tag.value = le(tag)
        d.key_valid.value = 1
        await FallingEdge(d.clk)
        d.key_valid.value = 0

        budget = _timeout_cycles(len(ct))

        async def wait_ready():
            nonlocal budget
            while d.ready.value != 1:
                await FallingEdge(d.clk)
                budget -= 1
                assert budget > 0, "timeout waiting for ready"

        await wait_ready()
        # Valid/ready handshake: a byte is accepted on a rising edge where
        # ct_valid=1 and ready=1.  Hold the byte until that happens.  (ready
        # drops for the ChaCha20 block refill after byte 63 of each 64-byte
        # block, so the byte after it must wait.)
        for i, byte in enumerate(ct):
            await FallingEdge(d.clk)
            d.ct_valid.value = 1
            d.ct_data.value = byte
            d.ct_sof.value = 1 if i == 0 else 0
            d.ct_eof.value = 1 if i == len(ct) - 1 else 0
            while True:
                await RisingEdge(d.clk)
                accepted = d.ready.value == 1
                await FallingEdge(d.clk)
                if accepted:
                    break
                budget -= 1
                assert budget > 0, f"timeout: byte {i} never accepted"
            d.ct_valid.value = 0
            d.ct_sof.value = 0
            d.ct_eof.value = 0

        while self.done_count == done_before:
            await FallingEdge(d.clk)
            budget -= 1
            assert budget > 0, f"timeout waiting for done (ct={len(ct)} aad={len(aad)} busy={d.busy.value} ready={d.ready.value})"

        result = (
            int(d.tag_out.value).to_bytes(16, "little"),
            int(d.tag_ok.value),
            int(d.pt_tag_ok.value),
        )
        # let the pt / verdict monitor see any trailing cycle
        await FallingEdge(d.clk)
        return result


async def start(dut):
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    h = Dut(dut)
    await h.reset()
    return h


def rand_packet(rng, n_ct=None, n_aad=None):
    key = bytes(rng.randrange(256) for _ in range(32))
    nonce = bytes(rng.randrange(256) for _ in range(12))
    n_aad = rng.randint(0, 16) if n_aad is None else n_aad
    n_ct = rng.choice([1, 2, 15, 16, 17, 63, 64, 65, 127, 128, 129, 200]) \
        if n_ct is None else n_ct
    aad = bytes(rng.randrange(256) for _ in range(n_aad))
    pt = bytes(rng.randrange(256) for _ in range(n_ct))
    ct, tag = chacha20_poly1305_encrypt(key, nonce, aad, pt)
    return key, nonce, aad, pt, ct, tag


def check_good(h, res, pt, tag, label):
    tag_out, tag_ok, pt_tag_ok = res
    assert tag_out == tag, f"{label}: tag_out {tag_out.hex()} != model {tag.hex()}"
    assert tag_ok == 1 and pt_tag_ok == 1, f"{label}: tag flags not set"
    assert bytes(h.pt) == pt, f"{label}: plaintext differs from model"
    assert h.pt_sof_seen == [0], f"{label}: pt_sof at {h.pt_sof_seen}"
    assert h.pt_eof_seen == [len(pt) - 1], f"{label}: pt_eof at {h.pt_eof_seen}"
    assert h.verdicts == [(0, RC_NONE)], f"{label}: verdict {h.verdicts}"


@cocotb.test()
async def rfc8439_sec_2_8_2(dut):
    """RFC 8439 §2.8.2 AEAD vector, tag and plaintext taken from the model."""
    h = await start(dut)
    key = bytes(range(0x80, 0xA0))
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you "
          b"only one tip for the future, sunscreen would be it.")
    ct, tag = chacha20_poly1305_encrypt(key, nonce, aad, pt)
    res = await h.run_packet(key, nonce, aad, ct, tag)
    check_good(h, res, pt, tag, "rfc8439")


@cocotb.test()
async def random_packets_match_model(dut):
    """60 random packets: lengths straddle 16/64-byte block boundaries."""
    h = await start(dut)
    rng = random.Random(0xC0FFEE)
    for n in range(60):
        key, nonce, aad, pt, ct, tag = rand_packet(rng)
        res = await h.run_packet(key, nonce, aad, ct, tag)
        check_good(h, res, pt, tag, f"pkt{n} ct={len(ct)} aad={len(aad)}")


@cocotb.test()
async def tamper_is_flagged_bad_tag(dut):
    """Flip one bit of ct, aad or tag: model rejects, RTL must signal RC_BAD_TAG."""
    h = await start(dut)
    rng = random.Random(0xBADBAD)
    for n in range(24):
        key, nonce, aad, pt, ct, tag = rand_packet(rng, n_aad=rng.randint(1, 16))
        which = n % 3
        if which == 0:
            i = rng.randrange(len(ct))
            ct = ct[:i] + bytes([ct[i] ^ (1 << rng.randrange(8))]) + ct[i + 1:]
        elif which == 1:
            i = rng.randrange(len(aad))
            aad = aad[:i] + bytes([aad[i] ^ (1 << rng.randrange(8))]) + aad[i + 1:]
        else:
            i = rng.randrange(16)
            tag = tag[:i] + bytes([tag[i] ^ (1 << rng.randrange(8))]) + tag[i + 1:]

        ok_model, _ = chacha20_poly1305_decrypt(key, nonce, aad, ct, tag)
        assert not ok_model, "model should reject the tampered packet"

        _, tag_ok, pt_tag_ok = await h.run_packet(key, nonce, aad, ct, tag)
        assert tag_ok == 0 and pt_tag_ok == 0, f"tamper#{n} accepted by RTL"
        assert h.verdicts == [(1, RC_BAD_TAG)], f"tamper#{n} verdict {h.verdicts}"


@cocotb.test()
async def reject_then_good_packet(dut):
    """A rejected packet must not poison the next good one (no sticky state)."""
    h = await start(dut)
    rng = random.Random(7)
    for n in range(10):
        key, nonce, aad, pt, ct, tag = rand_packet(rng, n_ct=70, n_aad=12)
        bad = bytes([tag[0] ^ 1]) + tag[1:]
        await h.run_packet(key, nonce, aad, ct, bad)
        assert h.verdicts == [(1, RC_BAD_TAG)]
        res = await h.run_packet(key, nonce, aad, ct, tag)
        check_good(h, res, pt, tag, f"recover{n}")


@cocotb.test()
async def every_length_1_to_200(dut):
    """Every ciphertext length 1..200 (AAD 0..16 cycling), reset after any failure."""
    h = await start(dut)
    rng = random.Random(1234)
    bad = []
    for n in range(1, 201):
        key, nonce, aad, pt, ct, tag = rand_packet(rng, n_ct=n, n_aad=n % 17)
        try:
            res = await h.run_packet(key, nonce, aad, ct, tag)
            check_good(h, res, pt, tag, f"len{n}")
        except AssertionError as e:
            bad.append((n, str(e).splitlines()[0][:80]))
            await h.reset()
    assert not bad, f"{len(bad)} failing lengths: {bad}"


def test_runner():
    """pytest / `python test_chacha_poly.py` entry: build with iverilog and run."""
    from cocotb.runner import get_runner

    rtl = REPO / "rtl"
    sources = sorted((rtl / "crypto" / "chacha_poly").glob("*.v"))
    runner = get_runner(os.getenv("SIM", "icarus"))
    runner.build(
        sources=sources,
        includes=[rtl / "control"],
        hdl_toplevel="chacha_poly",
        build_dir=REPO / "sim" / "sim_build" / "chacha_poly",
        always=True,
    )
    runner.test(
        hdl_toplevel="chacha_poly",
        test_module="test_chacha_poly",
        build_dir=REPO / "sim" / "sim_build" / "chacha_poly",
        test_dir=Path(__file__).resolve().parent,
    )


if __name__ == "__main__":
    test_runner()

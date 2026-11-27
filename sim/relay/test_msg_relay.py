"""
Bit-exact test: msg_relay encrypts exactly like model.chacha_poly (RFC 8439), routes
by PHYSICAL LINK rather than by any address in the packet, and queues messages that
arrive while one is being relayed instead of dropping them.

Link codes: 0 = JA (peer A), 1 = JB (attacker C), 2 = JD (peer B).
"""
import os, random, sys
import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge
import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO)
from model.chacha_poly import chacha20_poly1305_encrypt  # noqa

LINK_A, LINK_C, LINK_B = 0, 1, 2
# a message from peer B goes to peer A; anything else goes to peer B
DEST_LINK = {LINK_A: LINK_B, LINK_C: LINK_B, LINK_B: LINK_A}
UART_OF = {LINK_A: 0, LINK_B: 1}


def nonce_of(ctr):
    return ctr.to_bytes(8, "little") + b"\x00\x00\x00\x80"


async def setup(dut):
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    for s in ("pt_valid", "pt_sof", "drop_valid", "drop_fail", "key_load",
              "hs_hold_off", "tx_busy"):
        getattr(dut, s).value = 0
    dut.pt_data.value = 0
    dut.src_link.value = 0
    dut.key_slot.value = 0
    dut.key_data.value = 0
    dut.rst.value = 1
    for _ in range(5):
        await RisingEdge(dut.clk)
    dut.rst.value = 0
    for _ in range(3):
        await RisingEdge(dut.clk)


async def load_key(dut, slot, key):
    dut.key_slot.value = slot
    dut.key_data.value = int.from_bytes(key, "little")
    dut.key_load.value = 1
    await RisingEdge(dut.clk)
    dut.key_load.value = 0
    await RisingEdge(dut.clk)


class Tx:
    def __init__(self, dut):
        self.dut = dut
        self.bytes = []
        self.dests = []
        cocotb.start_soon(self.run())

    async def run(self):
        while True:
            await RisingEdge(self.dut.clk)
            if self.dut.tx_valid.value == 1:
                self.bytes.append(int(self.dut.tx_data.value))
                self.dests.append(int(self.dut.eg_dest.value))


async def send_msg(dut, msg, link, fail=False, settle=40):
    for i, b in enumerate(msg):
        dut.pt_valid.value = 1
        dut.pt_sof.value = 1 if i == 0 else 0
        dut.pt_data.value = b
        dut.src_link.value = link
        await RisingEdge(dut.clk)
    dut.pt_valid.value = 0
    dut.pt_sof.value = 0
    for _ in range(settle):
        await RisingEdge(dut.clk)
    dut.drop_valid.value = 1
    dut.drop_fail.value = 1 if fail else 0
    await RisingEdge(dut.clk)
    dut.drop_valid.value = 0
    dut.drop_fail.value = 0


async def wait_for(dut, tx, n_bytes, cycles=200000):
    for _ in range(cycles):
        await RisingEdge(dut.clk)
        if len(tx.bytes) >= n_bytes and dut.eg_active.value == 0:
            break
    for _ in range(50):
        await RisingEdge(dut.clk)


def check_frame(frame, msg, ctr, key):
    ct, tag = chacha20_poly1305_encrypt(key, nonce_of(ctr), b"", msg)
    exp = b"\xB0\x7E" + bytes([len(msg)]) + ctr.to_bytes(8, "little") + ct + tag
    assert frame == exp, f"\n got {frame.hex()}\n exp {exp.hex()}"


@cocotb.test()
async def relay_bit_exact(dut):
    """One message at a time: ciphertext, tag, counter and routing all exact."""
    await setup(dut)
    kA, kB = os.urandom(32), os.urandom(32)
    await load_key(dut, LINK_A, kA)
    await load_key(dut, LINK_B, kB)
    tx = Tx(dut)
    random.seed(1)
    # lengths cover: 1, partial chunk, exact 16, the 64-byte block edge, >64, max
    cases = [(LINK_A, 1), (LINK_A, 5), (LINK_A, 16), (LINK_A, 63), (LINK_A, 64),
             (LINK_A, 65), (LINK_A, 100), (LINK_B, 33), (LINK_C, 20), (LINK_A, 240)]
    keys = {LINK_A: kA, LINK_B: kB}
    ctr = {LINK_A: 0, LINK_B: 0}
    for link, ln in cases:
        msg = bytes(random.randrange(256) for _ in range(ln))
        dest = DEST_LINK[link]
        before = len(tx.bytes)
        await send_msg(dut, msg, link)
        await wait_for(dut, tx, before + 27 + ln)
        check_frame(bytes(tx.bytes[before:]), msg, ctr[dest], keys[dest])
        assert set(tx.dests[before:]) == {UART_OF[dest]}, "wrong transmitter"
        ctr[dest] += 1
    dut._log.info("10 frames bit-exact, counters advance, routing by link correct")

    # a failed verdict relays nothing
    before = len(tx.bytes)
    await send_msg(dut, b"evil", LINK_A, fail=True)
    for _ in range(4000):
        await RisingEdge(dut.clk)
    assert len(tx.bytes) == before, "a message the drop engine failed was relayed"
    # a verdict with no plaintext at all relays nothing
    dut.drop_valid.value = 1
    await RisingEdge(dut.clk)
    dut.drop_valid.value = 0
    for _ in range(4000):
        await RisingEdge(dut.clk)
    assert len(tx.bytes) == before
    dut._log.info("verdict gating holds")


@cocotb.test()
async def relay_no_peer_key(dut):
    """Nothing is relayed to a peer that has not handshaked; a reload resets its counter."""
    await setup(dut)
    kA, kB = os.urandom(32), os.urandom(32)
    await load_key(dut, LINK_A, kA)        # only A has a key; A's traffic goes to B
    tx = Tx(dut)
    await send_msg(dut, b"hello", LINK_A)
    for _ in range(4000):
        await RisingEdge(dut.clk)
    assert len(tx.bytes) == 0, "relayed to a peer with no key"
    assert int(dut.cnt_nopeer.value) == 1
    await load_key(dut, LINK_B, kB)
    await send_msg(dut, b"hi", LINK_A)
    await wait_for(dut, tx, 29)
    check_frame(bytes(tx.bytes), b"hi", 0, kB)
    dut._log.info("no-peer drop and key reload OK")


@cocotb.test()
async def relay_queues_messages(dut):
    """Messages arriving while one is in flight wait their turn instead of vanishing.

    This is the behaviour that matters on stage: A types two lines quickly, or A and B
    talk at the same instant. The old single-buffer relay counted the second message
    and dropped it, which looks exactly like a lost message to whoever typed it.
    """
    await setup(dut)
    kA, kB = os.urandom(32), os.urandom(32)
    await load_key(dut, LINK_A, kA)
    await load_key(dut, LINK_B, kB)
    tx = Tx(dut)

    msgs = [b"first message", b"second", b"third one here", b"fourth"]
    # send all four back to back; the first is still encrypting when the rest arrive
    for m in msgs:
        await send_msg(dut, m, LINK_A, settle=2)
    peak = int(dut.q_level.value)
    total = sum(27 + len(m) for m in msgs)
    await wait_for(dut, tx, total)
    assert int(dut.cnt_full.value) == 0, "a message was dropped for a full queue"
    assert int(dut.cnt_relayed.value) == len(msgs), \
        f"relayed {int(dut.cnt_relayed.value)} of {len(msgs)}"
    # every frame, in order, with consecutive counters
    stream = bytes(tx.bytes)
    off = 0
    for n, m in enumerate(msgs):
        ln = 27 + len(m)
        check_frame(stream[off:off + ln], m, n, kB)
        off += ln
    assert off == len(stream), "extra bytes on the wire"
    dut._log.info(f"4 queued messages relayed in order, peak queue depth {peak}")

    # beyond the queue depth a message IS dropped, but it is counted, and nothing
    # already queued is corrupted by the overflow
    before_relayed = int(dut.cnt_relayed.value)
    many = [bytes([65 + i]) * 8 for i in range(8)]
    for m in many:
        await send_msg(dut, m, LINK_A, settle=2)
    # eg_active only rises once the frame is being transmitted, so it is low while a
    # message is still encrypting: wait for the FSM itself to be back in S_IDLE.
    for _ in range(400000):
        await RisingEdge(dut.clk)
        if int(dut.q_level.value) == 0 and int(dut.st.value) == 0:
            break
    for _ in range(200):
        await RisingEdge(dut.clk)
    got = int(dut.cnt_relayed.value) - before_relayed
    dropped = int(dut.cnt_full.value)
    assert got + dropped == len(many), \
        f"{len(many)} offered, {got} relayed, {dropped} counted as full"
    assert got >= 5, f"queue should absorb at least QDEPTH+1, only took {got}"
    # the frames that did go out are still exact, with no gap in the counters
    stream = bytes(tx.bytes[off:])
    ctr = len(msgs)
    o = 0
    for m in many[:got]:
        ln = 27 + len(m)
        check_frame(stream[o:o + ln], m, ctr, kB)
        o += ln
        ctr += 1
    dut._log.info(f"overflow past the queue: {got} relayed, {dropped} counted, none corrupted")


@pytest.mark.parametrize("sim_build", ["sim_build_msg_relay"])
def test_runner(sim_build):
    from cocotb.runner import get_runner
    proj = REPO
    srcs = [f"{proj}/rtl/relay/msg_relay.v",
            f"{proj}/rtl/crypto/chacha_poly/chacha20.v",
            f"{proj}/rtl/crypto/chacha_poly/poly1305.v"]
    inc = [f"{proj}/rtl/control", f"{proj}/rtl/crypto/chacha_poly"]
    r = get_runner("icarus")
    r.build(verilog_sources=srcs, includes=inc, hdl_toplevel="msg_relay",
            build_dir=f"{proj}/sim/{sim_build}", always=True)
    r.test(hdl_toplevel="msg_relay", test_module="test_msg_relay",
           test_dir=os.path.dirname(__file__))


if __name__ == "__main__":
    test_runner("sim_build_msg_relay")

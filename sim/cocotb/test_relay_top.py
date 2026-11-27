#==========================================================================
# sim/cocotb/test_relay_top.py
# Full-board test of the re-encrypting relay build (pqc_nids_top with msg_relay).
#   A (JA), B (JD) and attacker C (JB) each handshake on their OWN link and get
#   their own reply. A -> B and B -> A messages leave the board ENCRYPTED under the
#   destination's key; a signature, a bad tag and a wrong-key peer are never
#   relayed. No plaintext appears on any TX pin.
#==========================================================================
import os, sys
import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge
import pytest

sys.path.insert(0, os.path.dirname(__file__))
import test_pqc_nids_top as T            # helpers (frames, uart, decode)
from test_pqc_nids_top import (wire_frame, eth_ip_udp, uart_send, rd, find_frame,
                               FPGA_IP, PORT_HS_INIT, PORT_DATA, compute_crc32)
REPO = T.REPO
from model.mlkem.kem import keygen_internal, decaps_internal            # noqa
from model.chacha_poly import chacha20_poly1305_encrypt, chacha20_poly1305_decrypt  # noqa

A_IP, B_IP, C_IP = 0x0A000001, 0x0A000002, 0x0A000003
PORTS = {"A": 40000, "B": 40001, "C": 40002}
IPS = {"A": A_IP, "B": B_IP, "C": C_IP}
RXPIN = {"A": "uart_rx_pin", "B": "peer_rx_pin", "C": "attacker_rx_pin"}
TXPIN = {"A": "uart_tx_pin", "B": "peer_tx_pin", "C": "attacker_tx_pin"}
CPB = T.CLKS_PER_BIT


class PinMon:
    def __init__(self, dut, pin):
        self.buf = bytearray()
        cocotb.start_soon(self.run(dut, getattr(dut, pin)))
    async def run(self, d, pin):
        while True:
            while rd(pin, 1) == 1:
                await RisingEdge(d.clk)
            for _ in range(CPB + CPB // 2):
                await RisingEdge(d.clk)
            v = 0
            for i in range(8):
                v |= rd(pin, 1) << i
                for _ in range(CPB):
                    await RisingEdge(d.clk)
            self.buf.append(v)


def nonce_of(ctr):
    return ctr.to_bytes(8, "little") + b"\x00\x00\x00\x80"


@cocotb.test()
async def relay_top(dut):
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    mons = {k: PinMon(dut, p) for k, p in TXPIN.items()}
    verdicts = []

    async def vmon():
        while True:
            await RisingEdge(dut.clk)
            if rd(dut.drop_valid):
                verdicts.append((rd(dut.drop_fail), int(dut.drop_reason.value)))
    cocotb.start_soon(vmon())

    dut.uart_rx_pin.value = 1; dut.attacker_rx_pin.value = 1; dut.peer_rx_pin.value = 1
    dut.btn_rst.value = 1
    for _ in range(20): await RisingEdge(dut.clk)
    dut.btn_rst.value = 0
    for _ in range(400):
        await RisingEdge(dut.clk)
        if rd(dut.kem_busy) == 1: break
    for _ in range(80000):
        await RisingEdge(dut.clk)
        if rd(dut.kem_busy, 1) == 0: break
    assert rd(dut.led[0]) == 0, "LD0 lit after boot KeyGen alone (should wait for a peer)"

    keys = {}
    async def join(who, seed, claim=None):
        ek, dk = keygen_internal(bytes([seed]) * 32, bytes([seed + 1]) * 32)
        for m in mons.values(): m.buf.clear()
        join.cleared = True
        ip = IPS[claim] if claim else IPS[who]
        await uart_send(dut, wire_frame(eth_ip_udp(ek, PORT_HS_INIT, PORTS[who], ip)),
                        RXPIN[who])
        reply = None
        for n in range(1_500_000):
            await RisingEdge(dut.clk)
            if len(mons[who].buf) >= 816 and n % 500 == 0:
                reply = find_frame(bytes(mons[who].buf), 816)
                if reply: break
        assert reply, f"{who}: no handshake reply on its own link"
        for k, m in mons.items():
            if k != who:
                assert len(m.buf) == 0, f"{who}'s reply leaked onto {k}'s link"
        ct = reply[2 + 42:2 + 810]
        keys[who] = decaps_internal(dk, ct)
        k_hw = None
        dut._log.info(f"{who} joined, LD0={rd(dut.led[0])}")

    await join("A", 1)
    assert rd(dut.led[0]) == 1, "LD0 should light after A's handshake"
    await join("B", 3)

    async def send(who, text, ctr, key=None, bad_tag=False, claim=None):
        # `who` is the physical LINK the frame goes out on; `claim` is the source
        # address written into the headers, which is what a spoofer controls.
        key = key or keys[who]
        ip = IPS[claim] if claim else IPS[who]
        aad = (ip.to_bytes(4, "big") + FPGA_IP.to_bytes(4, "big")
               + PORTS[who].to_bytes(2, "big") + PORT_DATA.to_bytes(2, "big"))
        c, tag = chacha20_poly1305_encrypt(key, ctr.to_bytes(12, "little"), aad, text)
        if bad_tag: tag = bytes([tag[0] ^ 0xFF]) + tag[1:]
        verdicts.clear()
        await uart_send(dut, wire_frame(eth_ip_udp(c + tag, PORT_DATA, PORTS[who], ip)),
                        RXPIN[who])
        for _ in range(80000):
            await RisingEdge(dut.clk)
            if verdicts: break
        assert verdicts, "no verdict"
        return verdicts[-1]

    def take(dest_mon, n_bytes, mark):
        return bytes(dest_mon.buf[mark:])

    async def expect_frame(dest, mark, text, ctr, key):
        n = 27 + len(text)
        for _ in range(60000):
            await RisingEdge(dut.clk)
            if len(mons[dest].buf) - mark >= n: break
        fr = bytes(mons[dest].buf[mark:mark + n])
        assert fr[:2] == b"\xB0\x7E" and fr[2] == len(text), fr.hex()
        c = int.from_bytes(fr[3:11], "little")
        assert c == ctr, f"counter {c} != {ctr}"
        ct, tag = fr[11:11 + len(text)], fr[11 + len(text):]
        assert text not in fr, "PLAINTEXT on the wire!"
        ok, pt = chacha20_poly1305_decrypt(key, nonce_of(c), b"", ct, tag)
        assert ok and pt == text, "relayed frame does not decrypt to the message"
        return fr

    # --- A -> B
    mB, mA = len(mons["B"].buf), len(mons["A"].buf)
    v = await send("A", b"hello from A", 0)
    assert v == (0, 0), v
    fr = await expect_frame("B", mB, b"hello from A", 0, keys["B"])
    dut._log.info(f"A->B relayed encrypted: {fr.hex()[:48]}...")
    assert len(mons["A"].buf) == mA, "something was sent back to A"
    # second message: counter advances
    mB = len(mons["B"].buf)
    await send("A", b"second", 1)
    await expect_frame("B", mB, b"second", 1, keys["B"])

    # --- B -> A (two-way)
    mA = len(mons["A"].buf)
    v = await send("B", b"hi A, B here", 0)
    assert v == (0, 0), v
    await expect_frame("A", mA, b"hi A, B here", 0, keys["A"])
    dut._log.info("B->A relayed encrypted")

    # --- signature from A: dropped, nothing relayed
    mB = len(mons["B"].buf)
    v = await send("A", b"x ${jndi:ldap://e} y", 2)
    assert v[0] == 1 and v[1] == 4, v
    for _ in range(30000): await RisingEdge(dut.clk)
    assert len(mons["B"].buf) == mB, "attack payload was relayed"
    # --- bad tag
    v = await send("A", b"tampered", 3, bad_tag=True)
    assert v[0] == 1 and v[1] == 7, v
    for _ in range(30000): await RisingEdge(dut.clk)
    assert len(mons["B"].buf) == mB, "bad-tag message was relayed"

    # --- attacker C: own link, wrong key -> BAD_TAG, nothing relayed
    await join("C", 7)
    mB = len(mons["B"].buf)
    v = await send("C", b"let me in", 0, key=bytes(32))
    assert v[0] == 1 and v[1] == 7, v
    for _ in range(30000): await RisingEdge(dut.clk)
    assert len(mons["B"].buf) == mB, "wrong-key message relayed"
    # C with its genuine key and a clean message is relayed (to B), encrypted
    v = await send("C", b"C says hi", 1)   # board stepped C's nonce on the wrong-key packet
    assert v == (0, 0), v
    # A's counter on B-link: A's earlier two + this one = ctr 2
    await expect_frame("B", mB, b"C says hi", 2, keys["B"])
    dut._log.info("attacker on its own link behaves as itself")

    # ---------------------------------------------------------------- SPOOFING
    # Identity is the physical link, so writing A's source address into a frame sent
    # on C's cable buys the attacker nothing. Under the old address-keyed table this
    # same sequence took over A's session slot and advanced A's nonce: a denial of
    # service against a session C cannot read. The proof that it no longer does is
    # that A's NEXT message still passes, under A's own key and next counter.
    keyA_before = keys["A"]
    await join("C", 11, claim="A")          # HS_INIT on C's link, claiming A's address
    assert keys["C"] != keyA_before, "spoofed handshake produced A's key"
    mB = len(mons["B"].buf)
    # DATA on C's link claiming A's address, under C's own (new) key: C is still C,
    # so this decrypts, passes, and is relayed as C's message.
    v = await send("C", b"I am totally A", 0, claim="A")
    assert v == (0, 0), f"spoofed-address data from C did not pass as C: {v}"
    await expect_frame("B", mB, b"I am totally A", 3, keys["B"])
    # A's session is untouched: same key, and its nonce never moved, so counter 4
    # (A sent 0, 1, the signature at 2 and the bad tag at 3) is still what the board
    # expects next.
    mB = len(mons["B"].buf)
    v = await send("A", b"still me", 4)
    assert v == (0, 0), f"A's session was disturbed by the spoof: {v}"
    await expect_frame("B", mB, b"still me", 4, keys["B"])
    dut._log.info("SPOOF FAILED: address-claiming on another link neither stole "
                  "nor disturbed A's session")

    # --------------------------------------------------------------- QUEUEING
    # Two messages from A back to back, the second arriving while the first is still
    # being encrypted. Both must arrive, in order, with consecutive counters.
    mB = len(mons["B"].buf)
    v = await send("A", b"queued one", 5)
    assert v == (0, 0), v
    v = await send("A", b"queued two", 6)
    assert v == (0, 0), v
    await expect_frame("B", mB, b"queued one", 5, keys["B"])
    await expect_frame("B", mB + 27 + len(b"queued one"), b"queued two", 6, keys["B"])
    dut._log.info("two back-to-back messages both relayed, in order")
    dut._log.info("full-board relay test passed")


@pytest.mark.parametrize("sim_build", ["sim_build_relay_top"])
def test_runner(sim_build):
    from cocotb.runner import get_runner
    proj = REPO
    dirs = ["rtl/ingress", "rtl/control", "rtl/detect", "rtl/io", "rtl/relay",
            "rtl/crypto/chacha_poly", "rtl/crypto/kem", "rtl/crypto/ntt",
            "rtl/crypto/sha3", "rtl/top"]
    sources = []
    for d in dirs:
        full = os.path.join(proj, *d.split("/"))
        sources += [os.path.join(full, f) for f in sorted(os.listdir(full)) if f.endswith(".v")]
    includes = [os.path.join(proj, *d.split("/")) for d in dirs]
    r = get_runner("icarus")
    r.build(verilog_sources=sources, includes=includes, hdl_toplevel="pqc_nids_top",
            parameters={"BAUD_RATE": 10_000_000, "TELEM_PERIOD_MS": 1},
            build_dir=os.path.join(proj, "sim", sim_build), always=True)
    r.test(hdl_toplevel="pqc_nids_top", test_module="test_relay_top",
           test_dir=os.path.join(proj, "sim", "cocotb"))


if __name__ == "__main__":
    test_runner("sim_build_relay_top")

#==========================================================================
# sim/cocotb/test_pqc_nids_top.py
#
# END-TO-END test of rtl/top/pqc_nids_top.v: the whole design, every lane, no
# models in the datapath. Stimulus is serial bits on uart_rx_pin and the
# observations are uart_tx_pin, the LEDs and the drop-engine verdict.
#
# Before the top level existed, nothing in the repository instantiated more than
# one lane; chacha_poly was instantiated nowhere at all.
#
# WHAT IT PROVES
#   1. The board completes a real ML-KEM-512 handshake as the responder:
#      it receives an 800-byte encapsulation key over the serial link, runs
#      Encaps on the real mlkem_top, and transmits the 768-byte ciphertext back
#      in a correctly framed packet (length prefix, Ethernet/IPv4/UDP headers,
#      CRC-32 trailer) that the host can decapsulate.
#   2. The shared secret the hardware derived equals the one Python derives from
#      the ciphertext it sent back. That is the handshake actually working, not
#      just completing.
#   3. A ChaCha20-Poly1305 data packet encrypted under that secret is accepted
#      and forwarded.
#   4. A signature in the decrypted plaintext is caught (RC_SIGNATURE), which
#      only works because the plaintext inspection bus is wired through.
#   5. A tampered tag is caught (RC_BAD_TAG).
#
# The build overrides BAUD_RATE to 10 MHz (10 clocks per bit) purely to keep
# simulation time sane; the synthesised design runs at 3 Mbaud per contract
# section 1. Nothing in the logic depends on the ratio.
#==========================================================================

import os
import sys

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import FallingEdge, RisingEdge

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO)

from model.mlkem.kem import keygen_internal, decaps_internal          # noqa: E402
from model.chacha_poly import chacha20_poly1305_encrypt               # noqa: E402
from model.pipeline import compute_crc32, PORT_HS_INIT, PORT_HS_RESP, PORT_DATA  # noqa: E402

CLKS_PER_BIT = 10          # must match BAUD_RATE in test_runner
RC_NONE, RC_CRC_FAIL, RC_SIGNATURE, RC_BAD_TAG = 0x0, 0x1, 0x4, 0x7

HOST_MAC = bytes.fromhex("001122334455")
FPGA_MAC = bytes.fromhex("aabbccddeeff")
HOST_IP, FPGA_IP = 0x0A000001, 0x0A0000FF
HOST_PORT = 40000


def ip_checksum(hdr: bytes) -> int:
    total = 0
    for i in range(0, len(hdr), 2):
        total += int.from_bytes(hdr[i:i + 2], "big")
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def eth_ip_udp(payload: bytes, dst_port: int, src_port: int = HOST_PORT,
               src_ip: int = HOST_IP, dst_ip: int = FPGA_IP) -> bytes:
    udp = (src_port.to_bytes(2, "big") + dst_port.to_bytes(2, "big")
           + (8 + len(payload)).to_bytes(2, "big") + b"\x00\x00" + payload)
    ip_len = 20 + len(udp)
    ip_no_csum = (b"\x45\x00" + ip_len.to_bytes(2, "big") + b"\x00\x01"
                  + b"\x00\x00" + bytes([64, 17]) + b"\x00\x00"
                  + src_ip.to_bytes(4, "big") + dst_ip.to_bytes(4, "big"))
    csum = ip_checksum(ip_no_csum)
    ip = ip_no_csum[:10] + csum.to_bytes(2, "big") + ip_no_csum[12:]
    return FPGA_MAC + HOST_MAC + b"\x08\x00" + ip + udp


def wire_frame(eth_payload: bytes) -> bytes:
    """Contract sections 1 and 2: [2 B total_length BE][payload][4 B CRC-32 BE],
    total_length includes the prefix and the CRC; the CRC covers the payload."""
    total = 2 + len(eth_payload) + 4
    crc = compute_crc32(eth_payload)
    return total.to_bytes(2, "big") + eth_payload + crc.to_bytes(4, "big")


async def uart_send_byte(dut, b: int, pin="uart_rx_pin"):
    """8N1, LSB first, one stop bit."""
    sig = getattr(dut, pin)
    sig.value = 0                                   # start
    for _ in range(CLKS_PER_BIT):
        await RisingEdge(dut.clk)
    for i in range(8):
        sig.value = (b >> i) & 1
        for _ in range(CLKS_PER_BIT):
            await RisingEdge(dut.clk)
    sig.value = 1                                   # stop
    for _ in range(CLKS_PER_BIT):
        await RisingEdge(dut.clk)


async def uart_send(dut, data: bytes, pin="uart_rx_pin"):
    for b in data:
        await uart_send_byte(dut, b, pin)


def rd(sig, default=0):
    """Read a 1-bit signal, treating an unresolved value as `default`. The TX
    pin and the verdict strobes are X for the first cycles after configuration,
    before the power-on reset hold expires."""
    try:
        txt = sig.value.binstr
    except Exception:
        return default
    if txt in ("0", "1"):
        return int(txt)
    return default


class TxCapture:
    """Decodes uart_tx_pin back into bytes, and records drop verdicts."""

    def __init__(self, dut):
        self.dut = dut
        self.rx = bytearray()          # handshake reply link (uart_tx_pin, JA)
        self.tel = bytearray()         # telemetry link (telem_tx_pin, JC)
        self.verdicts = []
        cocotb.start_soon(self._tx_mon(dut.uart_tx_pin, self.rx))
        cocotb.start_soon(self._tx_mon(dut.telem_tx_pin, self.tel))
        cocotb.start_soon(self._verdict_mon())

    async def _verdict_mon(self):
        d = self.dut
        while True:
            await FallingEdge(d.clk)
            if rd(d.drop_valid):
                self.verdicts.append((rd(d.drop_fail),
                                      int(d.drop_reason.value)))

    async def _tx_mon(self, pin, out):
        d = self.dut
        while True:
            # idle high; wait for a start bit. An unresolved pin counts as idle.
            while rd(pin, 1) == 1:
                await RisingEdge(d.clk)
            for _ in range(CLKS_PER_BIT + CLKS_PER_BIT // 2):
                await RisingEdge(d.clk)             # settle into bit 0
            val = 0
            for i in range(8):
                val |= rd(pin, 1) << i
                for _ in range(CLKS_PER_BIT):
                    await RisingEdge(d.clk)
            out.append(val)


def find_frame(stream: bytes, want_len: int):
    """Pull the first frame of exactly want_len bytes out of the TX stream.
    Telemetry frames start 0xA5 0x5A and are 52 bytes; the handshake reply is
    816 bytes and starts with its own big-endian length."""
    for i in range(len(stream) - 1):
        if int.from_bytes(stream[i:i + 2], "big") == want_len:
            cand = stream[i:i + want_len]
            if len(cand) == want_len:
                return cand
    return None


async def reset_and_keygen(dut, cap):
    dut.uart_rx_pin.value = 1
    dut.attacker_rx_pin.value = 1
    dut.btn_rst.value = 1
    for _ in range(20):
        await RisingEdge(dut.clk)
    dut.btn_rst.value = 0
    # the startup KeyGen must start and finish before anything else works
    for _ in range(400):
        await RisingEdge(dut.clk)
        if rd(dut.kem_busy) == 1:
            break
    assert rd(dut.kem_busy) == 1, "startup KeyGen never started"
    for n in range(60000):
        await RisingEdge(dut.clk)
        if rd(dut.kem_busy, 1) == 0:
            dut._log.info(f"startup KeyGen finished after about {n} cycles")
            return
    raise TimeoutError("startup KeyGen did not finish")


@cocotb.test()
async def top_handshake_then_data(dut):
    """The whole pipeline: handshake in, ciphertext out, then clean, signature
    and tampered data packets."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    cap = TxCapture(dut)
    await reset_and_keygen(dut, cap)

    # ---- 1. the host generates a key pair and sends its ek -----------------
    d_seed = bytes(range(32))
    z_seed = bytes(range(32, 64))
    ek, dk = keygen_internal(d_seed, z_seed)
    assert len(ek) == 800

    cap.rx.clear()
    await uart_send(dut, wire_frame(eth_ip_udp(ek, PORT_HS_INIT)))

    # ---- 2. the board runs Encaps and transmits the ciphertext back --------
    # The reply is 816 bytes at 10 clocks per bit, so about 82,000 clocks of
    # serial time on top of the Encaps itself. Scan only when enough bytes have
    # arrived to contain a whole frame, and only every so often: find_frame is a
    # linear scan and calling it every cycle is quadratic.
    reply = None
    for n in range(1_200_000):
        await RisingEdge(dut.clk)
        if len(cap.rx) >= 816 and (n % 500 == 0):
            reply = find_frame(bytes(cap.rx), 816)
            if reply is not None:
                dut._log.info(f"ciphertext reply captured after about {n} cycles")
                break
    if reply is None:
        raise TimeoutError(f"no 816-byte reply; captured {len(cap.rx)} TX bytes")

    payload, trailer = reply[2:2 + 810], reply[2 + 810:]
    assert compute_crc32(payload) == int.from_bytes(trailer, "big"), \
        "ciphertext reply failed its own CRC-32"
    assert payload[12:14] == b"\x08\x00", "reply is not IPv4"
    assert ip_checksum(payload[14:34]) == 0, "reply has a bad IPv4 header checksum"
    assert int.from_bytes(payload[36:38], "big") == PORT_HS_RESP, \
        "reply is not classified as HS_RESP"
    ct = payload[42:]
    assert len(ct) == 768, f"ciphertext is {len(ct)} bytes"

    # ---- 3. the derived secrets must agree --------------------------------
    k_host = decaps_internal(dk, ct)
    k_fpga = int(dut.kem_shared_secret.value).to_bytes(32, "little")
    assert k_host == k_fpga, (
        "handshake completed but the two sides derived different secrets\n"
        f"  host: {k_host.hex()}\n  fpga: {k_fpga.hex()}")
    assert int(dut.any_session_up.value) == 1, "no session established"
    assert rd(dut.led[0]) == 1, "LD0 should show an established session"
    dut._log.info(f"shared secret agreed: {k_host.hex()[:32]}...")

    # ---- 4. a clean data packet must pass ---------------------------------
    aad = (HOST_IP.to_bytes(4, "big") + FPGA_IP.to_bytes(4, "big")
           + HOST_PORT.to_bytes(2, "big") + PORT_DATA.to_bytes(2, "big"))

    async def send_data(plaintext, nonce_ctr, corrupt_tag=False):
        nonce = nonce_ctr.to_bytes(12, "little")
        c, tag = chacha20_poly1305_encrypt(k_host, nonce, aad, plaintext)
        if corrupt_tag:
            tag = bytes([tag[0] ^ 0xFF]) + tag[1:]
        cap.verdicts.clear()
        await uart_send(dut, wire_frame(eth_ip_udp(c + tag, PORT_DATA)))
        for _ in range(60000):
            await RisingEdge(dut.clk)
            if cap.verdicts:
                return cap.verdicts[-1]
        raise TimeoutError("no drop_engine verdict for the data packet")

    v = await send_data(b"GET /index.html HTTP/1.1\r\n\r\n", 0)
    assert v == (0, RC_NONE), f"clean data packet was not forwarded: {v}"

    # ---- 5. a signature in the PLAINTEXT must be caught -------------------
    v = await send_data(b"user input: whoami ; id", 1)
    assert v == (1, RC_SIGNATURE), f"signature in plaintext not caught: {v}"
    # LD4 blinks at the "fast" rate (120 ms period, so 6 million cycles), so it
    # has to be sampled across a whole period rather than at one instant.
    # The hold timer behind LD4 is the deterministic evidence that the LED was
    # triggered; sampling the pin would mean stepping a 120 ms blink period.
    # led_driver registers it on the same edge the verdict strobes, so give it
    # a couple of cycles to settle before reading.
    for _ in range(4):
        await RisingEdge(dut.clk)
    assert int(dut.u_led.hold[4].value) != 0, "LD4 hold timer not armed for RC_SIGNATURE"

    # ---- 6. a tampered tag must be caught --------------------------------
    v = await send_data(b"harmless payload", 2, corrupt_tag=True)
    assert v == (1, RC_BAD_TAG), f"tampered tag not caught: {v}"

    # ---- 7. the attacker link, concurrently with the sender --------------
    # A corrupted-CRC frame on JB while a clean data packet goes in on JA. Both
    # must be judged: the arbiter interleaves whole frames, it does not lose or
    # merge either.
    bad = bytearray(wire_frame(eth_ip_udp(b"attacker traffic", PORT_DATA)))
    bad[-1] ^= 0xFF
    nonce = (3).to_bytes(12, "little")
    c, tag = chacha20_poly1305_encrypt(k_host, nonce, aad, b"GET /second HTTP/1.1\r\n\r\n")
    good = wire_frame(eth_ip_udp(c + tag, PORT_DATA))
    cap.verdicts.clear()
    t_att = cocotb.start_soon(uart_send(dut, bytes(bad), pin="attacker_rx_pin"))
    t_snd = cocotb.start_soon(uart_send(dut, good))
    await t_att
    await t_snd
    for _ in range(80000):
        await RisingEdge(dut.clk)
        if len(cap.verdicts) >= 2:
            break
    got = sorted(cap.verdicts)
    assert (0, RC_NONE) in got, f"sender frame lost while attacker was active: {got}"
    assert (1, RC_CRC_FAIL) in got, f"attacker CRC fault not reported: {got}"
    assert int(dut.u_rx_arb.drop_a.value) == 0 and int(dut.u_rx_arb.drop_b.value) == 0

    # ---- 8. telemetry is on its own link, and the reply link carries none --
    for _ in range(300_000):                   # TELEM_PERIOD_MS = 1 -> 100k clocks
        await RisingEdge(dut.clk)
        if b"\xa5\x5a" in bytes(cap.tel) and len(cap.tel) >= 52 + 2:
            break
    i = bytes(cap.tel).find(b"\xa5\x5a")
    assert i >= 0 and len(cap.tel) >= i + 52, f"no telemetry frame on telem_tx_pin ({len(cap.tel)} bytes)"
    frame = bytes(cap.tel[i:i + 52])
    assert sum(frame) & 0xFF == 0, "telemetry frame does not sum to zero mod 256"
    assert b"\xa5\x5a" not in bytes(cap.rx[816:]), "telemetry leaked onto the handshake link"

    dut._log.info("end-to-end: handshake, secret agreement, pass, signature, bad tag, "
                  "concurrent attacker link, separate telemetry link")


# ==============================================================================
# Runner for pytest / command-line execution
# ==============================================================================
import pytest


@pytest.mark.parametrize("sim_build", ["sim_build_pqc_nids_top"])
def test_runner(sim_build):
    from cocotb.runner import get_runner

    proj = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    dirs = ["rtl/ingress", "rtl/control", "rtl/detect", "rtl/io",
            "rtl/crypto/chacha_poly", "rtl/crypto/kem", "rtl/crypto/ntt",
            "rtl/crypto/sha3", "rtl/top"]
    sources = []
    for d in dirs:
        full = os.path.join(proj, *d.split("/"))
        sources += [os.path.join(full, f) for f in sorted(os.listdir(full))
                    if f.endswith(".v")]
    includes = [os.path.join(proj, *d.split("/")) for d in dirs]

    runner = get_runner("icarus")
    runner.build(verilog_sources=sources, includes=includes,
                 hdl_toplevel="pqc_nids_top",
                 parameters={"BAUD_RATE": 10_000_000, "TELEM_PERIOD_MS": 1},
                 build_dir=os.path.join(proj, "sim", sim_build), always=True)
    runner.test(hdl_toplevel="pqc_nids_top", test_module="test_pqc_nids_top",
                test_dir=os.path.join(proj, "sim", "cocotb"))


if __name__ == "__main__":
    test_runner("sim_build_pqc_nids_top")

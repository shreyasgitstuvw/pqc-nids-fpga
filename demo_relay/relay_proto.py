"""
demo_relay/relay_proto.py -- the board -> peer frame.

    B0 7E | len (1) | counter (8, little-endian) | ciphertext (len) | tag (16)

ChaCha20-Poly1305 under the peer's own session key (the one its ML-KEM handshake
produced), no associated data. Nonce = counter (8 bytes LE) followed by 00 00 00 80,
the 0x80 marking the board->peer direction so a (key, nonce) pair is never reused
against the peer->board direction. The tag authenticates everything that matters,
so the frame carries no CRC; a receiver that loses sync scans for B0 7E and keeps
the first candidate whose tag verifies.
"""
MAGIC = b"\xB0\x7E"


def egress_nonce(ctr: int) -> bytes:
    return ctr.to_bytes(8, "little") + b"\x00\x00\x00\x80"


class EgressParser:
    """Feed it raw serial bytes; it yields (counter, ciphertext, plaintext) tuples
    for frames whose tag verifies, and counts frames that did not."""

    def __init__(self, key: bytes):
        from model.chacha_poly import chacha20_poly1305_decrypt
        self._dec = chacha20_poly1305_decrypt
        self.key, self.buf, self.bad = key, bytearray(), 0
        self.last_ctr = -1

    def feed(self, data: bytes):
        self.buf += data
        out = []
        while True:
            i = self.buf.find(MAGIC)
            if i < 0:
                self.buf = self.buf[-1:]          # keep a possible half magic
                break
            if i:
                del self.buf[:i]
            if len(self.buf) < 3:
                break
            n = self.buf[2]
            total = 3 + 8 + n + 16
            if len(self.buf) < total:
                break
            ctr = int.from_bytes(self.buf[3:11], "little")
            ct = bytes(self.buf[11:11 + n])
            tag = bytes(self.buf[11 + n:total])
            ok, pt = self._dec(self.key, egress_nonce(ctr), b"", ct, tag)
            if ok and ctr > self.last_ctr:
                self.last_ctr = ctr
                del self.buf[:total]
                out.append((ctr, ct, pt))
            else:
                self.bad += 1
                del self.buf[:1]                  # false magic or forgery: resync
        return out

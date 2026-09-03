# Member A — Theoretical Understanding Guide (Beginner Level)
## Track: Ingress Pipeline, Packet Parser, Interface Contract

This assumes you know how to write Verilog syntax but nothing about networking, framing, or why any of this is shaped the way it is. Read this before touching the build order in your master guide.

---

## 1. Why does a "packet" need a special hardware pipeline at all?

A network doesn't send you neat, labeled boxes of data. It sends you an electrical/optical signal that toggles a wire high and low over time. Everything from "where does one packet end and the next begin" to "which 32 bits are the source IP address" is a *convention* — an agreement both sides follow — not something physically visible in the signal. Your entire job is building the hardware that knows these conventions and turns a raw bitstream back into structured, meaningful fields.

Think of it like reading a letter with no punctuation, no capital letters, no paragraph breaks — just a continuous stream of characters. You could not identify sentences unless you'd been told the rule in advance ("every sentence is exactly 40 characters", or "a period followed by two spaces marks the end"). Networking protocols are exactly this: pre-agreed rules for carving a continuous stream into meaningful chunks.

## 2. UART — the physical link you're receiving from

UART (Universal Asynchronous Receiver-Transmitter) is one of the simplest ways two devices send bits to each other over a wire, with no shared clock signal between them (that's what "asynchronous" means — contrast with something like SPI, which does share a clock wire).

Since there's no shared clock, both sides must agree in advance on the **baud rate** — how many bits per second are being sent — so the receiver knows when to "sample" the wire. In this project that's 3 Mbaud (3 million bits per second) over the Pmod USB-UART module.

A UART byte transmission looks like this on the wire:
```
idle(high) → start bit(low) → 8 data bits → stop bit(high) → idle(high)
```
Your `uart_rx.v` module's whole job is: watch for that falling edge (start bit), then sample the wire at the agreed baud-rate interval eight times to reconstruct each data byte, then flag `valid` when a full byte has arrived. This is a classic "oversampling" problem — you typically sample well faster than the baud rate (commonly 16x) and vote on the majority value to reject noise, rather than sampling exactly once per bit period.

## 3. Framing — from a byte stream to a "packet"

UART gives you a stream of individual bytes with no concept of where a packet starts or ends — that's a separate, higher-level convention you (the deframer) impose. Two common approaches:

- **Delimiter-based**: a special byte sequence marks start/end (like how a text file might use a specific character to mark "new paragraph"). Risk: what if the actual data contains that same byte sequence? You need an escaping scheme.
- **Length-prefixed**: the first few bytes of a packet declare "the next N bytes are this packet's payload." Simpler to implement in hardware — you just count down — and it's the approach recommended in your build order.

Either way, the deframer's job is to turn "an endless stream of bytes" into "a sequence of discrete packets," each with a clear beginning (`sof`, start-of-frame) and end (`eof`, end-of-frame) signal for the modules downstream.

## 4. CRC — how do you know a packet arrived correctly?

Electrical noise, timing jitter, and interference can flip bits in transit. A **Cyclic Redundancy Check (CRC)** is a mathematical fingerprint computed over the packet's bytes and appended to it. The receiver recomputes the same fingerprint over the bytes it received and compares it to the one that was sent — if they don't match, at least one bit got corrupted in transit, and the packet is discarded.

The key intuition: CRC treats the byte stream as a giant binary number and does polynomial division (over GF(2), a mathematical field where addition is XOR) by a fixed, standardized "generator polynomial." The remainder of that division is the CRC value. This is a well-understood, standardized computation (CRC-32 is extremely common) — you're not inventing an algorithm, you're implementing a known one and verifying against `zlib.crc32` in Python.

**Important distinction you'll need later:** CRC catches *accidental* corruption (noise, glitches). It does nothing against *deliberate* tampering — an attacker who can rewrite a packet can just recompute the correct CRC for their tampered version. That's why there's a second, cryptographic layer (Poly1305, in a different module) checking for deliberate tampering — CRC and Poly1305 are answering different questions ("did noise corrupt this?" vs "did an adversary who doesn't know the secret key alter this?").

## 5. The OSI/networking layers you're parsing

Your parser walks through several nested "envelopes," each layer wrapping the next:

```
[ Ethernet header [ IPv4 header [ TCP or UDP header [ payload data ] ] ] ]
```

- **Ethernet header**: operates at the "local wire" level. Contains destination MAC address (who on this local link should receive it), source MAC address, and an "ethertype" field telling you what's inside (IPv4? ARP? something else?).
- **IPv4 header**: operates at the "which machine anywhere on the internet" level. Contains source IP address, destination IP address, a protocol field (TCP? UDP?), and a total-length field.
- **TCP or UDP header**: operates at the "which application/service on that machine" level, via port numbers. TCP additionally carries connection-state flags (SYN, ACK, FIN, etc.) because it's a connection-oriented protocol; UDP is simpler and connectionless.

Each header has a fixed (or, for some fields, variable) byte layout that's been standardized for decades — you're not designing these formats, you're implementing a reader for formats that already exist. This is exactly why nailing down the **exact bit offsets** in your interface contract matters: you're transcribing an existing, non-negotiable spec into hardware, and a single off-by-one in a bit offset produces a parser that silently reads garbage instead of failing loudly.

## 6. Why "flags" matter for the detection lane later

TCP's SYN flag is what starts a connection (like a knock on a door before it opens). A flood of SYN packets that never complete the connection handshake is a classic Denial-of-Service attack — the "SYN flood" your detection-lane teammate will be watching for. You don't need to detect this yourself, but understanding *why* the TCP flags field matters explains why your parser needs to expose it cleanly on the shared packet bus rather than treating it as an opaque byte.

## 7. Endianness — a quiet trap

Network protocols conventionally transmit multi-byte numbers **big-endian** ("network byte order") — most significant byte first. If your FPGA's internal registers default to little-endian interpretation (common on many architectures, and easy to assume by habit), a 16-bit port number or a 32-bit IP address will come out byte-swapped and *look* plausible while being completely wrong. This is a very common, very quiet bug — always explicitly define byte order in your interface contract and test with a value that's asymmetric enough to catch a swap (e.g., an IP address like `10.0.0.1`, not `1.1.1.1`, since the latter wouldn't reveal a swap bug).

## 8. Why you're the "foundation" track

Every downstream module — the crypto lane, the detection lane, the control logic — reads structured fields (source IP, destination port, TCP flags, payload bytes) that only exist because your parser extracted them from the raw bitstream. If your interface contract is ambiguous about a field's width or byte order, every other team member is building against a guess, and guesses from four different people rarely agree with each other by the time everyone integrates in Phase VI. That's the entire reason your first deliverable is a document, not code.

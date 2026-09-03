# Member D — Theoretical Understanding Guide (Beginner Level)
## Track: ChaCha20-Poly1305, Session Management, Drop Engine

This assumes no cryptography background beyond what's in Member C's guide's §7 (KEM basics) — read that section first if you haven't, since it explains where your session key comes from. This guide covers the symmetric-crypto and control-logic theory specific to your track.

---

## 1. Symmetric vs. asymmetric crypto — why you need a different tool once a key exists

Member C's track (ML-KEM) solves a hard problem: two parties who've never met agree on a secret, over a channel an eavesdropper can watch, without that secret ever being transmitted. This kind of "asymmetric" cryptography is mathematically expensive — it relies on hard problems like lattice arithmetic specifically *because* that difficulty is what protects the secret before both sides share it.

But once both sides *do* share a secret key, you don't need any of that expensive machinery anymore — you need something fast, since it now has to run on every single byte of every packet, potentially millions of times per session, rather than once. This is **symmetric cryptography**: both sides use the *same* secret key, and the underlying operations are simple, fast, and repetitive (XOR, bit rotation, addition) rather than complex algebraic structures. ChaCha20-Poly1305 is exactly this — the "workhorse" layer that runs constantly, in contrast to the KEM's "one expensive handshake per session."

## 2. Stream ciphers — what ChaCha20 actually is

There are two broad families of symmetric ciphers: **block ciphers** (like AES) encrypt fixed-size chunks (e.g., 128 bits) at a time, with a complex, tightly-interlinked internal structure per block. **Stream ciphers** instead generate a long, unpredictable sequence of bits (a "keystream") derived from the key, and encrypt data by simply XORing it with that keystream, one bit or byte at a time, for as long as needed.

ChaCha20 is a stream cipher: given a key and a "nonce" (a number used once, to ensure the same key never produces the same keystream twice), it generates an arbitrarily long keystream. Encryption is then just: `ciphertext = plaintext XOR keystream`. Decryption is identical: `plaintext = ciphertext XOR keystream` — XOR is its own inverse, which is why this is so cheap in hardware. **The entire security of the scheme rests on the keystream being computationally indistinguishable from true randomness** to anyone who doesn't know the key — if it weren't, an attacker could predict the keystream and undo the XOR without ever needing the key.

## 3. ARX — why ChaCha20 is "cheap" in hardware, specifically

ChaCha20's internal keystream generator is built entirely from three operations: **A**ddition (mod 2³²), **R**otation (circular bit-shift), and **X**OR. This is called an "ARX" design. None of these operations need a lookup table, a substitution box, or a finite-field multiplier — they're the simplest, cheapest operations a digital circuit can perform, and they map onto FPGA logic (adders, shift/rotate wiring, XOR gates) about as directly as an algorithm can.

Compare this to AES (the block-cipher alternative your synopsis explicitly considered and rejected — AES-GCM), which relies on a substitution box (a lookup table implementing a specific nonlinear function) and, for its authentication mode (GCM), Galois-field multiplication — a genuinely more complex arithmetic operation. This is the concrete reason your synopsis states ChaCha20-Poly1305 costs roughly half the logic of AES-GCM and closes timing more easily at 100 MHz: it's not a vague preference, it's the direct hardware cost of ARX operations versus S-boxes and Galois multiplication.

The internal building block is the **quarter-round**: a small, fixed sequence of add/rotate/XOR operations applied to four 32-bit words. The full ChaCha20 state is a 4×4 matrix of 32-bit words (512 bits total, derived from the key, nonce, and a counter), and a full round applies quarter-rounds to combinations of rows and diagonals, repeated 20 times (hence "ChaCha20") to sufficiently mix the state before it's used as keystream output.

## 4. Encryption alone is not enough — why you also need Poly1305

Encryption (via XOR with a keystream) protects **confidentiality** — an eavesdropper can't read the plaintext. But it does nothing to protect **integrity** — an attacker who can intercept and modify the ciphertext in transit can flip specific bits, and because XOR is bit-for-bit, flipping a ciphertext bit flips the corresponding plaintext bit in a completely predictable way, *without needing to know the key at all*. Encryption alone gives zero protection against an attacker deliberately tampering with a message they can't read.

**Poly1305** is a Message Authentication Code (MAC) — a small, fixed-size tag computed over the message using a secret key, such that any change to the message (even a single bit) produces a completely different, unpredictable tag with overwhelming probability. The receiver recomputes the tag over what it received and compares it to the tag it was sent; if they don't match, the message was altered (or never authentic in the first place) and must be discarded.

Poly1305 specifically is built on **polynomial evaluation over a large prime field** — conceptually, it treats the message as coefficients of a polynomial and evaluates that polynomial at a secret point (derived from the key), producing the tag. This is a different mathematical structure from ChaCha20's ARX operations, but still comparatively cheap — no lattice arithmetic, no NTT, just modular multiplication and addition.

## 5. AEAD — why encryption and authentication are combined into one construction

Combining a cipher and a MAC is called **Authenticated Encryption with Associated Data (AEAD)**. "Associated data" refers to information (like a packet header) that needs to be authenticated but not encrypted — you want to detect if a header field was tampered with, but the header itself may need to stay readable in the clear for routing.

The specific composition matters and isn't something to improvise: RFC 8439 defines exactly how ChaCha20 and Poly1305 combine (in the standard construction, the ciphertext is produced first, then the MAC is computed over the ciphertext — this is called "encrypt-then-MAC," which is generally the safer ordering compared to alternatives, because it lets you reject a tampered message *before* wasting any effort decrypting it). Implement the composition exactly as specified rather than reordering operations that "seem equivalent" — subtle reorderings of encrypt/authenticate operations have historically introduced real vulnerabilities in other protocols, which is precisely why the standard nails down the exact order.

## 6. Why this distinction matters for your reason-code logic

Your drop engine needs to distinguish **why** a packet was rejected, and there are genuinely different failure classes stacked at different layers:
- **CRC failure** (Member A's ingress layer): accidental bit-flip from electrical noise — nothing cryptographic involved.
- **Poly1305 tag failure** (your layer): the ciphertext or associated data was altered after encryption — deliberate tampering, detected per-packet.
- **FO-transform / implicit-rejection failure** (Member C's layer): the *handshake* itself was attacked with a malformed ciphertext — a different attack surface, checked once per session rather than per packet.

These are conceptually distinct events happening at different stages of the pipeline, and conflating them in your counters would make the final report's security analysis much weaker — "how many packets were tampered with in transit" and "was our session ever under active handshake attack" are different questions a defender would want separate answers to.

## 7. Finite State Machines — the theory behind `session_mgr.v`

A **Finite State Machine (FSM)** is a system that exists in exactly one of a fixed set of named states at any time, and moves between states only in response to defined triggering events. This is the right abstraction for session management because a link genuinely only makes sense in one of a few discrete modes at a time: no session exists yet (`IDLE`), a handshake is currently in progress (`HANDSHAKING`), a shared key has been successfully established and is usable (`ESTABLISHED`), or the handshake failed (`REJECTED`).

The subtlety specific to this project (covered more in your build order) is that the *transition itself*, and everything externally observable about it, must not leak which path was taken on a handshake attempt (success vs. implicit rejection) — the FSM's states are conceptually distinct internally, but from outside the chip, entering `ESTABLISHED` via a genuine handshake and entering the "decoy" path via implicit rejection must be indistinguishable in timing and signaling. This is an unusual requirement for an FSM (normally you'd only care that transitions are logically correct, not that they're externally camouflaged) and is worth designing for explicitly rather than treating as an afterthought.

## 8. Why "silent drops" are treated as a first-class design failure

Your synopsis is explicit that a drop which isn't counted is operationally indistinguishable from an attack that was never even detected — from a security-monitoring standpoint, both look like "nothing happened," even though one case is "we caught and stopped an attack" and the other is "we're blind to something." This is why every discard path in the whole pipeline — CRC failures, Poly1305 tag failures, signature matches, volumetric flags, protocol violations — routes through your drop engine's reason-code counters rather than being silently discarded at the point of failure. Your control logic is what turns "the system defended itself" into something a human operator can actually see and act on.

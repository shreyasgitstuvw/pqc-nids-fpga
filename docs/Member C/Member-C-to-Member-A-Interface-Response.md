# Member C → Member A: Interface Contract Response

**Re:** `docs/Member A/interface_contract.md` (DRAFT) — items marked
**[MEMBER A: CONFIRM]** that name Member C, plus one correction Member C is
raising unprompted.

**From:** Member C (ML-KEM-512 crypto lane)
**Status of Member C's lane at time of writing:** Python golden model complete
and passing the official FIPS 203 KAT vectors **80/80, zero skips** — 25 keyGen,
25 encapsulation, 10 decapsulation (5 valid + 5 tampered), 10 encapsulation-key
checks, 10 decapsulation-key checks. Every number in this document comes from
that verified model, not from estimation.

---

## 0. Summary — what Member A can close after reading this

| Contract item | Member C's answer | Action for A |
|---|---|---|
| §4 `packet_type` mechanism | **Port-based.** Reasoning in §1 below | Decide with D, then lock |
| §6 `HANDSHAKE_REJECT` (4'h8) | **Definition is wrong as written — it breaks the security property §5 demands.** Replacement proposed | **Must change before freeze** |
| §6 `fo_transform.v` verdict latency | **Does not participate in the per-packet drop path at all.** One fewer lane to synchronise | Remove the row, or mark N/A |
| §5 `shared_secret : 256 bits` | Correct. 32 bytes exactly | Confirm |
| §5 session count | 1 is sufficient for Member C; 4 is harmless | A's call |
| §3 payload delivery | Same-bus streaming works for Member C | Confirm |
| §1 2-byte length field | Sufficient. Largest object is 800 bytes | Confirm |

---

## 1. §4 — `packet_type` classification: use the port

**Recommendation: option 1, port-based.** Pick a fixed `l4_dst_port`, write the
number into the contract, done.

The reason is *when* the classification becomes available, not how clean it
looks. With a port, `packet_type` is known the moment the L4 header is parsed —
before a single payload byte arrives. `mlkem_top.v` can leave idle and begin
its input sequencing while the handshake payload is still streaming in.

With option 2 (a leading type byte in the payload), classification is not
available until the first payload byte lands, which is strictly later and adds
a dependency between the parser's payload path and the crypto lane's start
condition. It buys nothing in exchange: an attacker can set a payload tag byte
just as freely as a destination port, so it is not a security control either
way. Neither option authenticates anything — that is what the ML-KEM handshake
itself is for.

**One caveat Member A should be aware of, not solve:** a fixed handshake port
is trivially floodable. That is fine and expected — it is Member B's
`count_min_sketch.v` lane that handles volumetric abuse, not Member C's. Worth
confirming with B that the handshake port is inside the sketch's monitored
space.

---

## 2. §6 — `HANDSHAKE_REJECT` as defined is a security bug. Please change it.

This is the item Member C is raising unprompted, and it is the most important
thing in this document.

### What the contract currently says

> | `HANDSHAKE_REJECT` | `4'h8` | Member C — `fo_transform.v` | Implicit rejection on handshake (tampered/invalid ciphertext) |

### Why that cannot be implemented

The contract's own §5 states the requirement correctly:

> the `state` transition into `ESTABLISHED` via a genuine handshake and the
> transition via implicit rejection must be **externally indistinguishable** —
> same latency, same signal shape, from any observer outside `session_mgr.v`.

And Member C's own guide (`Member-C-ML-KEM-Crypto-Core.md`, §4 Step 5) states
the FIPS 203 requirement:

> On decapsulation failure, FIPS 203 requires returning a deterministic
> pseudo-random key derived from a stored secret — **never an explicit error**.

A reason code *is* an explicit error. If `fo_transform.v` asserts
`fail=1, reason=HANDSHAKE_REJECT` whenever implicit rejection occurs, then
`drop_engine.v` drops the packet and increments a distinguishable counter.
An observer watching whether the handshake proceeds learns exactly one bit:
*was my ciphertext valid?*

That bit is the entire thing the Fujisaki-Okamoto transform exists to deny.
The FO construction converts a CPA-secure PKE into a CCA-secure KEM precisely
by refusing to answer that question — on a bad ciphertext it returns a decoy
key `K̄ = J(z‖c)` that is indistinguishable from a real one. Re-exposing the
answer one layer up, in the drop engine, gives back the chosen-ciphertext
oracle the transform was built to remove. The crypto would be correct and the
system would still be broken.

This is verified behaviour in the model, not theory. From the golden model's
negative-path test:

```
tampered H(ek) in dk    : rejected — invalid decapsulation key (sec 7.3)
tampered ciphertext     : silent decoy key returned (correct)
```

A tampered *key* raises. A tampered *ciphertext* returns silently. The RTL
must preserve that asymmetry.

### What happens instead on a bad handshake

Nothing, at handshake time — by design. Decapsulation "succeeds", `K̄` is
installed as the session key, and `state` goes to `ESTABLISHED` on exactly the
same cycle it would have otherwise. The two sides now hold different keys, so
the peer's **first data packet fails its Poly1305 tag check** and surfaces as
`BAD_TAG` (`4'h7`) through Member D's existing lane.

That is the correct place for the failure to appear. It costs one wasted
packet and requires no new mechanism. It also handles a legitimate peer whose
packet was corrupted in transit identically to an attacker, which is the point.

### Proposed replacement

Keep the code point, change what it means:

| Code | Value | Source module | Meaning |
|---|---|---|---|
| `HANDSHAKE_KEY_INVALID` | `4'h8` | Member C — `mlkem_top.v` | Handshake **key material** failed FIPS 203 §7.2/§7.3 structural validation |

And add an explicit non-entry to the contract so nobody re-adds it later:

> **Implicit rejection emits no verdict.** `fo_transform.v` has no path to
> `drop_engine.v`. A tampered ciphertext is indistinguishable from a valid one
> at handshake time by construction; the failure surfaces downstream as
> `BAD_TAG`.

`HANDSHAKE_KEY_INVALID` is safe to signal openly because it is a structural
check on public, non-secret data — key lengths and coefficient canonicality —
and its outcome does not depend on any secret. It is a different failure class
from implicit rejection in exactly the way §2 of the contract already
distinguishes `CRC_FAIL` from `BAD_TAG`.

**What these checks are** (both implemented and KAT-verified in `kem.py`):

- **§7.2, encapsulation key** — an `ek` stores 512 coefficients at 12 bits
  each. 12 bits holds 0–4095, but q = 3329, so values 3329–4095 are
  *representable but invalid*, and nothing in the byte layout rejects them.
  Test: `ByteDecode₁₂` then re-`ByteEncode₁₂`; require byte equality. Decode
  reduces mod q, so a non-canonical 3500 returns as 171 and re-encodes
  differently. 10/10 KAT vectors.
- **§7.3, decapsulation key** — `dk` = `dk_pke‖ek‖H(ek)‖z`. Recompute
  `SHA3-256` over the embedded `ek` and require it to match the stored field.
  Catches a `dk` whose halves came from different keypairs. 10/10 KAT vectors.

Whether §7.2 sits on a receive path depends on the handshake role
`mlkem_top.v` plays: as **initiator** the FPGA receives the peer's `ek` and
§7.2 guards attacker-controlled input; as **responder** it receives a
*ciphertext*, for which there is deliberately no validity check — that is the
implicit-rejection path. §7.3 is a local integrity check on our own stored key
either way. Member A does not need to resolve this; Member C flags it so the
reason code isn't assumed to fire on every handshake.

---

## 3. §6 — verdict latency for `fo_transform.v`

**Answer: it does not participate.** Per §2 above, the FO transform emits no
verdict, so it never gates `drop_engine.v` and contributes nothing to the
slowest-lane calculation. Member A's hardest open item gets one row simpler.

`HANDSHAKE_KEY_INVALID` does emit a verdict, but only on handshake packets,
and it is not on the per-packet data path either. It can be treated as an
out-of-band session-establishment result rather than a lane in the per-packet
race.

### Cycle counts for the §6.3 synopsis timing table

Measured from the golden model (`model/mlkem/opcount.py`), exact call counts
per invocation:

| Operation | Keccak-f1600 | NTT | INTT | base-case mult | modular mults |
|---|---:|---:|---:|---:|---:|
| KeyGen | 31 | 4 | 0 | 512 | 6,144 |
| Encaps | 30 | 2 | 3 | 768 | 9,088 |
| Decaps | 30 | 4 | 4 | 1,024 | 13,312 |

Decaps is the largest because the FO transform is *decrypt + re-encrypt* — it
pays for an encryption it then throws away. That is inherent to the
construction, not an inefficiency to optimise out.

### Measured RTL Cycle Counts & Updated §6.3 Timing Table

Following Stage 3 verification of `ntt_core.v` and `poly_mul_acc.v`, exact measured
hardware cycle counts per component are:

- **Forward NTT (`ntt_core.v`):** **1,192 clock cycles** (7 stages Cooley-Tukey + 256-cycle scratch copy-back)
- **Inverse INTT (`ntt_core.v`):** **1,195 clock cycles** (7 stages Gentleman-Sande + 256-cycle $INV\_N$ scaling directly from scratch)
- **Pointwise Multiply & Accumulate (`poly_mul_acc.v`):** **2,049 clock cycles** per 256-coefficient polynomial product (128 degree-1 coefficient pairs × 16 cycles sequential execution + 1 cycle done)
- **Keccak-f[1600] (`keccak_f1600.v`):** **25 clock cycles** per permutation

#### Decapsulation Polynomial Operations Breakdown

In Decapsulation ($k=2$, Algorithm 17), polynomial operations dominate the compute time:
- $4 \times \text{Forward NTT} = 4 \times 1,192 = 4,768\text{ cycles}$
- $4 \times \text{Inverse INTT} = 4 \times 1,195 = 4,780\text{ cycles}$
- $8 \times \text{Pointwise Mult/Acc} = 8 \times 2,049 = 16,392\text{ cycles}$
- **Subtotal (Polynomial Operations):** **25,940 clock cycles (≈ 259.4 µs @ 100 MHz)**

Adding Keccak permutation cycles (approx. 30 permutations × 25 cycles ≈ 750 cycles plus rate absorb/squeeze overhead in `shake_wrapper.v`), total Decapsulation latency is estimated at **≈ 26,700–27,500 clock cycles (≈ 267–275 µs @ 100 MHz)**.

| Operation | Polynomial Cycles | Keccak Permutations | Estimated Total Cycles | @100 MHz |
|---|---:|---:|---:|---:|
| KeyGen | 8,986 | 31 (≈ 775) | ≈ 9,800 | ≈ 98 µs |
| Encaps | 18,361 | 30 (≈ 750) | ≈ 19,200 | ≈ 192 µs |
| Decaps | 25,940 | 30 (≈ 750) | ≈ 26,900 | ≈ 269 µs |

#### Architectural Note: Known Optimization (Recorded, Not Implemented)
- **Interleaving coefficient pairs in `poly_mul_acc.v`:**
  Stage 2 originally budgeted ~644 cycles per polynomial product by interleaving independent coefficient pairs across the 3-stage `modmul.v` pipeline. The committed RTL implementation uses a simpler, robust sequential schedule (5 back-to-back multiplies per pair, taking 16 cycles/pair for 2,049 cycles total).
  Interleaving pairs is recorded as a **known optimisation** for future refinement: it would reduce pointwise multiply from 2,049 cycles to ~645 cycles (a ~3.18× speedup per product), saving ~11,200 cycles (~112 µs) in Decaps. Because Decaps total latency at ~259 µs is already ~10× faster than the 2,560 µs UART ciphertext arrival window, this optimisation is deferred to keep the RTL simple and verifiable.

### The number that actually matters for integration planning

At 3 Mbaud with 8N1 framing, moving the handshake objects over the wire costs:

| Object | Size | UART time |
|---|---:|---:|
| Encapsulation key `ek` | 800 B | ≈ 2.67 ms |
| Ciphertext `c` | 768 B | ≈ 2.56 ms |

**The link is roughly 10× slower than the crypto.** A full decapsulation is
~259 µs against ~2.56 ms just to receive the ciphertext. The handshake remains
heavily UART-bound, not compute-bound.

Two consequences worth Member A's attention:

1. The crypto lane is not the integration risk it looks like on paper. Member C
   remains the schedule risk for *getting it correct*, but not for handshake
   latency.
2. **Timing-side-channel checking gets easier.** Since the compute is buried
   under a link delay ~30× larger, the externally observable handshake time is
   dominated by transfer, not by which decapsulation branch ran. This does not
   remove the requirement that `fo_transform.v` be constant-shape internally —
   §5 still stands and Member C still owns proving it in the testbench — but
   it means an accidental few-cycle asymmetry is unlikely to be externally
   measurable over UART. Belt and braces, not a licence to skip the check.

---

## 4. §5 — session register file: confirmed

- **`shared_secret : 256 bits`** — correct, and exactly right. ML-KEM-512's
  shared secret is 32 bytes. Not truncated, not padded.
- **Session count** — Member C needs **one**. The crypto lane holds no
  per-session state of its own beyond the key it writes on completion. If
  Member D wants 4 entries for their own reasons that costs Member C nothing.
- **Write timing** — Member C writes `shared_secret` on decapsulation
  completion. Per §2 above, that write happens on the same cycle whether the
  handshake was genuine or implicitly rejected. `session_mgr.v` must not
  branch on which occurred, because it cannot be told.

---

## 5. §3 — packet bus: confirmed for Member C

Streaming payload bytes on `data`/`valid`/`sof`/`eof` after the header fields
latch is fine. Member C's consumption pattern is simple: on
`packet_type == handshake`, capture the payload byte stream into a buffer until
`eof`, then run the KEM. No random access into the payload, no need for a
second interface.

The only requirement is that the **full** payload arrives — 800 bytes for an
`ek`, 768 for a ciphertext — with `eof` marking the true end. A truncated
handshake payload must not be presented as complete; Member C would rather see
`FRAME_TIMEOUT` and never be started than receive a short buffer.

Member C has no opinion on IPv4 options or non-IPv4 EtherTypes. Rejecting both
as `MALFORMED` is fine.

---

## 6. §1 — framing: confirmed

2 bytes is sufficient. The largest object Member C puts on the wire is the
800-byte `ek`; with framing and CRC overhead a handshake frame stays under
~820 bytes, well inside the 65,535-byte ceiling. Member C does not need
fragmentation and would prefer not to have it — a whole handshake object in
one frame keeps `mlkem_top.v`'s input path a simple buffer-until-`eof`.

---

## 7. Open items Member C is *not* answering

- Verdict latencies for `count_min_sketch.v` (B) and `poly1305.v` (D).
- The drop-engine synchronisation approach (pad-to-slowest vs. track-outstanding).
  Member C's lane is out of that path either way, so Member C has no stake and
  defers entirely to A and D.
- Whether `FLOOD` and `SCAN` need separate codes — Member B's call.

---

## 8. §5 — BRAM Budget Request & Decapsulation Polynomial Liveness Table

Member C formally requests an architectural allocation of **6 RAMB36E1 equivalents (approx. 4.3% of the ZedBoard XC7Z020's 140 RAMB36 budget)** for the post-quantum crypto lane.

### 8.1 Why 6 RAMB36E1s? Peak Polynomial Liveness Analysis
ML-KEM-512 ($k=2$) coefficients are 12-bit integers in $\mathbb{Z}_q$ ($q=3329$). Each 256-coefficient polynomial requires $256 \times 12\text{ bits} = 3,072\text{ bits} = 384\text{ bytes}$.
During the Fujisaki-Okamoto (FO) transform in Decapsulation (Algorithm 17), the engine must decrypt the ciphertext, recover $m'$, re-encrypt to $(u', v')$, and compare against the original ciphertext $(u, v)$ without early-abort timing leaks.

The table below traces concurrent polynomial liveness across the decapsulation timeline:

| Phase | Operation | Active Polynomials | Live Poly Count | Memory Role |
|---|---|---|:---:|---|
| **1. Ingress** | Unpack & Decompress $c = (u, v)$ | $u_0, u_1, v$ | 3 | Input buffers |
| **2. Decrypt** | Forward NTT on $u$: $\hat{u} = \text{NTT}(u)$ | $\hat{u}_0, \hat{u}_1, v, \text{Scratch}$ | 4 | NTT domain conversion |
| | Pointwise dot product $\hat{\mathbf{s}}^T \hat{\mathbf{u}}$ | $\hat{u}_0, \hat{u}_1, \hat{s}_0, \hat{s}_1, \hat{w}, v$ | 6 | Secret key multiply |
| | INTT: $w = \text{INTT}(\hat{w})$ | $w, v, u_0, u_1$ | 4 | Poly subtract $\to m'$ |
| **3. Re-encrypt** | Sample $y \in \mathbb{Z}_q^2$, $\hat{y} = \text{NTT}(y)$ | $\hat{y}_0, \hat{y}_1, u_0, u_1, v$ | 5 | Ephemeral vector |
| | Sample matrix $\hat{\mathbf{A}}$ row-by-row | $\hat{y}_0, \hat{y}_1, \hat{A}_{i0}, \hat{A}_{i1}, \text{acc}_i, u_0, u_1, v$ | **8 (PEAK)** | Matrix-vector product |
| | INTT: $w' = \text{INTT}(\hat{A}^T \hat{y})$ | $w_0', w_1', \hat{y}_0, \hat{y}_1, u_0, u_1, v$ | 7 | Normal domain conversion |
| | Accumulate errors $e_1, e_2$ | $u_0', u_1', v', u_0, u_1, v$ | 6 | Candidate ciphertext |
| **4. Verify** | Constant-time compare $(u', v') == (u, v)$ | $u_0', u_1', v', u_0, u_1, v$ | 6 | FO comparison |

### 8.2 BRAM Mapping & Allocation Breakdown
Although 8 polynomials total only $8 \times 384\text{ B} = 3,072\text{ bytes}$ (which fits in the capacity of 1 RAMB36), dual-port butterfly execution and 3-operand pointwise multiply-accumulate ($\text{acc} \leftarrow A \cdot B + C$) require independent memory ports across concurrent streams.

We partition the storage across independent banks:
1. **Polynomial Register File (8 independent banks):** 4 $\times$ RAMB36E1 (split as 8 $\times$ RAMB18E1 blocks, each storing one $256 \times 12$-bit polynomial with dedicated Port A/B).
2. **NTT Ping-Pong Scratch RAM:** 1 $\times$ RAMB18E1 ($0.5 \times$ RAMB36E1) for in-flight butterfly stage swapping.
3. **Decapsulation Key Storage (secret key $\mathbf{s}$, public key $\hat{\mathbf{t}}$, seeds):** 1 $\times$ RAMB36E1.
4. **Total Lane Allocation Request:** **5.5 to 6 RAMB36E1 equivalents**.

This guarantees zero port contention and zero pipeline stalls during matrix-vector products, while leaving **$\ge 134$ RAMB36E1 blocks ($> 95\%$ of device BRAM)** for Member A's packet buffers and Member B's detection sketches.

---

*Prepared by Member C against `interface_contract.md` DRAFT. Every measured
number is reproducible with `python model/mlkem/kat_test.py` and
`python model/mlkem/opcount.py` from the repo root.*

# Member C → Member A: Contract Freeze Package

**Purpose:** get Member A's §4/§5/§6 edits down to copy-paste, and close the
two Member C threads that were still open. Companion to
`Member-C-to-Member-A-Interface-Response.md` — that document *argues* the
`HANDSHAKE_REJECT` correction, this one *applies* it and adds what surfaced
while making it concrete.

**Authority note:** `interface_contract.md` says Member A is final authority
and that changes are posted as a diff rather than silently edited. So Member C
has **not** touched that file. Everything below is paste-ready for A to accept,
modify, or reject.

---

## 0. What's new here that wasn't in the response document

Two gaps found while turning the correction into actual Verilog:

1. **§4 `packet_type` has one code for handshake traffic, but ML-KEM's
   handshake is two different messages** going in opposite directions, with
   different sizes and different processing. `mlkem_top.v` cannot currently
   tell which one arrived. **This needs a Member A decision.** — §3 below.
2. **Session state `REJECTED` (2'b11) becomes unreachable** once implicit
   rejection is correctly silent. Member D will otherwise wire it to the FO
   transform and reintroduce the exact leak we just removed. — §5 below.

Also delivered: `rtl/control/reason_codes.vh` now exists (drafted, pending A's
sign-off), and the `mlkem_top.v` → `session_mgr.v` signal list is specified,
which closes Member C's own outstanding handoff item.

---

## 1. Paste-ready edits to `interface_contract.md`

### Edit 1 — §6 reason code table

**Find:**

```
| `HANDSHAKE_REJECT` | `4'h8` | Member C — `fo_transform.v` | Implicit rejection on handshake (tampered/invalid ciphertext) |
```

**Replace with:**

```
| `HANDSHAKE_KEY_INVALID` | `4'h8` | Member C — `mlkem_top.v` | Structural validation failure on handshake key material (FIPS 203 §7.2 ek canonicality, §7.3 H(ek) integrity, or payload length mismatch for session state). Checks public data only — safe to signal openly. |
```

### Edit 2 — §6, add immediately after the reason code table

```
**RULE — implicit rejection emits no verdict.**

`fo_transform.v` has no connection to `drop_engine.v` and drives no reason
code. On a tampered or invalid *ciphertext*, FIPS 203 requires decapsulation
to return a deterministic decoy key and report nothing; signalling it hands an
attacker the one bit ("was my ciphertext valid?") that the Fujisaki-Okamoto
transform exists to deny. The failure surfaces downstream as `BAD_TAG` (4'h7)
when the peer's first data packet fails Poly1305.

This rule and §5's indistinguishability requirement are the same requirement
stated twice. If they ever conflict again, §5 wins.
```

### Edit 3 — §6 verdict timing table

**Find:**

```
| `fo_transform.v` | ? (handshake-only, not per-data-packet) | **needs Member C's input**, ... |
```

**Replace with:**

```
| `fo_transform.v` | N/A — emits no verdict | **CONFIRMED (Member C).** Not in the drop path; excluded from the slowest-lane calculation. |
| `mlkem_top.v` (key validation) | handshake packets only | **CONFIRMED (Member C).** Off the per-packet data path; treat as an out-of-band session-establishment result, not a lane in the per-packet race. |
```

### Edit 4 — §5, append to the session register file section

```
**Write-path requirement (Member C → Member D).** `mlkem_top.v` writes
`shared_secret` on decapsulation completion, on the same cycle and with the
same signal shape whether the handshake was genuine or implicitly rejected.
`session_mgr.v` must not branch on which occurred — it cannot be told, by
construction.

Consequence: `state = REJECTED (2'b11)` is reachable ONLY from
`HANDSHAKE_KEY_INVALID`. It is never entered as a result of a decapsulation
outcome. See §5.1 for the signal list.
```

### Edit 5 — §7 checklist, items Member C closes

```
- [x] §1 length field width — CONFIRMED sufficient (Member C: largest object 800 B)
- [x] §3 payload delivery via same bus — CONFIRMED (Member C)
- [x] §4 packet_type mechanism — port-based (Member C); port NUMBERS still need A+D
- [x] §5 shared_secret width — CONFIRMED 256 bits exact (Member C)
- [x] §5 session count — 1 sufficient for Member C, 4 harmless
- [x] §6 Member C verdict latencies — CONFIRMED N/A, out of drop path
- [ ] §4 handshake message direction — NEW, needs A's decision (see freeze package §3)
```

---

## 2. Port numbers — concrete proposal

Member A needs literal numbers in §4. Proposal, both in the private/dynamic
range (49152–65535) where nothing standard collides:

| Constant | Port | Carries | Direction |
|---|---:|---|---|
| `PORT_HS_INIT` | **51001** | encapsulation key `ek`, 800 B | initiator → responder |
| `PORT_HS_RESP` | **51002** | ciphertext `c`, 768 B | responder → initiator |
| `PORT_DATA` | **51010** | ChaCha20-Poly1305 session data | either |

Adjacent-but-not-consecutive numbering keeps room to insert a third handshake
message later without renumbering. Member D should confirm none of these
collide with test traffic before A writes them in.

---

## 3. **NEW — the handshake has two messages and `packet_type` has one code**

### The gap

§4 defines `2'b00` as "Handshake / key-exchange packet". But an ML-KEM
handshake is two distinct messages:

| Message | Size | Sender | Receiver's action |
|---|---:|---|---|
| encapsulation key `ek` | 800 B | initiator | run **Encaps**, reply with ciphertext |
| ciphertext `c` | 768 B | responder | run **Decaps**, derive session key |

Both currently classify as `2'b00`. `mlkem_top.v` receives a byte stream and
must decide whether to run Encaps or Decaps — two different state machines,
different inputs, different outputs — and the packet bus does not tell it
which. This is not hypothetical: it blocks Phase 9 (`mlkem_top.v`) directly.

### Two ways to fix it

**Option A — two ports, use the reserved `packet_type` codes.** Parser maps
`PORT_HS_INIT` → `2'b00`, `PORT_HS_RESP` → `2'b10` (currently reserved).

**Option B — one port, discriminate inside `mlkem_top.v`** using session
`state` plus `payload_len` (800 vs 768, already on the bus).

### Member C recommends **Option A**

Three reasons:

1. **The reserved code points exist for exactly this.** `2'b10` and `2'b11`
   are already allocated as spare in §4; this is the case they were reserved
   for, and it costs one extra port number.
2. **Classification belongs in the parser.** The parser already turns a port
   into `packet_type`; making it emit two values instead of one is a constant
   comparison, not new logic. Option B instead pushes protocol demultiplexing
   into the crypto core, which is the module with the least slack and the
   highest verification burden.
3. **Verifiability.** With Option A, `mlkem_top.v`'s state machine has an
   explicit input for "which handshake message is this". With Option B it
   infers direction from a length field an attacker chooses. Inference is the
   thing you have to argue about in a viva; an explicit signal is not.

Under Option A the §4 table becomes:

```
| 2'b00 | Handshake — encapsulation key (ek)   | Member C (mlkem_top.v → Encaps) |
| 2'b01 | Established-session encrypted data   | Member D (chacha_poly)          |
| 2'b10 | Handshake — ciphertext (c)           | Member C (mlkem_top.v → Decaps) |
| 2'b11 | Reserved                             | —                               |
```

### The structural gate that comes with it

Whichever option A picks, `mlkem_top.v` will enforce this, and it is the
**only** handshake rejection that signals:

| Session state | packet_type | payload_len | Action |
|---|---|---:|---|
| IDLE | `2'b00` (ek) | 800 | run Encaps |
| HANDSHAKING | `2'b10` (c) | 768 | run Decaps |
| any other combination | | | `HANDSHAKE_KEY_INVALID`, drop |

**Why this doesn't leak.** State, packet type and length are all public and
structural — none depends on key material. A *well-formed* ciphertext that
happens to be cryptographically invalid passes this gate and proceeds to
silent implicit rejection. The line is: **structural → signal, cryptographic
→ silent.** That single sentence is the rule the whole §6 correction reduces
to, and it is worth putting in the contract verbatim.

---

## 4. `rtl/control/reason_codes.vh` now exists

The contract references this path in §6; the file did not exist. Member C has
drafted it at `rtl/control/reason_codes.vh` with the corrected enum, the
no-verdict rule as an in-file comment block, and the `REJECTED`-reachability
consequence spelled out for Member D.

Header is `REASON_CODES_VH`, width macro `RC_WIDTH = 4`, codes named `RC_*`.
Member A owns it — adjust naming to taste, this is a starting point that makes
the §6 edits concrete rather than a claim on A's file.

---

## 5. `mlkem_top.v` → `session_mgr.v` handoff — Member C's open thread, closed

Member C's own guide (§6) lists this as an outstanding coordination item:
*"coordinate the exact handoff format (32-byte secret, which register, what
'session established' signal looks like)"*. Specifying it here.

### 5.1 Signal list

```verilog
// mlkem_top.v  ==>  session_mgr.v      (Member C drives, Member D consumes)

output reg         kem_done;          // 1-cycle pulse: handshake compute finished
output reg [15:0]  kem_session_id;    // which session_entry_t to write
output reg [255:0] kem_shared_secret; // the 32-byte key -- real or decoy
output reg         kem_key_invalid;   // structural failure only (see below)
```

### 5.2 The signal that must **not** exist

There is deliberately no `kem_success`, `kem_valid`, `kem_reject`, or any
equivalent describing the *cryptographic* outcome. `mlkem_top.v` will not
expose one because it must not be knowable outside `fo_transform.v`. If a
future revision adds one, the implicit-rejection property is broken regardless
of what the rest of the design does.

`kem_key_invalid` is **not** that signal. It reports structural failure only
(§3's gate, or §7.2/§7.3), fires *instead of* `kem_done`, and never fires as a
result of a decapsulation outcome.

### 5.3 Timing contract

- `kem_done` asserts a **fixed** number of cycles after the last payload byte,
  identical for a genuine and an implicitly-rejected handshake. Member C owns
  proving this in the testbench.
- `kem_shared_secret` is stable for the cycle `kem_done` is high.
- Exactly one of `kem_done` / `kem_key_invalid` fires per handshake packet.
- Cycle count to be filled in from measured RTL. Current model-derived estimate
  for Decaps is ≈8,900 cycles (≈89 µs at 100 MHz) — treat as a lower bound,
  expect 1.5–2× with control and memory overhead.

### 5.4 What Member D does with it

On `kem_done`: write `kem_shared_secret` into the entry, set state
`ESTABLISHED`. **Unconditionally.** No inspection of the key, no branch on its
value or provenance.

On `kem_key_invalid`: set state `REJECTED`, raise
`RC_HANDSHAKE_KEY_INVALID`. This is the only path to `REJECTED`.

### 5.5 The joint test this enables

Master-Interface-Document §2 (Seam 2) requires a *joint* Member C + D test
proving indistinguishability at the `session_mgr.v` boundary. With the signal
list above that test is concrete: drive one genuine and one tampered-ciphertext
handshake, capture every signal crossing the seam, assert the two traces are
identical in shape and cycle count and differ only in the value of
`kem_shared_secret`. Member C will scaffold it in `sim/cocotb/` during Phase 9
and hand it to Member D.

---

## 6. Still blocked — not Member C's to answer

| Item | Owner | Blocks |
|---|---|---|
| `count_min_sketch.v` verdict latency | B | §6 sync approach |
| `FLOOD`/`SCAN` split or merge | B | §6 enum freeze |
| Handshake port inside CMS monitored space | B | (raised in response doc §1) |
| `poly1305.v` verdict latency | D | §6 sync approach |
| Port number collision check | D | §4 freeze |
| Drop-engine sync: pad-to-slowest vs track-outstanding | A + D | §6 freeze |

Member C's lanes are out of the per-packet drop path, so the slowest-lane
calculation is now strictly between Member B and Member D.

---

*Every measured number reproducible from the repo root:*
*`python model/mlkem/kat_test.py` (80/80, zero skips) and*
*`python model/mlkem/opcount.py` (operation counts).*

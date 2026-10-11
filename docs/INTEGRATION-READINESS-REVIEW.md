# Integration Readiness Review — pqc-nids-fpga

**Reviewer:** Member C, acting as team lead
**Date:** 11 Oct 2026
**Commit reviewed:** `40cd8ae` on `main`, plus `origin/member-a/parser-model` (unmerged)
**Scope:** every tracked file in the repository, every branch, every inter-module interface

---

## The verdict up front

Every module in this project works. Almost none of them are connected, and the one
connection the contract describes but never assigns an owner — the session lookup — is
the reason the data path cannot function at all.

The per-lane work is genuinely good. ML-KEM-512 is bit-exact against the full NIST
vector set through real RTL. ChaCha20 and Poly1305 are bit-exact against RFC 8439.
The drop engine's priority arbitration and its tag-telemetry exception are both correct.
The Count-Min Sketch infers BRAM properly and its four hash functions are measurably
independent. Twenty-five of thirty RTL files are Verilator `-Wall` clean. That is a
real engineering result and it should not be undersold.

But the project has no top level. `rtl/top/` contains a `.gitkeep`. `constraints/`
contains a `.gitkeep`. There is no XDC, no synthesis script, and no module anywhere
that instantiates more than one lane — the only two multi-module files in the tree are
simulation fixtures. `chacha_poly` is not instantiated anywhere at all. So the order of
the remaining work is not "synthesis, then bitstream, then demo." It is: build the
integration layer that does not exist, fix four defects that only appear once the lanes
are connected, then synthesise.

**Synthesis today would produce a bitstream that cannot complete a single handshake.**

---

## 1. The hard blocker: the data path is dead by construction

This is one causal chain, and every link in it is verified in simulation.

`parser.v` drives `session_id <= 16'd0` unconditionally. It is assigned at
`parser.v:134` (reset) and `:172` (per packet) and nowhere else — the parser performs no
lookup, because the lookup does not exist. Contract §3 defines the field as "matched
session ID from lookup; 0 = unassigned," so the parser is emitting the
"unassigned" sentinel for every packet, correctly, for want of anything to look up in.

`session_mgr.v:88` computes `kem_id_ok = (kem_session_id[15:2] == 14'd0) &&
(kem_session_id[1:0] != 2'd0)`, which rejects id 0 as out of range. Measured:

```
session_id=0 -> lk_state=0 lk_ok=0 key=NOT STORED
session_id=1 -> lk_state=2 lk_ok=1 key=STORED
session_id=4 -> lk_state=0 lk_ok=0 key=NOT STORED
```

So a handshake arriving with the session id the parser actually emits is silently
discarded by the session table. No session ever reaches ESTABLISHED. `chacha_poly`
therefore never receives a key; every data packet stays encrypted; and `cam_matcher`,
which per contract §3.1 reads only the decrypted plaintext stream, never sees a byte.
The entire detection path downstream of the cipher is unreachable.

Both modules are individually correct and individually contract-conformant. The defect
is that contract §3 describes a session lookup — mapping a packet's 5-tuple to a session
index — and §5 assigns Member D only the register file that *holds* sessions. Nobody
owns the function that *assigns* an id to an arriving packet. It appears in no task on
the board. This is the single most important thing to fix and it is unowned work, not a
bug in anyone's module.

---

## 2. What does not exist

Not "is incomplete" — does not exist as a file.

| Missing | Referenced by | Consequence |
|---|---|---|
| `rtl/top/*` — any top-level | nothing | no synthesis target |
| the session-lookup module | contract §3 | §1 above |
| a `session_mgr` → `chacha_poly` key sequencer | `session_mgr.v:19` claims `lk_*` go to `chacha_poly` | `chacha_poly` has no `lk_*` ports; nothing issues `lk_req` or strobes `key_valid` |
| a tag extractor | `chacha_poly.expected_tag[127:0]` | the Poly1305 tag arrives as the last 16 payload *bytes*; nothing strips them into a parallel word, and nothing excludes them from `ct_valid` |
| an AAD definition and extractor | `chacha_poly.aad_data[127:0]`, `aad_len[4:0]` | **AAD appears in no document in the repository.** `grep -ri aad docs/` returns nothing. Undefined interface, and the port caps AAD at 16 bytes |
| a nonce assembler | `chacha_poly.nonce[95:0]` | `session_mgr` holds 64 bits; the 96-bit value is `{32'd0, counter}` |
| something to drive `nonce_adv` | `session_mgr.v:72` | §4 below |
| `rtl/io/*` — LED/OLED/status | `demo/display/*.py`, synopsis §7 | the demo's visible output has no hardware |
| `constraints/*.xdc` | Vivado | no clock has ever been constrained; every timing claim in every file header is unverified |
| `scripts/build_bitstream.tcl` | `demo/run/demo_load_bitstream.tcl:11` | the documented one-command burn references a script that was never written |
| `test-network/send.py`, `recv.py`, `attacker.py` | `demo/verify/smoke_test.py` | the smoke test is an explicit stub and returns 1 |
| `scripts/measure_timing.py` | execution plan line 130 | §6.3 wall-clock numbers have no source |

**Member A's entire ingress lane is unmerged.** `rtl/ingress/` on `main` holds only
`.gitkeep`. `uart_rx.v`, `uart_tx.v`, `crc32.v`, `deframer.v` and `parser.v` live on
`origin/member-a/parser-model`, 14 commits ahead and 61 behind, with **no open PR**.
There is no packet bus source on `main` at all. Merging it is the precondition for
every integration item above, and it will not pass CI as it stands: 11 Verilator
warnings across 4 of the 5 files (`parser.v` 5, `uart_rx.v` 3, `uart_tx.v` 2,
`deframer.v` 1) against a CI lint job that treats warnings as errors. Everything
on `main` is clean; this lane is the exception.

---

## 3. Defects that will survive into the bitstream

Ordered by what breaks first on hardware. Each is reproduced in simulation unless
marked *estimated*.

### 3.1 Any data packet over 64 bytes hangs or silently corrupts the cipher

`chacha_poly` stops accepting bytes for 22 cycles every 64 bytes while `chacha20`
regenerates a keystream block, and signals this only on a `ready` output. Contract §3
defines the packet bus as `valid`/`sof`/`eof`/`data` with **no ready field**, and §3.1
promises "no added latency." Driving the core from a contract-conformant producer that
cannot be throttled, measured:

```
len=16:  done after 11 cycles, pt bytes = 16   OK
len=64:  done after 11 cycles, pt bytes = 64   OK
len=65:  *** NO done after 20000 cycles -- HUNG ***  pt bytes = 64
len=100: done after 12 cycles, pt bytes = 75   (25 plaintext bytes silently lost)
len=100 with ready honoured: done after 12 cycles, pt bytes = 100   OK
```

The core is correct; the bus specification is wrong. 64 bytes is far below any
realistic packet. Fix by adding backpressure to the contract's packet bus, or by
precomputing keystream blocks one ahead so the core never stalls. The second is
preferable because it does not require a contract amendment that propagates to every
consumer, and `chacha20` already has 22 idle cycles per block to work in.

### 3.2 `RC_HANDSHAKE_KEY_INVALID` can never be reported

`drop_engine.v:116-124` sets `expected_lanes = 5'b01011` for handshake packets — CRC,
PROTO, CMS. The KEM lane is not in the mask. The commit at `:306` fires as soon as
those three report, a few cycles after the header, and clears `in_packet` at `:336`.
The KEM verdict arrives 17,658 to 33,814 cycles later. Measured:

```
HS_INIT packet, lanes report, KEM verdict 30 cycles later:
  cnt_handshake_key_invalid = 0, cnt_total_passed = 1
CONTROL, same packet, KEM verdict delivered before commit:
  cnt_handshake_key_invalid = 1, drop_reason = 4'h8
```

A handshake with structurally invalid key material is counted as **passed** before the
KEM has begun computing. The arbitration logic is correct — only the window is wrong.
`demo/verify/smoke_test.py` lists `HANDSHAKE_KEY_INVALID` as one of its five expected
attack outcomes, so this is also a demo blocker. This sits on my own seam and I own
the fix: the handshake verdict is asynchronous to the packet and needs either a
deferred per-session verdict slot or removal from the packet-scoped engine entirely.

### 3.3 Every packet in a session reuses nonce 0

`session_mgr` increments correctly (`:112-114`) and saturates properly, but nothing
pulses `nonce_adv`. The only instantiation ties it to `1'b0`
(`sim/seam2_kem_session_top.v:104` — my fixture). Measured: `lk_nonce` reads 0 on the
first lookup and 0 again twenty cycles later. ChaCha20 keystream reuse across packets
destroys confidentiality completely. The module is right; the port has no driver and no
owner.

### 3.4 The Count-Min Sketch goes blind for 2048 contiguous cycles per epoch

Measured: `clearing` is high for exactly 2048 cycles. During it, `header_valid` is
gated off at `count_min_sketch.v:90`, so no verdict strobe is produced; and
`drop_engine.v:188` requires `rep_cms` before it will commit for *any* packet type. So
packets arriving in that window are not dropped and not forwarded — they are never
adjudicated. With `EPOCH_N = 32768` that is 2048/34816 = **5.9% of packets at line
rate**, as one contiguous 20.5 µs hole, which is long enough for a burst to cross
undetected. Measured with `EPOCH_N = 8` to force the boundary: 4,200 header
presentations produced 33 verdicts.

Verdicts emitted in the cycles *before* the clear also carry duplicated counts
(observed `c_flow` = 8, 9, 9, 9), because the clear branch at `:234` outranks the
update branch at `:252` and blocks the writeback while the verdict block at `:320`
knows nothing about `clearing`. Fix with two counter banks swapped at the epoch
boundary, so the clear never stalls the lane.

### 3.5 A late verdict is charged to the wrong packet

The verdict interface carries no packet identity: `in_packet` is one bit and the
`fail_*` flags are global. Given 3.1's measured per-packet cost, the crypto verdict
routinely arrives after the next packet's `sof`. Delegated review reproduced packet A's
`RC_BAD_TAG` landing inside packet B's window: B is dropped, A is never adjudicated,
`cnt_total_passed` stays 0. Contract §6's latency table budgets `poly1305.v` at "0-2
cycles after eof," which is the assumption that makes a single-bit `in_packet` safe.
Measured per-packet setup is 50 cycles plus roughly 1.37 cycles per byte.

Related, same root cause: `drop_engine` has no watchdog. `pkt_eof` is an input but is
explicitly sunk unused at `:165`. If any expected lane never strobes, that packet gets
no verdict, ever.

### 3.6 Two combinational paths will not close at 100 MHz — *estimated*

No Vivado run exists, so these are structural estimates, not measurements.

`poly1305.v:299` is a 131×64 unsigned multiply plus a 195-bit add in one cycle,
decomposing to roughly 24 DSP48E1 with no internal pipeline register, feeding a ~6-level
adder tree. Estimated well over 20 ns against a 10 ns budget. `poly1305.v:286` is the
same class one stage earlier. `poly1305.v:323-338` chains four dependent ~130-bit carry
chains plus a 131-bit compare and a mux in one cycle; estimated 12-14 ns, pure fabric
with no DSP escape. Both have cheap fixes — the standard five-limb 26-bit Poly1305
decomposition for the multiplies, and splitting `S_REDUCE` across two states for the
reduction. The extra cycles cost nothing at one byte per cycle of ingress.

`chacha20.v:85-88` (four dependent 32-bit adds through the round mux) is estimated at
8-9 ns: it fits, with under 2 ns of slack on a -1 part. It is the path that will fail
first if placement goes badly.

`hash_functions.v:58,65-73` holds nine combinational 32-bit constant multiplies in one
cycle. As DSP that is ~34 DSP48E1 against a ~8 budget; as LUT shift-add it is ~4,600
LUT6. Neither figure appears in any budget in the repo. One pipeline register between
`port_diffused` and the row multiplies fixes both the area and the timing risk.

### 3.7 Smaller, verified defects

- **`cam_matcher` one-byte cross-packet false match.** The `pt_sof` window clear is
  registered (`:226-228`), so during the SOF cycle the comparators see the new packet's
  first byte against the previous packet's tail. `RC_SIGNATURE` is attributed to the
  wrong packet. Multi-byte splits are correctly rejected; only this one position leaks.
- **`cam_matcher` drops a verdict strobe on back-to-back EOFs.** Assignment order at
  `:246` and `:257` lets the clear win, so a 1-byte packet immediately following
  another produces one verdict for two packets. Per §6 that packet then stalls
  `drop_engine` permanently.
- **`RC_SCAN` cannot detect what the contract defines.** `dst_ip` never reaches the
  hash — `count_min_sketch.v:39` sinks it, and `hash_functions.v:60` sets
  `host_key = src_ip`. So the host sketch counts packets per source, not distinct
  destinations per source. §6 defines `RC_SCAN` as a spread/fan-out anomaly. Vertical
  port scans are caught; horizontal IP sweeps are misclassified as `RC_FLOOD` above 512
  packets and missed below it. `FANOUT_MAX` measures no fan-out. `protocol` is also
  discarded, so a TCP and a UDP flow sharing `(src_ip, dst_port)` share a counter.
- **`drop_engine`'s `v_crc_*` and `v_deframe_*` do not match what Member A built.**
  `crc32.v` has no verdict interface at all (only `crc_out`, `crc_valid`).
  `deframer.v` has one verdict port carrying three codes — `RC_CRC_FAIL`,
  `RC_FRAME_TIMEOUT`, `RC_MALFORMED`. `drop_engine` expects two ports and derives the
  reason from *which port fired*, sinking `v_deframe_reason` unused at `:165`. Wiring
  the deframer to `v_deframe_*` mislabels every CRC failure as `RC_FRAME_TIMEOUT`.
- **`protocol_validator` Rule 6 depends on an unstated reading of `l4_length`.**
  `:113` computes `expected_total = 20 + l4_length + payload_len`. Contract §3 defines
  the field as "TCP data offset or UDP header length." Under the literal reading of
  "UDP header length" — the on-wire UDP Length field, which includes the payload —
  `payload_len` is counted twice and **every UDP packet with a payload is rejected as
  `RC_MALFORMED`** (measured). It works only if the field means the L4 header length in
  bytes. Resolve in the contract before the parser merges.
- **`chacha20.v:110-114` uses array element references in an explicit event list.**
  IEEE 1364-2001 does not clearly permit this. Verilator and Icarus accept it; Vivado's
  behaviour is version-dependent. Rewriting as `always @*` was verified bit-identical.
  Free insurance in the design's only combinational block.
- **`cam_matcher` has no signature memory.** The 16 signatures are hardcoded comparator
  trees, so the signature set cannot change without re-synthesis. All 132 constant
  bytes were verified correct against their comments. Worth stating plainly in the
  report rather than calling it a CAM.
- **`cam_matcher` verdict latency is 2 cycles after `pt_eof`, not 1** as `:251` and
  contract §6 both claim. **CMS verdict latency is 4 cycles after `header_valid`**, not
  "2-4 cycles after `eof`" — `eof` is unused, so the contract's reference point does
  not describe the module.

---

## 4. What is verified and trustworthy

Stated plainly, because it is most of the engineering and it is sound.

**ML-KEM-512 (Member C).** Bit-exact against the complete NIST ML-KEM-512 vector set
through the real `mlkem_top.v`: KeyGen 25/25, Encaps 25/25, encapsulation-key check
10/10, Decaps 10/10 including the modified-ciphertext implicit-rejection cases. Cycle
counts measured at KeyGen 17,640-17,669, Encaps 24,022-24,049, Decaps 33,786-33,814.
Decaps is constant-time with respect to the ciphertext: the full per-cycle waveform at
the `session_mgr` boundary is identical for authentic and rejected handshakes, and
`scripts/mutation_check_seam2.py` proves that test fails if a one-cycle delay or a
verdict strobe is planted on the rejected path. The dk hash check (NIST group 7) is
model-only by design — the device generates its key on-chip and never imports one.

**ChaCha20 (Member D).** Exact match to RFC 8439 §2.3.2, all sixteen output words.
Quarter-round, round schedule, constants, 32-bit counter, counter starting at 1 for the
payload and 0 for the one-time key, little-endian serialisation — all correct.

**Poly1305 (Member D).** Exact match to RFC 8439 §2.5.2. The `r` clamp mask is
byte-for-byte correct. The mod-2^130-5 reduction is provably complete with a single
conditional subtract, including the band between 2^130-5 and 2^130 that is the usual
place to get this wrong. Tag comparison is one registered 128-bit equality —
constant-time, no early exit. It is slow, not wrong.

**AEAD framing (Member D).** 39/39 correct tags and plaintexts across payload lengths
1-129 crossed with AAD lengths 0/12/16, covering both padding arms, the 64-byte
keystream boundary, and a tampered-ciphertext case producing the correct
`RC_BAD_TAG`. The MAC input sequence is exactly right.

**Drop engine arbitration (Member D).** The §6 priority mux is correct, including
`RC_BAD_TAG` outranking `RC_SIGNATURE`, verified in both same-cycle and cross-cycle
arrival orders. The §6 telemetry exception — not counting a CAM hit on a tag-failed
packet as a confirmed signature — is implemented correctly. Per-packet reset on
`pkt_sof` works. Its problems are entirely about when the window opens and closes.

**Count-Min Sketch memories (Member B).** Eight arrays, correctly written for BRAM
inference: 4 × RAMB36E1 (2048 × 16) and 4 × RAMB18E1 (1024 × 16), about 6 BRAM36
equivalents, 4.3% of 140. Single write port each, registered reads, `ram_style = "block"`
applied, and the `initial` zeroing loop correctly fenced behind `COCOTB_SIM`. The
forwarding network covers the read-after-write hazard and the epoch reset is clean.

**Hash independence (Member B).** The four multiply-shift functions are genuinely
distinct — four different odd multipliers, not shifts of one product — and correctly
extract the high bits. Measured over 4.5 M key pairs, the collision distribution matches
independence (0 rows: 4,489,587 observed vs 4,489,720 expected). The caveat is not
correlation but that the constants are fixed `localparam`s with no reseed path, so the
(ε, δ) bound is an empirical property on non-adversarial traffic, not a guarantee
against anyone who reads the source.

**Protocol validator (Member B).** All six documented rules implemented and behaving as
stated across 28 directed vectors, correctly gating the TCP flag checks on `is_tcp`,
emitting `RC_MALFORMED`, at the claimed 1-cycle latency. Rule 6's `l4_length` ambiguity
above is the only problem.

**Lint and suite.** All 25 RTL files on `main` are Verilator `-Wall` clean, and the
full cocotb suite on `main` is 30 passed, 0 failed, 0 skipped in 24m 32s.

---

## 5. Repository claims that are not true

Worth fixing because the report will quote them.

- `chacha20.v:25` and `poly1305.v:32` claim no DSPs. `poly1305.v:286` and `:299` are
  variable × variable multiplies; Vivado will infer DSP48E1 by default and nothing sets
  `use_dsp`.
- Every resource and timing figure in every RTL header is pre-synthesis. No XDC exists,
  so none has been checked against a constrained run.
- `session_mgr.v:19` says `lk_*` goes to `chacha_poly.v`. `chacha_poly` has no `lk_*`
  ports.
- `session_mgr.v:48` says nonce reuse is never allowed. Nothing drives `nonce_adv`.
- Contract §3.1's "no added latency beyond what `chacha_poly` already imposes" and §6's
  "0-2 cycles after eof" for `poly1305.v` are both contradicted by a measured 50-cycle
  setup plus ~1.37 cycles/byte.
- `docs/PROJECT-TASK-BOARD.md:205` marks `D8` (`session_mgr.v`) complete and `C17`'s
  old blocker line listed `D8` as pending. `D8` did land; the board line is stale.
- The board's §6.3 table still carries the `opcount.py` lower bounds (4,800 / 6,000 /
  8,900). The measured figures are ~3.7-4.0× higher. The lower bounds are labelled, but
  they must not reach the report as results.
- `AGENTS.md` and the execution plan describe `fo_transform.v` as a module. The
  behaviour is implemented and verified inside `mlkem_top.v`; there is no such file.

Two findings from delegated review that I checked and **rejected**: `model/detect.py`
does exist (44 KB on `main`), `docs/Member B/` does exist, and
`sim/cocotb/test_lane2_drop_engine.py` does exist with five tests. Those reviews ran
against a partial file set I staged for them, not against `main`.

---

## 6. Why the test suite did not catch any of this

Every defect in §1 and §3 is a cross-module defect, and the project's verification
strategy cannot see them. The pattern is the same each time: a module is tested against
a hand-written reference model, and the model encodes the same assumption the module
does, so the two agree and the test passes.

The clearest instance is `test_drop_engine.py`. It does exercise the KEM lane. Its
reference model iterates `for c in range(0, 64)` and asserts "model: packet never
committed" outside that window, so every KEM verdict it schedules lands within 64 cycles
of `sof`. The real `mlkem_top` reports at 17,658 to 33,814 cycles. The RTL and its model
share the wrong assumption, and the test is structurally incapable of failing on it.
`chacha_poly`'s tests drive it through its own `ready` handshake, so they never
encounter §3.1. CMS's tests do not run across an epoch boundary at line rate.

This is exactly the failure mode `C17` was created to prevent, and at the Seam-2 key
boundary it worked: wiring the real `mlkem_top` to the real `session_mgr` and comparing
waveforms caught a class of bug no module-level test could. Nobody did the same for the
verdict path, the key-delivery path, or the packet bus. **The lesson is specific: a
seam needs a test that instantiates both real modules and no model of either.**

---

## 7. Ordered plan to a working bitstream

Nothing below is synthesis. Synthesis is step 9.

1. **Resolve the three unowned interface questions, in writing, in the contract.** What
   assigns `session_id` to an arriving packet, and who builds it. What the AAD is, and
   whether 16 bytes is enough. What `l4_length` means. These block everything and none
   is a coding task.
2. **Open Member A's PR and clear its 11 lint warnings.** Width casts in `uart_rx`/
   `uart_tx`/`parser`, the unused `crc_ready` in `deframer`, and either use or remove
   `PORT_DATA`. Without this `main` has no packet bus at all.
3. **Reconcile the verdict interface with what exists.** Decide whether `crc32` gains a
   verdict port or `deframer`'s single verdict feeds a reworked `drop_engine` input that
   honours `v_deframe_reason` instead of inferring the code from which port fired.
4. **Add backpressure, or remove the need for it.** My recommendation is to precompute
   one keystream block ahead in `chacha20` so `chacha_poly` never stalls, which avoids a
   contract amendment touching every consumer. Either way, fix §3.1 before anything
   streams a real packet.
5. **Take the handshake verdict out of the packet-scoped drop engine**, and give the
   verdict interface a packet id so a late `RC_BAD_TAG` cannot be charged to the next
   packet. These are one design change, and it is mine and Member D's jointly.
6. **Write the integration layer:** session lookup, the `session_mgr` → `chacha_poly`
   key sequencer, the nonce assembler and the `nonce_adv` pulse, the tag extractor, the
   AAD extractor, and `rtl/io/` for the status display.
7. **Write `rtl/top/pqc_nids_top.v`** and a seam test per boundary — both real modules,
   no models — following the C17 pattern.
8. **Double-buffer the CMS epoch counters**, pipeline `hash_functions`, pipeline the two
   `poly1305` paths, and fix the two `cam_matcher` boundary defects.
9. **Write `constraints/pqc_nids.xdc` and `scripts/build_bitstream.tcl`, then
   synthesise.** Only now do the resource and timing numbers become real, and only now
   can §6.3 be filled in with measurements instead of estimates.
10. **Build `test-network/` and finish `smoke_test.py`.** Note that its
    `HANDSHAKE_KEY_INVALID` case cannot pass until item 5 is done.

Items 1-3 are unblocking work that costs conversations, not code. Item 6 is the largest
piece of unwritten RTL left in the project, and it is currently assigned to nobody.

---

## 8. Verification provenance

So that every claim above can be traced or challenged.

**Run by me on commit `40cd8ae`:** the full file and module inventory; the
module/instantiation graph across all 34 modules; `verilator --lint-only -Wall` on all
30 RTL files including Member A's unmerged lane; the `session_mgr` session-id and nonce
tests; the `drop_engine` late-KEM-verdict test and its control; the `chacha_poly`
no-backpressure sweep at 16/64/65/100 bytes plus the `ready`-honoured control; the CMS
epoch-clear measurement; and the full `pytest sim/cocotb` suite — **30 passed in 24m 32s,
zero failures, zero skips**. That green suite is itself the evidence for §6: every
defect above is a cross-module defect, and a suite of per-module tests passes cleanly
in their presence.

**Delegated to two independent reviewers**, briefed with the code and the contract but
not with my hypotheses, and spot-checked by me: the RFC 8439 conformance of ChaCha20,
Poly1305 and the AEAD framing; the BRAM inference arithmetic; the hash-independence
measurement; the protocol-validator rule sweep; and the `cam_matcher` signature-byte
audit and boundary tests. Two of their findings were wrong and are corrected in §5.

**Estimated, not measured — no Vivado run exists:** every timing figure in §3.6, the
DSP and LUT counts for `hash_functions`, and all resource numbers in all RTL headers.
These need item 9 before they can be stated as results.

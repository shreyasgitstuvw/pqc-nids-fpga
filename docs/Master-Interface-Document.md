# Master Interface Document
## How All Four Tracks Connect Into One Pipeline

Each member's guide describes their own module in isolation. This document describes the seams — the exact points where one person's output becomes another person's input — since these seams are where integration bugs live if they aren't nailed down early.

---

## 1. The whole pipeline, in one picture

```
                                    ┌─────────────────────────────┐
                                    │        MEMBER A             │
  UART wire ──▶ uart_rx ──▶ deframer ──▶ crc32 ──▶ parser ──▶ [ PACKET BUS ]
                                    └─────────────────────────────┘
                                                   │
                              copied to BOTH lanes in the SAME clock cycle
                                                   │
                    ┌──────────────────────────────┴──────────────────────────────┐
                    ▼                                                              ▼
        ┌───────────────────────┐                                    ┌───────────────────────┐
        │      MEMBER C          │                                    │      MEMBER D          │
        │  (handshake packets    │                                    │  (data packets,        │
        │   only — session       │  session key handoff               │   once session         │
        │   establishment)       │ ───────────────────────────────▶  │   ESTABLISHED)          │
        │  ML-KEM-512 engine     │      (32-byte shared secret,        │  ChaCha20-Poly1305      │
        │  keygen/encaps/decaps  │       written to session register)  │  session_mgr            │
        │  FO transform          │                                    │  {fail, reason_code}    │
        │  {fail=n/a on success, │                                    └───────────┬─────────────┘
        │   reason=REJECT on     │                                                │
        │   implicit rejection}  │                                                │
        └───────────┬────────────┘                                               │
                    │                                                             │
                    │            ┌───────────────────────┐                        │
                    │            │      MEMBER B          │                        │
                    │            │  cam_matcher            │                        │
                    │            │  count_min_sketch       │                        │
                    │            │  protocol_validator      │                        │
                    │            │  {fail, reason_code}    │                        │
                    │            └───────────┬─────────────┘                        │
                    │                        │                                       │
                    └────────────┬───────────┴───────────────────────────────────────┘
                                 ▼
                    ┌─────────────────────────────┐
                    │   MEMBER D — drop_engine.v    │
                    │   merges all verdicts,        │
                    │   increments reason counters, │
                    │   forwards clean packets      │
                    └───────────┬────────────────────┘
                                 ▼
                        clean packet out (or dropped, counted, logged)
```

**The single most important structural fact:** the packet bus coming out of Member A's parser is read by Member B's detection lane and (for the relevant packet types) Member C/D's crypto lane *in the same clock cycle* — the lanes never wait on each other. This is what the synopsis means by the design being "sub-additive": the expensive parts (lattice math and signature/volume checks) run concurrently on the same packet, not one after another.

---

## 2. The three seams, in detail

### Seam 1 — Member A → Members B, C, D: the packet bus

**What crosses this seam:** the struct defined in `docs/interface_contract.md` — `{ valid, sof, eof, data[7:0], eth_hdr, ip_hdr, tcp_udp_hdr, payload_len, session_id }`.

**Who reads it:** every other module in the design. This is why it's frozen first and why it's the one artifact all four people must agree on before writing RTL.

**What can go wrong here:** a field width or byte-order mismatch between what Member A's parser emits and what Members B/C/D assume they're reading. Because this is a shared bus rather than a point-to-point link, a bug here doesn't fail loudly in one place — it silently corrupts input to *every* downstream module simultaneously, and each team might independently (and wrongly) suspect their own logic first. **Mitigation:** Member A's cocotb testbench output (the 20+ hand-crafted packets) should be checked into the repo and used as a shared reference by every other member when building their own testbenches, so everyone is developing against the same known-good bus values from day one.

### Seam 2 — Member C → Member D: the session key handoff

**What crosses this seam:** a 32-byte shared secret, plus a session state signal (IDLE/HANDSHAKING/ESTABLISHED/REJECTED), written into the shared session register file that both `mlkem_top.v` (Member C) and `chacha_poly` + `session_mgr.v` (Member D) touch.

**Direction:** one-way for the key itself (Member C's KEM produces it, Member D's ChaCha engine consumes it), but the *state machine* around it is really co-owned — Member D's `session_mgr.v` needs to react correctly the instant Member C's engine finishes a handshake, whether that handshake succeeded or failed via implicit rejection.

**The property that must hold across this seam, jointly:** if a handshake fails, the resulting session state and the (decoy) key handed to Member D's cipher must be **indistinguishable from a successful handshake**, from any externally observable signal — timing, signal shape, cycle count. This is the one place in the whole project where correctness isn't "does each module work in isolation" but "do these two modules, working correctly on their own terms, jointly avoid leaking information through their combined external behavior." **This needs a joint test, not two separate ones** — Member C and Member D should write a shared cocotb testbench (or at minimum, run each other's testbenches against their own module) that specifically drives both a successful and a rejected handshake and confirms the observable behavior at the `session_mgr.v` boundary is the same shape in both cases.

**What can go wrong here:** each side independently verifies their own half correctly (KEM computes the right decoy value; ChaCha correctly uses whatever key it's given) while the *timing* of when that value becomes available, or a stray status flag, differs between the success and failure paths — a leak that neither module's isolated testbench would ever catch, because each one only tested its own logical correctness, not the pair's combined observable footprint.

### Seam 3 — Members B and D → Member D's drop_engine: verdict merging

**What crosses this seam:** `{fail, reason_code}` from Member B's detection lane (evaluating every packet), and `{fail, reason_code}` from the cryptographic checks (Poly1305 tag verification, which lives conceptually with Member D's ChaCha module, and CRC failure, which is Member A's ingress layer feeding in earlier).

**Timing requirement:** both lanes must assert their verdict a *known, fixed* number of cycles after a packet's `eof`, so the drop engine knows exactly when it's safe to make a final forward/drop decision. If Member B's CAM lookup (1 cycle) and Member C/D's Poly1305 check (however many cycles that takes) complete at different latencies, the drop engine's design must account for the *slower* of the two paths — this needs to be pinned down as a specific number in the interface contract, not left as "whenever each lane happens to finish."

**What can go wrong here:** if both lanes can fail on the *same* packet in the *same* cycle, there needs to be an agreed, documented priority rule for which reason code gets logged (or whether both get logged as separate counter increments) — otherwise different team members' modules might implicitly assume different priority orderings, and the final reason-code statistics in your report become internally inconsistent depending on which path happened to be checked last.

---

## 3. End-to-end walkthrough: a session from cold start to a dropped attack packet

This is the sequence to have in your head when reasoning about integration, and it's a good basis for your Phase VI integration test:

1. **Device A sends its ML-KEM encapsulation key.** Member A's ingress pipeline receives it, parses it as a handshake-type packet, places it on the packet bus.
2. **Member C's engine recognizes this as a handshake packet** (not regular data — this distinction needs to be encoded somewhere in the packet bus or a dedicated packet-type field, decided in the interface contract) and begins encapsulation/decapsulation processing. Member B's detection lane also sees this packet on the same bus but has nothing meaningful to flag on a legitimate handshake packet (it still runs its checks — protocol validation still applies — but shouldn't false-positive on normal handshake traffic; worth an explicit test case).
3. **Handshake completes.** Member C writes the shared secret and `ESTABLISHED` state into the session register. Member D's `session_mgr.v` observes this transition and now permits `chacha_poly` to use that key for subsequent data packets on this session.
4. **Device A sends encrypted data packets.** Each one flows through Member A's ingress → packet bus → **both lanes simultaneously**: Member D's ChaCha20-Poly1305 checks the authentication tag (was this altered in transit?), while Member B's CAM/CMS/validator independently checks for known signatures and volumetric anomalies, entirely unaware of and unaffected by whether the crypto check passes or fails.
5. **An attacker (third device) injects a tampered or malicious packet.** Depending on what's wrong with it: a bad Poly1305 tag fails Member D's check; a known malicious payload fails Member B's CAM check; an unusually high volume from that source trips Member B's CMS; a malformed header fails Member B's protocol validator. Any one of these (or several at once) asserts `{fail, reason_code}`.
6. **Member D's drop_engine merges the verdicts**, increments the appropriate reason-code counter(s), and discards the packet before it reaches the host — all within the sub-microsecond budget the synopsis specifies, since this decision happens in the datapath, not at the physical layer.
7. **The counted, categorized drop is visible** on the LED/OLED status display and the live command-line readout on both legitimate devices and the attacker's own view of what got through — nothing is silently lost.

---

## 4. Integration checklist — Phase VI, before anyone declares their piece "done"

- [ ] Member A's packet bus test vectors are checked into the repo and referenced by B, C, and D's own testbenches
- [ ] Member C and Member D have run a **joint** test confirming implicit-rejection indistinguishability at the `session_mgr.v` boundary, not just independent module-level tests
- [ ] The exact cycle latency of each lane's verdict signal (relative to a packet's `eof`) is documented in the interface contract and matches what's actually implemented, not just what was originally planned
- [ ] A same-cycle dual-failure test case exists (a packet that both Member B's lane and Member D's Poly1305 check reject simultaneously) with a documented, agreed priority rule for reason-code logging
- [ ] A full end-to-end simulation exists exercising the 7-step walkthrough above — handshake, established session, normal traffic, and at least one attack of each category (bad tag, known signature, volumetric flood, malformed header) — with all reason codes correctly attributed
- [ ] Every module's cocotb testbench and its corresponding `model/` Python reference agree bit-exact — this should already be true per-module by this point, but re-confirm after any interface-contract changes made during integration

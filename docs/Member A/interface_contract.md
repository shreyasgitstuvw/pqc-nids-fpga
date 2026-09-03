# Interface Contract
## pqc-nids-fpga — Frozen Cross-Module Interfaces

**Status:** DRAFT — pending Member A review and sign-off from all four members before freeze.
**Owner:** Member A (final authority on every section below). Sections needing your specific decision are marked **[MEMBER A: CONFIRM]**. Everything else is a concrete proposal you can accept, tweak, or override — this is a strong starting point, not a finished spec; treat every number here as challengeable.

Once frozen, changes to this file require notifying every member whose module reads the changed section (see the "Consumers" line under each section). Do not silently edit after freeze — post the diff.

---

## 1. Physical link and framing

| Parameter | Value | Notes |
|---|---|---|
| Physical link | Pmod USB-UART (FTDI FT232RQ) | **Not** the ZedBoard's onboard USB-UART — that's wired to the processor's dedicated pins and unreachable from programmable logic (synopsis §7.1 note) |
| Baud rate | 3,000,000 (3 Mbaud) | |
| Data bits / parity / stop bits | 8 / none / 1 | Standard UART framing, **[MEMBER A: CONFIRM]** if you're using a different convention |
| Byte order (all multi-byte fields, everywhere in this document) | **Big-endian ("network byte order")** | Non-negotiable for the Ethernet/IP/TCP/UDP headers, since that's the wire convention those protocols already use. Applies equally to internal fields you're defining fresh (session_id, lengths, etc.) — pick one convention and use it everywhere, don't mix. |

### Framing scheme
**Proposed: length-prefixed framing.** Each frame on the wire:

```
[ 2 bytes: total_length (big-endian, includes this header) ] [ payload bytes... ]
```

**[MEMBER A: CONFIRM]** — decide and lock:
- Is 2 bytes enough for `total_length`, or do handshake packets (800-byte encapsulation key, 768-byte ciphertext, per synopsis §6.1) push you toward a 3-byte or wider field? A 2-byte field caps you at 65,535 bytes, which covers the synopsis's stated packet sizes comfortably — flag this only if you're planning larger frames than the crypto lane currently needs.
- What happens on a truncated frame (fewer bytes arrive than `total_length` claims)? Proposed: deframer holds partial state, does not assert `eof`, and a timeout (define a cycle count) forces a drop with reason `FRAME_TIMEOUT`.
- Do you need a delimiter-based fallback for framing recovery after a corrupted length field, or is length-prefix-only acceptable given CRC will catch most corruption? Proposed: length-prefix only, rely on CRC (§2) to catch corruption; a garbage length field just means a garbage-sized "frame" gets CRC-rejected downstream.

---

## 2. Link-layer integrity — CRC

| Field | Value |
|---|---|
| Algorithm | CRC-32 (standard polynomial, matches `zlib.crc32` / `binascii.crc32` for cross-checking against `model/pipeline.py`) |
| Position | Appended after the frame payload, 4 bytes, big-endian |
| Failure behavior | Frame dropped before reaching the parser; reason code `CRC_FAIL` incremented (§6) |

**Consumers:** Member A (implements), Member D (drop_engine counts `CRC_FAIL`).

**Note for the whole team:** CRC failure and Poly1305 tag failure (Member D's lane) are different failure classes — one is accidental corruption, the other is deliberate tampering after decryption is already in play. Keep their reason codes distinct; see §6.

---

## 3. Internal packet bus — the shared struct

This is the single most important definition in this document. Every module downstream of the parser reads this struct in the same clock cycle. **[MEMBER A: CONFIRM]** every bit width below — these are proposed based on the standard protocol field sizes; adjust only if you have a specific reason to deviate (e.g., truncating MAC addresses you don't need to route on).

```
packet_bus_t {
    valid            : 1 bit    // asserted for every cycle carrying live packet data
    sof              : 1 bit    // start-of-frame, asserted on the first valid cycle of a packet
    eof              : 1 bit    // end-of-frame, asserted on the last valid cycle of a packet
    data             : 8 bits   // byte-wide payload stream, valid alongside `valid`

    // --- Ethernet header (populated once parsed, held stable for the packet's duration) ---
    eth_dst_mac      : 48 bits  // destination MAC
    eth_src_mac      : 48 bits  // source MAC
    eth_type         : 16 bits  // 0x0800 = IPv4, others per standard EtherTypes

    // --- IPv4 header ---
    ip_version_ihl   : 8 bits   // version (4 bits) + IHL (4 bits) — split out downstream if needed
    ip_total_length  : 16 bits
    ip_protocol      : 8 bits   // 6 = TCP, 17 = UDP
    ip_src_addr      : 32 bits
    ip_dst_addr      : 32 bits

    // --- TCP/UDP header (interpretation depends on ip_protocol) ---
    l4_src_port      : 16 bits
    l4_dst_port      : 16 bits
    tcp_flags        : 8 bits   // only meaningful when ip_protocol == TCP; zero/ignore otherwise
    l4_length        : 16 bits  // TCP data offset+reserved, or UDP length, per protocol

    // --- Project-specific fields (not part of any standard header — you're defining these fresh) ---
    payload_len      : 16 bits  // length of the data payload after all headers are stripped
    session_id       : 16 bits  // see §5; 0 = no session / unassigned
    packet_type      : 2 bits   // see §4 below — THIS FIELD IS THE KEY OPEN DECISION
}
```

**Open questions for you to resolve and lock:**
- IPv4 options (header length > 20 bytes / IHL > 5): supported, or rejected as malformed? Proposed: reject as malformed (`MALFORMED` reason code) — simplest, and matches a synthetic test network where you control both endpoints and don't need options support.
- Non-IPv4 EtherTypes (ARP, IPv6, etc.): flagged as malformed, or silently passed through unparsed with only `eth_*` fields populated? Proposed: flag as `MALFORMED` for now, matching the "reject anything outside the exact scope we're testing" posture — revisit only if the test network needs ARP for address resolution.
- Do detection-lane and crypto-lane modules need raw payload bytes (beyond the parsed headers) delivered on this same bus, or via a separate parallel byte-stream signal? Proposed: `data`/`valid`/`sof`/`eof` continue streaming payload bytes after the header fields are latched, so both lanes can consume header context and payload bytes from the same bus without a second interface — confirm this matches how Member B (CAM matching against payload) and Member C (handshake payload extraction) expect to consume it.

**Consumers:** Member B (detection), Member C (crypto — handshake packets), Member D (crypto — data packets), Member D's `drop_engine.v` (uses `session_id` for verdict merging).

---

## 4. Packet classification — `packet_type`

This field doesn't exist in any standard protocol — it's how the pipeline tells Member C's crypto-handshake logic apart from Member D's per-packet data logic, and it needs to be decided, not inherited from a spec.

| `packet_type` value | Meaning | Consumed primarily by |
|---|---|---|
| `2'b00` | Handshake / key-exchange packet | Member C (`mlkem_top.v`) |
| `2'b01` | Established-session encrypted data packet | Member D (`chacha_poly`) |
| `2'b10` | Reserved | — |
| `2'b11` | Reserved | — |

**[MEMBER A: CONFIRM]** how this field gets set. Two realistic options:
1. **Port-based:** a fixed, agreed port number on `l4_dst_port` designates handshake traffic (simplest, matches how real protocols often reserve a port for control traffic).
2. **Explicit type byte:** the application-layer payload itself starts with a 1-byte tag your parser reads and promotes into this field.

Whichever you choose, write the exact value/port number here once decided, and confirm it with Member C (who triggers on `packet_type == handshake`) and Member D (who triggers on `packet_type == established-data`) before freezing.

---

## 5. Session register file

Owned structurally by Member D's `session_mgr.v`, but **written by Member C** (session key, on successful/rejected handshake) and **read by Member D's `chacha_poly`**. Member A's parser populates `session_id` on the packet bus (§3) that indexes into this table.

```
session_entry_t {
    session_id       : 16 bits   // matches packet_bus_t.session_id
    shared_secret     : 256 bits  // 32-byte key from ML-KEM decapsulation
    nonce_counter     : 64 bits   // ChaCha20 nonce, incremented per packet — [MEMBER D: CONFIRM width is sufficient for expected session packet volume]
    state             : 2 bits    // 00=IDLE, 01=HANDSHAKING, 10=ESTABLISHED, 11=REJECTED
}
```

**Critical cross-cutting requirement (applies to Member C and Member D jointly, not Member A):** the `state` transition into `ESTABLISHED` via a genuine handshake and the transition via implicit rejection must be **externally indistinguishable** — same latency, same signal shape, from any observer outside `session_mgr.v`. This doesn't change what Member A builds, but Member A's parser/egress timing (how quickly a response goes back out over UART) shouldn't inadvertently leak which case occurred either — worth a quick sanity check once integration testing starts.

**[MEMBER A: CONFIRM]** — how many concurrent sessions does the test network actually need? The synopsis's test network (§6.4) is two communicating devices plus one attacker — a single-session table (or a very small fixed table, e.g. 4 entries) is probably sufficient. Don't over-build a large session table if the test scope doesn't need it; document whatever number you land on here.

---

## 6. Lane → drop-engine verdict interface

Every module that can reject a packet (CRC, protocol validator, CAM matcher, Count-Min Sketch, Poly1305 tag check, FO-transform/implicit-rejection) outputs this same shape to Member D's `drop_engine.v`:

```
verdict_t {
    fail             : 1 bit
    reason_code      : 4 bits   // see enum below
}
```

### Reason code enum (`rtl/control/reason_codes.vh`)

| Code | Value | Source module | Meaning |
|---|---|---|---|
| `NONE` | `4'h0` | — | No failure; packet passes |
| `CRC_FAIL` | `4'h1` | Member A — `crc32.v` | Link-layer corruption (accidental) |
| `FRAME_TIMEOUT` | `4'h2` | Member A — `deframer.v` | Truncated/incomplete frame |
| `MALFORMED` | `4'h3` | Member B — `protocol_validator.v` | Structurally invalid header (bad flags, length mismatch, etc.) |
| `SIGNATURE` | `4'h4` | Member B — `cam_matcher.v` | Matched known attack signature |
| `FLOOD` | `4'h5` | Member B — `count_min_sketch.v` | Volumetric anomaly (high-rate) |
| `SCAN` | `4'h6` | Member B — `count_min_sketch.v` | Volumetric anomaly (distinct-target spread) |
| `BAD_TAG` | `4'h7` | Member D — `poly1305.v` | Per-packet authentication failure (deliberate tampering) |
| `HANDSHAKE_REJECT` | `4'h8` | Member C — `fo_transform.v` | Implicit rejection on handshake (tampered/invalid ciphertext) |
| `4'h9`–`4'hF` | reserved | — | Available for future use — request via Member A, don't self-assign |

**[MEMBER A: CONFIRM]** the exact numeric assignment above is a proposal — freeze it once all three consuming members (B, C, D) confirm they don't need additional distinctions within a category (e.g., does Member B need `FLOOD` and `SCAN` split, or is one `VOLUMETRIC` code enough? Their theory guide treats these as related but distinguishable — check with them directly).

### Verdict timing

**[MEMBER A: CONFIRM — this is the highest-priority open item in this whole document.]** Every lane must assert its verdict a fixed, known number of cycles after a packet's `eof`, so `drop_engine.v` knows exactly when it's safe to make a final call. Latencies differ wildly by module (CAM: 1 cycle; Poly1305: depends on payload length already streamed; NTT/FO-transform: only relevant at handshake time, not per-packet). Decide and document:

| Module | Expected verdict latency (cycles after `eof`) | Status |
|---|---|---|
| `crc32.v` | 0 (computed inline during streaming, ready at `eof`) | proposed |
| `protocol_validator.v` | 0–1 (combinational or 1-cycle registered) | proposed — confirm with Member B |
| `cam_matcher.v` | 1 | confirmed per synopsis design (1-cycle CAM lookup) |
| `count_min_sketch.v` | ? | **needs Member B's input** |
| `poly1305.v` | ? | **needs Member D's input** — likely 0 since the tag is verified as the last bytes stream in |
| `fo_transform.v` | ? (handshake-only, not per-data-packet) | **needs Member C's input**, and doesn't block the per-packet drop-engine path the way the others do — confirm this is understood by Member D as a session-establishment-time check only |

`drop_engine.v` must wait for the **slowest** confirmed lane before finalizing a verdict. If lanes complete at different cycle counts, either pad the faster ones to match (simpler drop-engine logic) or have drop_engine track outstanding lanes per packet explicitly (more flexible, more complex) — **[MEMBER A: CONFIRM]** which approach, in consultation with Member D since they implement `drop_engine.v`.

**Simultaneous-failure priority rule** — if two lanes fail the same packet in the same cycle, which reason code gets logged? Proposed: log **both** as separate counter increments (simplest, most complete telemetry) rather than picking one — confirm this doesn't complicate `drop_engine.v`'s implementation more than it's worth; if it does, propose a priority order instead and document it here.

**Consumers:** Member B, Member C, Member D all implement modules that populate this interface; Member D's `drop_engine.v` consumes it.

---

## 7. Open items checklist — what Member A needs to finalize before freeze

- [ ] Confirm framing scheme details (§1): length field width, truncation/timeout behavior
- [ ] Confirm every packet bus field width (§3), especially whether IPv4 options and non-IPv4 EtherTypes are supported or rejected
- [ ] Decide and document the `packet_type` classification mechanism (§4) — port-based or explicit tag — in consultation with Member C and Member D
- [ ] Confirm session table size (§5) matches actual test-network scope
- [ ] Finalize reason code numeric assignments (§6) after checking with Member B on flood/scan granularity
- [ ] **Collect verdict latency numbers from Members B, C, D (§6 table) and decide the drop-engine synchronization approach with Member D — this is the single item most likely to cause Phase VI integration pain if left vague**
- [ ] Circulate the finalized version to all three other members for explicit sign-off before treating this as frozen; note the freeze date and version at the top of this file once done

---

*Once finalized, replace the DRAFT status at the top of this file with a frozen version number and date, and this checklist section can be removed or moved to a changelog.*

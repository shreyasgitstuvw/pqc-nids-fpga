# Interface Contract
## pqc-nids-fpga — Frozen Cross-Module Interfaces

**Status:** FROZEN — v1.0.0 (12 Sep 2026)
**Owner:** Member A (contract authority). All sections confirmed and locked.
**Change Policy:** Any proposed changes to this file must be posted as a diff and approved by Member A. Changes require explicit notification of all affected members whose modules read the changed section (see "Consumers" lines).

---

## 1. Physical link and framing

| Parameter | Value | Notes |
|---|---|---|
| Physical link | Pmod USB-UART (FTDI FT232RQ) | **Not** the ZedBoard's onboard USB-UART — that's wired to the processor's dedicated pins and unreachable from programmable logic (synopsis §7.1 note) |
| Baud rate | 3,000,000 (3 Mbaud) | Confirmed. At 100 MHz sysclk, bit period is 33.33 cycles (16× oversampling clock = 48 MHz / 2.083 cycles, fractional baud divider). |
| Data bits / parity / stop bits | 8 / none / 1 | Standard UART framing (8N1). |
| Byte order (all multi-byte fields, everywhere in this document) | **Big-endian ("network byte order")** | Applies to standard Ethernet/IP/TCP/UDP headers as well as project-internal fields (`session_id`, lengths, etc.). |

### Framing scheme
**Length-prefixed framing.** Each frame on the wire:

```
[ 2 bytes: total_length (big-endian, includes this header) ] [ payload bytes... ] [ 4 bytes: CRC-32 ]
```

**Decisions & Parameters:**
- **Length field width:** **2 bytes** (`total_length`, big-endian). A 2-byte field caps frames at 65,535 bytes, which covers the largest ML-KEM-512 handshake object (800-byte encapsulation key $ek$, framing total ~820 bytes) with >70× headroom. 2 bytes is locked.
- **Truncated frame behavior:** `deframer.v` holds partial frame state and does not assert `eof`. A frame timeout counter triggers if no bytes arrive for **50,000 cycles** (500 µs at 100 MHz, ~15× the byte arrival interval of 333 cycles at 3 Mbaud). On timeout, `deframer.v` resets to idle, discards partial state, and pulses `verdict.valid` with `verdict.fail = 1` and `verdict.reason_code = RC_FRAME_TIMEOUT` (`4'h2`).
- **Delimiter / Recovery:** Length-prefix only; no delimiter-based fallback. A corrupted length field results in mismatched frame bounds and is caught downstream by CRC-32 (§2) or frame timeout.

**Consumers:** Member A (`uart_rx.v`, `deframer.v`, `crc32.v`), Member D (`drop_engine.v` counts `RC_FRAME_TIMEOUT`).

---

## 2. Link-layer integrity — CRC

| Field | Value |
|---|---|
| Algorithm | CRC-32 (IEEE 802.3 polynomial `0x04C11DB7`, reflected `0xEDB88320`, matches `zlib.crc32` / `binascii.crc32` for cross-checking against `model/pipeline.py`) |
| Position | Appended immediately after the frame payload, 4 bytes, big-endian |
| Failure behavior | Frame dropped before reaching the parser; reason code `RC_CRC_FAIL` (`4'h1`) reported to `drop_engine.v` |

**Consumers:** Member A (implements `crc32.v`), Member D (`drop_engine.v` counts `RC_CRC_FAIL`).

**Note on failure classification:** CRC failure (`RC_CRC_FAIL`) indicates link-layer corruption in transit. Poly1305 failure (`RC_BAD_TAG`) indicates cryptographic message tampering. Their counters and telemetry are strictly separated.

---

## 3. Internal packet bus — the shared struct

Every module downstream of the parser reads this struct in the same clock cycle. Fields are stable across the packet presentation.

```verilog
// packet_bus_t: parallel header context + streaming payload bus
packet_bus_t {
    valid            : 1 bit    // asserted for every cycle carrying live packet payload
    sof              : 1 bit    // start-of-frame, asserted on the first valid payload cycle
    eof              : 1 bit    // end-of-frame, asserted on the last valid payload cycle
    data             : 8 bits   // byte-wide payload stream, valid alongside `valid`

    // --- Ethernet header (latched once parsed, held stable throughout packet) ---
    eth_dst_mac      : 48 bits  // destination MAC
    eth_src_mac      : 48 bits  // source MAC
    eth_type         : 16 bits  // 0x0800 = IPv4; non-IPv4 rejected as MALFORMED

    // --- IPv4 header ---
    ip_version_ihl   : 8 bits   // version (4 bits) + IHL (4 bits); IHL != 5 rejected as MALFORMED
    ip_total_length  : 16 bits  // total length in bytes
    ip_protocol      : 8 bits   // 6 = TCP, 17 = UDP; other protocols rejected as MALFORMED
    ip_src_addr      : 32 bits  // IPv4 source address
    ip_dst_addr      : 32 bits  // IPv4 destination address

    // --- TCP/UDP header ---
    l4_src_port      : 16 bits  // TCP/UDP source port
    l4_dst_port      : 16 bits  // TCP/UDP destination port
    tcp_flags        : 8 bits   // meaningful when ip_protocol == TCP; 8'h00 for UDP
    l4_length        : 16 bits  // TCP data offset or UDP header length

    // --- Project-specific classification fields ---
    payload_len      : 16 bits  // length of the payload in bytes after stripping headers
    session_id       : 16 bits  // matched session ID from lookup; 0 = unassigned
    packet_type      : 2 bits   // packet type classification (see §4)
}
```

**Header Constraints & Rejection Rules:**
- **IPv4 Options:** Packets with `IHL > 5` (options present) are rejected as `RC_MALFORMED` (`4'h3`) by `protocol_validator.v`.
- **Non-IPv4 EtherTypes:** Non-IPv4 frames (`eth_type != 16'h0800`) are rejected as `RC_MALFORMED` (`4'h3`).
- **Payload Delivery:** Raw payload bytes stream on `data[7:0]` with `valid`, `sof`, and `eof` after header fields latch. Member B (CAM and sketch) and Member C (handshake extraction) consume payload bytes directly from this bus.

**Consumers:** Member B (`protocol_validator.v`, `cam_matcher.v`, `count_min_sketch.v`), Member C (`mlkem_top.v`), Member D (`chacha_poly`, `session_mgr.v`, `drop_engine.v`).

---

## 4. Packet classification — `packet_type`

Classification is performed in `parser.v` using **Option A (Port-based classification)** off `l4_dst_port`.

### Port Assignments

| Port Macro | Port Number | Description | Direction | Expected Size |
|---|---:|---|---|---:|
| `PORT_HS_INIT` | **51001** | Handshake — Encapsulation Key (`ek`) | Initiator $\rightarrow$ Responder | 800 B |
| `PORT_HS_RESP` | **51002** | Handshake — Ciphertext (`c`) | Responder $\rightarrow$ Initiator | 768 B |
| `PORT_DATA` | **51010** | Established Session Data (ChaCha20-Poly1305) | Bidirectional | variable |

### `packet_type` Encoding

| `packet_type` | Trigger Port | Classification | Primary Consumer | Target Action |
|---|---|---|---|---|
| `2'b00` | `51001` (`PORT_HS_INIT`) | Handshake: Encapsulation Key (`ek`) | Member C (`mlkem_top.v`) | Run **Encaps**, reply with $c$ |
| `2'b01` | `51010` (`PORT_DATA`)    | Established Session Encrypted Data  | Member D (`chacha_poly`) | Authenticate & decrypt |
| `2'b10` | `51002` (`PORT_HS_RESP`) | Handshake: Ciphertext (`c`)        | Member C (`mlkem_top.v`) | Run **Decaps**, derive key |
| `2'b11` | —                        | Reserved                            | — | Dropped (`RC_MALFORMED`) |

**Structural Handshake Gate (`mlkem_top.v`):**
`mlkem_top.v` enforces structural validation on handshake packets before computation:
- `state == IDLE`, `packet_type == 2'b00`, `payload_len == 800`: Proceed to Encaps.
- `state == HANDSHAKING`, `packet_type == 2'b10`, `payload_len == 768`: Proceed to Decaps.
- Any mismatch: Assert `kem_key_invalid`, drop with `RC_HANDSHAKE_KEY_INVALID` (`4'h8`).

---

## 5. Session register file

Owned structurally by Member D's `session_mgr.v`. Populated by `mlkem_top.v` on handshake completion and referenced by `chacha_poly` during session data processing.

```verilog
session_entry_t {
    session_id       : 16 bits   // matches packet_bus_t.session_id
    shared_secret     : 256 bits  // 32-byte key derived from ML-KEM
    nonce_counter     : 64 bits   // 64-bit per-packet ChaCha20 nonce counter
    state             : 2 bits    // 2'b00=IDLE, 2'b01=HANDSHAKING, 2'b10=ESTABLISHED, 2'b11=REJECTED
}
```

- **Session Table Capacity:** **4 concurrent sessions** (indices 0..3). Session ID `0` is reserved for unassigned/pre-session traffic.
- **Nonce Counter:** 64 bits provides over 500 years of operation at line rate without overflow. Nonce reuse is strictly prevented; session must re-key before counter wrap.

### 5.1 `mlkem_top.v` $\rightarrow$ `session_mgr.v` Interface (Member C $\rightarrow$ Member D)

```verilog
// Port definitions on mlkem_top.v driving session_mgr.v
output reg         kem_done;          // 1-cycle strobe: handshake compute finished
output reg [15:0]  kem_session_id;    // session table index to write
output reg [255:0] kem_shared_secret; // 32-byte shared secret (genuine or decoy)
output reg         kem_key_invalid;   // 1-cycle strobe: structural failure only
```

**Critical Security Requirements:**
1. **Implicit Rejection Indistinguishability:** On decapsulation completion, `mlkem_top.v` asserts `kem_done` on the exact same clock cycle and with identical signal waveforms whether the handshake was authentic or implicitly rejected. `session_mgr.v` writes `kem_shared_secret` into the session table and sets `state = ESTABLISHED` (`2'b10`) **unconditionally**.
2. **Signals that Deliberately Do Not Exist:** There is no `kem_success`, `kem_valid`, or `kem_reject` signal. Cryptographic rejection is not knowable outside `fo_transform.v`.
3. **Reachability of `REJECTED`:** `state = REJECTED` (`2'b11`) is reachable **only** via `kem_key_invalid` (structural failure). It is never entered as a result of decapsulation.

---

## 6. Lane $\rightarrow$ drop-engine verdict interface

Every module capable of rejecting a packet outputs a uniform verdict struct to Member D's `drop_engine.v`:

```verilog
verdict_t {
    valid            : 1 bit    // 1-cycle strobe asserted when this lane's verdict is ready
    fail             : 1 bit    // 1 = reject/drop packet; 0 = pass
    reason_code      : 4 bits   // reason code (RC_* enum, 4'h0 if fail == 0)
}
```

### Reason Code Enum (`rtl/control/reason_codes.vh`)

| Code Macro | Value | Originating Module | Trigger Condition |
|---|---|---|---|
| `RC_NONE` | `4'h0` | — | Packet passes lane checks |
| `RC_CRC_FAIL` | `4'h1` | Member A (`crc32.v`) | Link-layer CRC-32 mismatch (accidental corruption) |
| `RC_FRAME_TIMEOUT` | `4'h2` | Member A (`deframer.v`) | Frame truncated or byte arrival timed out |
| `RC_MALFORMED` | `4'h3` | Member B (`protocol_validator.v`) | Structurally invalid headers (bad IHL, non-IPv4, bad flags) |
| `RC_SIGNATURE` | `4'h4` | Member B (`cam_matcher.v`) | Payload or header matched known attack signature |
| `RC_FLOOD` | `4'h5` | Member B (`count_min_sketch.v`) | Volumetric rate anomaly threshold exceeded |
| `RC_SCAN` | `4'h6` | Member B (`count_min_sketch.v`) | Volumetric spread/fanout anomaly threshold exceeded |
| `RC_BAD_TAG` | `4'h7` | Member D (`poly1305.v`) | Poly1305 MAC tag mismatch (deliberate data tampering) |
| `RC_HANDSHAKE_KEY_INVALID` | `4'h8` | Member C (`mlkem_top.v`) | Structural key validation failure (FIPS 203 §7.2/§7.3, length) |
| `4'h9`–`4'hF` | — | Reserved | Reserved for future expansion (assigned by Member A) |

---

### RULE: IMPLICIT REJECTION EMITS NO VERDICT

> `fo_transform.v` has **no connection to `drop_engine.v`** and drives no reason code.
>
> On a tampered or invalid ciphertext, FIPS 203 decapsulation produces a deterministic pseudorandom decoy key $\bar{K} = J(z \parallel c)$ and completes silently. Emitting a verdict or dropping the handshake leaks the single bit (*"was the ciphertext valid?"*) that the Fujisaki-Okamoto transform exists to deny, recreating a chosen-ciphertext oracle.
>
> The failure surfaces downstream as **`RC_BAD_TAG` (`4'h7`)** when the peer attempts to transmit session data under the invalid key.
>
> **The Golden Rule:** *Structural failures signal openly; cryptographic failures stay silent.*

---

### Drop-Engine Synchronization Architecture

To eliminate cross-module timing brittleness and avoid mid-build revisions, `drop_engine.v` is **latency-agnostic by construction**, synchronizing on per-lane `verdict_valid` strobes rather than hardcoded post-`eof` cycle counters:

1. **Strobe-Based Handshake:** Each participating lane asserts `verdict.valid` for exactly 1 cycle when its verdict is resolved.
2. **Early Fail Termination:** If any lane asserts `verdict.valid` with `fail = 1`, `drop_engine.v` immediately flags the frame for discard and latches the corresponding reason code.
3. **Commit on Full Resolution:** For a packet to be forwarded, all active lanes assigned to that `packet_type` must assert `verdict.valid` with `fail = 0`.
4. **Lane Participation by Packet Type:**
   - **Data Packets (`packet_type == 2'b01`):** Participating lanes are `crc32.v`, `protocol_validator.v`, `cam_matcher.v`, `count_min_sketch.v`, and `poly1305.v`.
   - **Handshake Packets (`packet_type == 2'b00, 2'b10`):** Handshake key validation runs out-of-band in `mlkem_top.v` and signals only on structural failure via `kem_key_invalid`.

#### Provisional Target Latency Reference

*(Note: Target latencies below are design targets for planning; `drop_engine.v` relies strictly on `valid` strobes, confirm final numbers once D5/B7 exist.)*

| Module | Target Verdict Latency | Basis |
|---|---|---|
| `crc32.v` | 0 cycles after `eof` | Computed inline during streaming; ready at `eof` cycle |
| `protocol_validator.v` | 0–1 cycles after header latch | Pure combinational check or single registered stage |
| `cam_matcher.v` | 1 cycle after byte stream | 1-cycle match lookup in parallel CAM |
| `count_min_sketch.v` | ~2–4 cycles after `eof` | Hash compute + multi-bank BRAM read/compare (target latency, confirm once B7/B9 exist) |
| `poly1305.v` | 0–2 cycles after `eof` | Inline accumulator; tag comparison completes at `eof` (target latency, confirm once D5 exists) |
| `fo_transform.v` | **N/A — emits no verdict** | Excluded from drop-engine path; implicit rejection is silent |
| `mlkem_top.v` | Out-of-band (~8,900 cycles) | Session establishment; structural error signals `RC_HANDSHAKE_KEY_INVALID` |

#### Simultaneous-Failure Priority Rule
If multiple lanes signal `fail = 1` for the same packet:
1. **Telemetry:** `drop_engine.v` increments separate counters for **all** asserting reason codes, preserving complete threat telemetry.
2. **Single-Egress Verdict Register Priority:** If downstream hardware requires a single dominant code, priority is ordered by inspection layer:
   $$\text{RC\_CRC\_FAIL} > \text{RC\_FRAME\_TIMEOUT} > \text{RC\_MALFORMED} > \text{RC\_BAD\_TAG} > \text{RC\_SIGNATURE} > \text{RC\_FLOOD} > \text{RC\_SCAN} > \text{RC\_HANDSHAKE\_KEY\_INVALID}$$

---

## 7. Sign-off and Status

| Role | Member | Status | Notes |
|---|---|---|---|
| Ingress / Contract Authority | **Member A** | **SIGNED OFF** | Architecture and interfaces locked |
| Threat Detection Lane | **Member B** | PENDING SIGN-OFF | `B1` unblocked; verify CMS / CAM interfaces |
| ML-KEM Crypto Core | **Member C** | **SIGNED OFF** | Adopted freeze package & reason_codes.vh |
| ChaCha-Poly & Control | **Member D** | PENDING SIGN-OFF | `D1` unblocked; verify drop_engine strobe interface |

---
*End of Interface Contract v1.0.0. All downstream RTL must conform to these definitions.*

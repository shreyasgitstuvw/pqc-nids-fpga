//==========================================================================
// rtl/control/reason_codes.vh
//
// Shared drop-verdict reason codes. Referenced by docs/Member A/
// interface_contract.md sec 6. Included by every module that can reject a
// packet, and by drop_engine.v which merges their verdicts.
//
// Owner: Member A (contract authority).
// This file drafted by Member C to make the sec 6 correction concrete --
// see docs/Member C/Member-C-Contract-Freeze-Package.md. Member A should
// review, adjust, and adopt; do not treat as frozen until A signs off.
//
// Do not self-assign codes in 4'h9..4'hF. Request them via Member A.
//==========================================================================

`ifndef REASON_CODES_VH
`define REASON_CODES_VH

`define RC_WIDTH 4

//--------------------------------------------------------------------------
// Verdict codes
//--------------------------------------------------------------------------
`define RC_NONE                 4'h0  // no failure; packet passes
`define RC_CRC_FAIL             4'h1  // A  crc32.v            link corruption
`define RC_FRAME_TIMEOUT        4'h2  // A  deframer.v         truncated frame
`define RC_MALFORMED            4'h3  // B  protocol_validator invalid header
`define RC_SIGNATURE            4'h4  // B  cam_matcher.v      known signature
`define RC_FLOOD                4'h5  // B  count_min_sketch   rate anomaly
`define RC_SCAN                 4'h6  // B  count_min_sketch   spread anomaly
`define RC_BAD_TAG              4'h7  // D  poly1305.v         auth failure
`define RC_HANDSHAKE_KEY_INVALID 4'h8 // C  mlkem_top.v        see below
// 4'h9 .. 4'hF                       reserved -- request from Member A

//--------------------------------------------------------------------------
// RC_HANDSHAKE_KEY_INVALID (4'h8) -- read this before wiring it up
//
// Signalled ONLY on STRUCTURAL validation failure of handshake key material:
//
//   FIPS 203 sec 7.2  encapsulation key check
//       - ek length != 800 bytes (ML-KEM-512), or
//       - a coefficient is non-canonical: 12-bit fields hold 0..4095 but
//         q = 3329, so 3329..4095 are representable yet invalid.
//
//   FIPS 203 sec 7.3  decapsulation key check
//       - dk length != 1632 bytes, or
//       - SHA3-256(embedded ek) != embedded H(ek) field.
//
//   Plus the structural gate on handshake framing:
//       - payload length does not match the expected object for this
//         session state (see the freeze package, sec 3).
//
// These are all checks on PUBLIC, non-secret data. Their outcome does not
// depend on any key material, so signalling them openly leaks nothing.
//
//--------------------------------------------------------------------------
// RULE: IMPLICIT REJECTION EMITS NO VERDICT.
//
// fo_transform.v has NO connection to drop_engine.v. It must not drive any
// signal in this file.
//
// On a tampered or invalid CIPHERTEXT, FIPS 203 requires decapsulation to
// return a deterministic decoy key Kbar = J(z||c) and report nothing. That
// is the whole mechanism of the Fujisaki-Okamoto transform: it denies an
// attacker the single bit "was my ciphertext valid?". Asserting a reason
// code on that event hands the bit back at the system level and restores
// the chosen-ciphertext oracle the transform exists to remove. The crypto
// would be correct and the system would still be broken.
//
// The failure surfaces downstream instead: the two peers now hold different
// keys, so the peer's first DATA packet fails Poly1305 and is reported as
// RC_BAD_TAG (4'h7) by Member D's existing lane. That costs one wasted
// packet and needs no new mechanism.
//
// Consequence for session_mgr.v (Member D): session state REJECTED (2'b11)
// is reachable ONLY from RC_HANDSHAKE_KEY_INVALID. It is NEVER entered as a
// result of a decapsulation outcome, because that outcome is not knowable
// outside fo_transform.v. Wiring REJECTED to the FO transform reintroduces
// exactly the leak this rule removes.
//
// Verified in the Python golden model (model/mlkem/kem.py):
//     tampered H(ek) in dk  -> raises  (structural, sec 7.3)
//     tampered ciphertext   -> silent decoy key returned
// Reproduce: python model/mlkem/kat_test.py   (80/80, zero skips)
//--------------------------------------------------------------------------

`endif // REASON_CODES_VH

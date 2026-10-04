// =============================================================================
// session_mgr.v -- Session register file and per-session state machine
//
// Owner : Member D        Contract: docs/Member A/interface_contract.md, sec 5
// Clock : clk (100 MHz), synchronous active-high reset rst
//
// WHAT IT DOES (hardware view)
//   A 4-entry register file. Each entry holds:
//       state[1:0]   00 IDLE | 01 HANDSHAKING | 10 ESTABLISHED | 11 REJECTED
//       secret[255:0] 32-byte ML-KEM shared secret
//       nonce[63:0]   per-packet ChaCha20 nonce counter
//
//   Write side  (from mlkem_top.v, contract sec 5.1)
//       kem_done          1-cycle strobe, handshake finished
//       kem_session_id    entry to write
//       kem_shared_secret key, genuine OR implicit-rejection decoy
//       kem_key_invalid   1-cycle strobe, STRUCTURAL failure only
//
//   Read side   (to chacha_poly.v)  -- 1-cycle registered lookup
//       lk_req + lk_id  ->  next cycle: lk_valid strobe, lk_ok, lk_key, lk_nonce
//   Nonce side
//       nonce_adv + nonce_adv_id : counter++ after a packet consumed its nonce
//
// THE ONE HARD RULE (AGENTS.md, @control)
//   The write on kem_done is UNCONDITIONAL: secret <= kem_shared_secret,
//   nonce <= 0, state <= ESTABLISHED. No signal anywhere in this module is
//   derived from the VALUE of kem_shared_secret, and there is no input that
//   says "genuine" vs "decoy" (none exists in the contract). So a genuine and
//   an implicitly-rejected handshake produce identical timing and identical
//   state transitions here. By construction, not by discipline.
//
//   REJECTED is entered ONLY from kem_key_invalid. Decapsulation can never
//   reach it.
//
// DECISIONS THAT NEED MEMBER A / C SIGN-OFF (not invented silently)
//   1. Contract sec 5 says "indices 0..3" AND "session ID 0 is reserved".
//      Implemented: 4 storage entries, entry index = session_id[1:0];
//      session_id 0 and ids >= 4 are out of range: writes ignored, lookups
//      miss. So 3 ids (1..3) are usable. These checks use only the PUBLIC
//      session id, never the secret.
//   2. The contract has no "handshake started" input, so nothing drives
//      state HANDSHAKING. The encoding is kept, but this module never enters
//      it until such a strobe is added to the contract.
//   3. The lookup/nonce ports (lk_*, nonce_adv*) are internal to Member D
//      and are not in the contract.
//   4. Nonce is 64-bit; the 96-bit ChaCha nonce is {32'h0, counter}. An entry
//      whose counter reached all-ones reports lk_ok = 0 (must re-key; reuse
//      of a nonce is never allowed).
// =============================================================================
`timescale 1ns / 1ps

module session_mgr (
    input  wire         clk,
    input  wire         rst,

    // ---- from mlkem_top.v (contract sec 5.1) ----
    input  wire         kem_done,
    input  wire [15:0]  kem_session_id,
    input  wire [255:0] kem_shared_secret,
    input  wire         kem_key_invalid,

    // ---- lookup port to chacha_poly.v ----
    input  wire         lk_req,
    input  wire [15:0]  lk_id,
    output reg          lk_valid,       // 1-cycle strobe, answers lk_req
    output reg          lk_ok,          // 1 = ESTABLISHED and nonce not exhausted
    output reg  [255:0] lk_key,
    output reg  [95:0]  lk_nonce,
    output reg  [1:0]   lk_state,

    // ---- nonce advance ----
    input  wire         nonce_adv,
    input  wire [15:0]  nonce_adv_id
);

    localparam [1:0] ST_IDLE   = 2'b00;
    // 2'b01 (HANDSHAKING) intentionally not declared: never entered, see decision 2
    localparam [1:0] ST_ESTAB  = 2'b10;
    localparam [1:0] ST_REJECT = 2'b11;

    reg [1:0]   st     [0:3];
    reg [255:0] secret [0:3];
    reg [63:0]  nonce  [0:3];

    // Public-id range checks (id 1..3 usable)
    wire kem_id_ok = (kem_session_id[15:2] == 14'd0) && (kem_session_id[1:0] != 2'd0);
    wire lk_id_ok  = (lk_id[15:2]          == 14'd0) && (lk_id[1:0]          != 2'd0);
    wire adv_id_ok = (nonce_adv_id[15:2]   == 14'd0) && (nonce_adv_id[1:0]   != 2'd0);

    wire [1:0] kem_idx = kem_session_id[1:0];
    wire [1:0] lk_idx  = lk_id[1:0];
    wire [1:0] adv_idx = nonce_adv_id[1:0];

    integer i;

    always @(posedge clk) begin
        if (rst) begin
            for (i = 0; i < 4; i = i + 1) begin
                st[i]     <= ST_IDLE;
                secret[i] <= 256'd0;
                nonce[i]  <= 64'd0;
            end
            lk_valid <= 1'b0;
            lk_ok    <= 1'b0;
            lk_key   <= 256'd0;
            lk_nonce <= 96'd0;
            lk_state <= ST_IDLE;
        end else begin
            // ---------------- write side ----------------
            // Nonce advance first; a same-cycle KEM write to the same entry
            // overrides it (new key restarts the counter at 0).
            if (nonce_adv && adv_id_ok && st[adv_idx] == ST_ESTAB &&
                nonce[adv_idx] != 64'hFFFF_FFFF_FFFF_FFFF)
                nonce[adv_idx] <= nonce[adv_idx] + 64'd1;

            if (kem_key_invalid && kem_id_ok) begin
                // Structural failure: the only way into REJECTED.
                // Zeroise the key so a bad entry can never encrypt.
                st[kem_idx]     <= ST_REJECT;
                secret[kem_idx] <= 256'd0;
                nonce[kem_idx]  <= 64'd0;
            end else if (kem_done && kem_id_ok) begin
                // UNCONDITIONAL write -- genuine key or decoy, same path.
                st[kem_idx]     <= ST_ESTAB;
                secret[kem_idx] <= kem_shared_secret;
                nonce[kem_idx]  <= 64'd0;
            end

            // ---------------- lookup side ----------------
            lk_valid <= lk_req;
            if (lk_req) begin
                if (lk_id_ok) begin
                    lk_state <= st[lk_idx];
                    lk_key   <= secret[lk_idx];
                    lk_nonce <= {32'd0, nonce[lk_idx]};
                    lk_ok    <= (st[lk_idx] == ST_ESTAB) &&
                                (nonce[lk_idx] != 64'hFFFF_FFFF_FFFF_FFFF);
                end else begin
                    lk_state <= ST_IDLE;
                    lk_key   <= 256'd0;
                    lk_nonce <= 96'd0;
                    lk_ok    <= 1'b0;
                end
            end
        end
    end

endmodule

//==========================================================================
// rtl/control/session_lookup.v
//
// Packet -> session-id resolution for the internal packet bus.
//
// WHY THIS MODULE EXISTS
//   interface_contract.md section 3 defines the packet-bus field
//       session_id : 16 bits  // matched session ID from lookup; 0 = unassigned
//   and section 5 gives Member D the register file that *holds* sessions. Nothing
//   owned the function that *assigns* an id to an arriving packet, so parser.v
//   emitted session_id = 0 for every packet and session_mgr.v rejected 0 as out
//   of range (session_mgr.v kem_id_ok). The effect was that no session could ever
//   reach ESTABLISHED, no key was ever stored, no data packet could be decrypted,
//   and cam_matcher.v never saw a plaintext byte. This module closes that gap.
//
// KEY CHOICE
//   The table is keyed on ip_src_addr alone, not the full 5-tuple. A peer's
//   source port changes from packet to packet, so including it would make every
//   packet a miss. The source address is what identifies the peer across its
//   handshake and its subsequent data packets.
//
//   An attacker who spoofs a victim's source address maps onto the victim's slot.
//   That is not a hole: it buys them nothing, because the session key is the
//   ML-KEM shared secret and they cannot produce a Poly1305 tag that verifies
//   under it. Such a packet fails with RC_BAD_TAG, which is the correct verdict.
//
// ALLOCATION POLICY
//   SLOTS = 3, giving ids 1..3. session_mgr.v reserves id 0 and ignores ids >= 4,
//   so 1..3 is exactly the usable range (session_mgr.v decision 1).
//     packet_type 2'b00 (HS_INIT) or 2'b10 (HS_RESP)
//         A handshake claims a session. Reuse this peer's slot if it already has
//         one; otherwise take a free slot; otherwise evict round-robin. A
//         handshake therefore always resolves to a usable id.
//     packet_type 2'b01 (DATA)
//         Look up only. A hit returns the peer's id; a miss returns 0, which
//         session_mgr treats as out of range and chacha_poly is never keyed for.
//         That is the correct outcome for data on a session that was never
//         established.
//     packet_type 2'b11 (Reserved)
//         Returns 0. drop_engine rejects reserved packets as RC_MALFORMED.
//
// TIMING AND STABILITY
//   sid_valid strobes one cycle after hdr_valid, and session_id is then held
//   stable until the next hdr_valid. Section 3 requires the header fields to be
//   "latched once parsed, held stable throughout packet", and session_id is one
//   of those fields. The one-cycle lookup matches protocol_validator.v, which also
//   answers one cycle after header_valid.
//
// Resource estimate (XC7Z020, pre-synthesis): 3 x 32-bit key registers plus
//   3 valid bits and a 2-bit victim pointer, about 100 FFs and 3 32-bit
//   comparators (~40 LUTs). No BRAM, no DSP.
//==========================================================================

`timescale 1ns / 1ps

module session_lookup (
    input  wire        clk,
    input  wire        rst,

    // ---- from parser.v (packet bus header context) ----
    input  wire        hdr_valid,       // 1-cycle strobe: headers parsed
    input  wire [31:0] ip_src_addr,     // peer address = table key
    input  wire [1:0]  packet_type,     // 2'b00 HS_INIT, 2'b01 DATA, 2'b10 HS_RESP

    // ---- resolved session id (packet-bus field) ----
    output reg  [15:0] session_id,      // 1..3 on a hit/allocation, 0 = unassigned
    output reg         sid_valid,       // 1-cycle strobe: session_id updated
    output reg         sid_hit,         // 1 = resolved to an existing session
    output reg         sid_allocated,   // 1 = a handshake claimed a new slot
    output reg         sid_evicted,     // 1 = that allocation evicted a live slot

    // ---- session teardown (from drop_engine / control) ----
    input  wire        clear_req,       // 1-cycle strobe: invalidate clear_id
    input  wire [15:0] clear_id         // session id to invalidate (1..3)
);

    localparam [1:0] PKT_HS_INIT = 2'b00;
    localparam [1:0] PKT_DATA    = 2'b01;
    localparam [1:0] PKT_HS_RESP = 2'b10;

    // Slot i holds session id (i+1), so ids run 1..3.
    reg [31:0] key   [0:2];
    reg        occupied [0:2];
    reg [1:0]  victim;              // round-robin eviction pointer, 0..2

    // ---- combinational match against all three slots ----
    wire hit0 = occupied[0] && (key[0] == ip_src_addr);
    wire hit1 = occupied[1] && (key[1] == ip_src_addr);
    wire hit2 = occupied[2] && (key[2] == ip_src_addr);
    wire       any_hit  = hit0 | hit1 | hit2;
    wire [1:0] hit_slot = hit0 ? 2'd0 : (hit1 ? 2'd1 : 2'd2);

    wire       any_free  = ~occupied[0] | ~occupied[1] | ~occupied[2];
    wire [1:0] free_slot = ~occupied[0] ? 2'd0 : (~occupied[1] ? 2'd1 : 2'd2);

    wire is_handshake = (packet_type == PKT_HS_INIT) || (packet_type == PKT_HS_RESP);
    wire is_data      = (packet_type == PKT_DATA);

    // Slot chosen when a handshake claims a session: reuse, else free, else evict.
    wire [1:0] claim_slot = any_hit ? hit_slot : (any_free ? free_slot : victim);
    wire       claim_evicts = !any_hit && !any_free;

    // Teardown decode (clear_id 1..3 -> slot 0..2)
    wire        clear_ok   = clear_req && (clear_id >= 16'd1) && (clear_id <= 16'd3);
    wire [1:0]  clear_slot = clear_id[1:0] - 2'd1;

    integer i;

    always @(posedge clk) begin
        if (rst) begin
            for (i = 0; i < 3; i = i + 1) begin
                key[i]      <= 32'd0;
                occupied[i] <= 1'b0;
            end
            victim        <= 2'd0;
            session_id    <= 16'd0;
            sid_valid     <= 1'b0;
            sid_hit       <= 1'b0;
            sid_allocated <= 1'b0;
            sid_evicted   <= 1'b0;
        end else begin
            // 1-cycle strobes default low; session_id itself is held.
            sid_valid     <= 1'b0;
            sid_hit       <= 1'b0;
            sid_allocated <= 1'b0;
            sid_evicted   <= 1'b0;

            // Teardown first; a same-cycle hdr_valid allocation below overrides it
            // for the slot it claims, which is the intended precedence.
            if (clear_ok) begin
                occupied[clear_slot] <= 1'b0;
                key[clear_slot]      <= 32'd0;
            end

            if (hdr_valid) begin
                sid_valid <= 1'b1;

                if (is_handshake) begin
                    key[claim_slot]      <= ip_src_addr;
                    occupied[claim_slot] <= 1'b1;
                    session_id           <= {14'd0, claim_slot} + 16'd1;
                    sid_hit              <= any_hit;
                    sid_allocated        <= ~any_hit;
                    sid_evicted          <= claim_evicts;
                    // Advance the victim pointer only when we actually evicted.
                    if (claim_evicts)
                        victim <= (victim == 2'd2) ? 2'd0 : (victim + 2'd1);
                end else if (is_data && any_hit) begin
                    session_id <= {14'd0, hit_slot} + 16'd1;
                    sid_hit    <= 1'b1;
                end else begin
                    // DATA on an unestablished session, or a reserved type.
                    session_id <= 16'd0;
                end
            end
        end
    end

endmodule

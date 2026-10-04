// rtl/control/drop_engine.v
//
// Drop Engine -- Merges Lane 1 and Lane 2 verdicts and maintains threat telemetry
// Member D (@control)
//
// References:
//   - docs/Member A/interface_contract.md (v1.1.0 Section 6)
//   - docs/Member D/Member-D-ChaCha-Poly-and-Control.md (Step 4)
//   - rtl/control/reason_codes.vh
//
// Architecture & Synchronization (Interface Contract Section 6):
// ==============================================================
// 1. Strobe-based & Latency-agnostic:
//    Participating lanes assert their uniform 1-cycle verdict strobe
//    {valid, fail, reason_code} when their check completes.
// 2. Early Fail Detection & Priority Resolution:
//    If one or more lanes signal fail=1, the packet is flagged for drop.
//    Dominant egress reason code follows the inspection-layer hierarchy:
//      RC_CRC_FAIL (1) > RC_FRAME_TIMEOUT (2) > RC_MALFORMED (3) >
//      RC_BAD_TAG (7)  > RC_SIGNATURE (4)     > RC_FLOOD (5)     >
//      RC_SCAN (6)     > RC_HANDSHAKE_KEY_INVALID (8)
// 3. Commit on Full Resolution:
//    When all participating lanes for the packet_type have reported,
//    the final verdict is emitted on drop_valid (1-cycle strobe).
// 4. Telemetry Counters:
//    Dedicated 32-bit saturating counters for every reason code.
//    Telemetry Exception (v1.1.0):
//      If RC_BAD_TAG asserts, a simultaneous RC_SIGNATURE from cam_matcher
//      is NOT counted as a signature detection (decrypted noise, not real attack).
//
// Constraints: Verilog-2001, single clk, sync active-high rst, registered outputs.

`timescale 1ns / 1ps
`include "reason_codes.vh"

module drop_engine (
    input  wire        clk,
    input  wire        rst,

    // ---- Packet Context & Framing --------------------------------------------
    input  wire        pkt_sof,         // 1-cycle strobe: packet starts
    input  wire        pkt_eof,         // 1-cycle strobe: packet payload ends
    input  wire [1:0]  pkt_type,        // 2'b00=HS_INIT, 2'b01=DATA, 2'b10=HS_RESP

    // ---- Lane 1 / Ingress Verdicts (Member A) --------------------------------
    input  wire        v_crc_valid,
    input  wire        v_crc_fail,
    input  wire [3:0]  v_crc_reason,

    input  wire        v_deframe_valid, // Frame timeout from deframer
    input  wire        v_deframe_fail,
    input  wire [3:0]  v_deframe_reason,

    // ---- Lane 2 Verdicts (Member B) ------------------------------------------
    input  wire        v_proto_valid,   // Protocol validator
    input  wire        v_proto_fail,
    input  wire [3:0]  v_proto_reason,

    input  wire        v_cam_valid,     // Signature CAM matcher
    input  wire        v_cam_fail,
    input  wire [3:0]  v_cam_reason,

    input  wire        v_cms_valid,     // Count-min sketch (flood / scan)
    input  wire        v_cms_fail,
    input  wire [3:0]  v_cms_reason,

    // ---- Lane 1 / Crypto Auth Verdicts (Member D & Member C) -----------------
    input  wire        v_poly_valid,    // Poly1305 auth tag match
    input  wire        v_poly_fail,
    input  wire [3:0]  v_poly_reason,

    input  wire        v_kem_valid,     // Structural handshake key invalid
    input  wire        v_kem_fail,
    input  wire [3:0]  v_kem_reason,

    // ---- Egress Verdict (1-cycle strobe when decision resolves) --------------
    output reg         drop_valid,      // 1-cycle pulse: verdict ready
    output reg         drop_fail,       // 1 = discard/drop packet, 0 = forward/pass
    output reg  [3:0]  drop_reason,     // Dominant reason code (`RC_NONE if drop_fail==0)

    // ---- Telemetry Counters (Host / LED / OLED visible) ----------------------
    output reg  [31:0] cnt_crc_fail,
    output reg  [31:0] cnt_frame_timeout,
    output reg  [31:0] cnt_malformed,
    output reg  [31:0] cnt_signature,
    output reg  [31:0] cnt_flood,
    output reg  [31:0] cnt_scan,
    output reg  [31:0] cnt_bad_tag,
    output reg  [31:0] cnt_handshake_key_invalid,
    output reg  [31:0] cnt_total_drops,
    output reg  [31:0] cnt_total_passed
);

    // =========================================================================
    // Active lane tracking for current packet
    // =========================================================================
    reg [1:0] latched_pkt_type;
    reg       in_packet;

    // Bit masks of lanes that must report before decision commits
    // Bit 0: CRC
    // Bit 1: Protocol Validator
    // Bit 2: CAM Matcher
    // Bit 3: Count-Min Sketch
    // Fail flags latched across the packet evaluation window
    reg fail_crc;
    reg fail_deframe;
    reg fail_proto;
    reg fail_cam;
    reg fail_cms_flood;
    reg fail_cms_scan;
    reg fail_poly;
    reg fail_kem;

    // Determine expected lanes based on packet_type
    function [4:0] get_expected_lanes;
        input [1:0] ptype;
        begin
            case (ptype)
                2'b01:   get_expected_lanes = 5'b11111; // DATA: CRC, PROTO, CAM, CMS, POLY
                2'b00,
                2'b10:   get_expected_lanes = 5'b01011; // HANDSHAKE: CRC, PROTO, CMS (no CAM, no POLY)
                default: get_expected_lanes = 5'b00000; // Reserved / Malformed
            endcase
        end
    endfunction

    // Dominant reason code priority selector per contract Section 6:
    // RC_CRC_FAIL > RC_FRAME_TIMEOUT > RC_MALFORMED > RC_BAD_TAG >
    // RC_SIGNATURE > RC_FLOOD > RC_SCAN > RC_HANDSHAKE_KEY_INVALID
    function [3:0] select_dominant_reason;
        input f_crc;
        input f_deframe;
        input f_proto;
        input f_poly;
        input f_cam;
        input f_flood;
        input f_scan;
        input f_kem;
        begin
            if (f_crc)
                select_dominant_reason = `RC_CRC_FAIL;
            else if (f_deframe)
                select_dominant_reason = `RC_FRAME_TIMEOUT;
            else if (f_proto)
                select_dominant_reason = `RC_MALFORMED;
            else if (f_poly)
                select_dominant_reason = `RC_BAD_TAG;
            else if (f_cam)
                select_dominant_reason = `RC_SIGNATURE;
            else if (f_flood)
                select_dominant_reason = `RC_FLOOD;
            else if (f_scan)
                select_dominant_reason = `RC_SCAN;
            else if (f_kem)
                select_dominant_reason = `RC_HANDSHAKE_KEY_INVALID;
            else
                select_dominant_reason = `RC_NONE;
        end
    endfunction

    // Check if any failure has been recorded
    wire any_fail = fail_crc || fail_deframe || fail_proto || fail_poly ||
                    fail_cam || fail_cms_flood || fail_cms_scan || fail_kem;

    reg rep_crc;
    reg rep_proto;
    reg rep_cam;
    reg rep_cms;
    reg rep_poly;

    // Bit masks of lanes that must report before decision commits
    // Bit 0: CRC, Bit 1: PROTO, Bit 2: CAM, Bit 3: CMS, Bit 4: POLY
    reg [4:0] expected_lanes;

    // Active lanes that have reported (combining registered and current cycle strobes)
    wire [4:0] cur_reported = {
        rep_poly  || v_poly_valid,
        rep_cms   || v_cms_valid,
        rep_cam   || v_cam_valid,
        rep_proto || v_proto_valid,
        rep_crc   || v_crc_valid
    };

    // All expected lanes have responded
    wire all_lanes_reported = in_packet && ((cur_reported & expected_lanes) == expected_lanes);
    wire eff_deframe_flag   = fail_deframe || (v_deframe_valid && v_deframe_fail);

    // =========================================================================
    // Synchronous Engine & Telemetry Logic
    // =========================================================================
    always @(posedge clk) begin
        if (rst) begin
            drop_valid                  <= 1'b0;
            drop_fail                   <= 1'b0;
            drop_reason                 <= `RC_NONE;
            in_packet                   <= 1'b0;
            latched_pkt_type            <= 2'b00;
            expected_lanes              <= 5'b00000;
            rep_crc                     <= 1'b0;
            rep_proto                   <= 1'b0;
            rep_cam                     <= 1'b0;
            rep_cms                     <= 1'b0;
            rep_poly                    <= 1'b0;

            fail_crc                    <= 1'b0;
            fail_deframe                <= 1'b0;
            fail_proto                  <= 1'b0;
            fail_cam                    <= 1'b0;
            fail_cms_flood              <= 1'b0;
            fail_cms_scan               <= 1'b0;
            fail_poly                   <= 1'b0;
            fail_kem                    <= 1'b0;

            cnt_crc_fail                <= 32'd0;
            cnt_frame_timeout           <= 32'd0;
            cnt_malformed               <= 32'd0;
            cnt_signature               <= 32'd0;
            cnt_flood                   <= 32'd0;
            cnt_scan                    <= 32'd0;
            cnt_bad_tag                 <= 32'd0;
            cnt_handshake_key_invalid   <= 32'd0;
            cnt_total_drops             <= 32'd0;
            cnt_total_passed            <= 32'd0;
        end else begin
            // Default: clear 1-cycle egress strobe
            drop_valid <= 1'b0;



            // -----------------------------------------------------------------
            // Packet Start: initialize tracking mask and clear packet latches
            // -----------------------------------------------------------------
            if (pkt_sof) begin
                in_packet        <= 1'b1;
                latched_pkt_type <= pkt_type;
                expected_lanes   <= get_expected_lanes(pkt_type);
                rep_crc          <= 1'b0;
                rep_proto        <= 1'b0;
                rep_cam          <= 1'b0;
                rep_cms          <= 1'b0;
                rep_poly         <= 1'b0;

                fail_crc         <= 1'b0;
                fail_deframe     <= 1'b0;
                fail_proto       <= 1'b0;
                fail_cam         <= 1'b0;
                fail_cms_flood   <= 1'b0;
                fail_cms_scan    <= 1'b0;
                fail_poly        <= 1'b0;
                fail_kem         <= 1'b0;

                // Immediate reject if packet_type == 2'b11 (reserved)
                if (pkt_type == 2'b11) begin
                    fail_proto <= 1'b1;
                end
            end

            // -----------------------------------------------------------------
            // Latch incoming asynchronous verdict strobes from active lanes
            // -----------------------------------------------------------------
            if (v_crc_valid) begin
                rep_crc <= 1'b1;
                if (v_crc_fail) fail_crc <= 1'b1;
            end

            if (v_deframe_valid && v_deframe_fail) begin
                // Frame timeout can arrive out of band
                fail_deframe <= 1'b1;
            end

            if (v_proto_valid) begin
                rep_proto <= 1'b1;
                if (v_proto_fail) fail_proto <= 1'b1;
            end

            if (v_cam_valid) begin
                rep_cam <= 1'b1;
                if (v_cam_fail) fail_cam <= 1'b1;
            end

            if (v_cms_valid) begin
                rep_cms <= 1'b1;
                if (v_cms_fail) begin
                    if (v_cms_reason == `RC_SCAN)
                        fail_cms_scan  <= 1'b1;
                    else
                        fail_cms_flood <= 1'b1;
                end
            end

            if (v_poly_valid) begin
                rep_poly <= 1'b1;
                if (v_poly_fail) fail_poly <= 1'b1;
            end

            if (v_kem_valid && v_kem_fail) begin
                fail_kem <= 1'b1;
            end

            // -----------------------------------------------------------------
            // Verdict Resolution & Commit
            // -----------------------------------------------------------------
            if (in_packet && (all_lanes_reported || eff_deframe_flag || (latched_pkt_type == 2'b11))) begin : blk_commit
                // Combine current cycle arrivals with already latched flags
                // (ensures zero-latency same-cycle verdict latching)
                reg eff_crc, eff_deframe, eff_proto, eff_cam, eff_flood, eff_scan, eff_poly, eff_kem;
                reg eff_fail;
                reg [3:0] eff_reason;

                eff_crc     = fail_crc     || (v_crc_valid     && v_crc_fail);
                eff_deframe = fail_deframe || (v_deframe_valid && v_deframe_fail);
                eff_proto   = fail_proto   || (v_proto_valid   && v_proto_fail);
                eff_cam     = fail_cam     || (v_cam_valid     && v_cam_fail);
                eff_flood   = fail_cms_flood || (v_cms_valid   && v_cms_fail && (v_cms_reason == `RC_FLOOD));
                eff_scan    = fail_cms_scan  || (v_cms_valid   && v_cms_fail && (v_cms_reason == `RC_SCAN));
                eff_poly    = fail_poly    || (v_poly_valid    && v_poly_fail);
                eff_kem     = fail_kem     || (v_kem_valid     && v_kem_fail);

                eff_fail = eff_crc || eff_deframe || eff_proto || eff_poly ||
                           eff_cam || eff_flood || eff_scan || eff_kem;

                eff_reason = select_dominant_reason(
                    eff_crc, eff_deframe, eff_proto, eff_poly,
                    eff_cam, eff_flood, eff_scan, eff_kem
                );

                // Drive 1-cycle egress verdict
                drop_valid  <= 1'b1;
                drop_fail   <= eff_fail;
                drop_reason <= eff_reason;

                // Close current packet evaluation window
                in_packet <= 1'b0;

                // -------------------------------------------------------------
                // Telemetry counter updates (saturating 32-bit counters)
                // -------------------------------------------------------------
                if (eff_fail) begin
                    if (cnt_total_drops != 32'hFFFFFFFF)
                        cnt_total_drops <= cnt_total_drops + 32'd1;

                    if (eff_crc && cnt_crc_fail != 32'hFFFFFFFF)
                        cnt_crc_fail <= cnt_crc_fail + 32'd1;

                    if (eff_deframe && cnt_frame_timeout != 32'hFFFFFFFF)
                        cnt_frame_timeout <= cnt_frame_timeout + 32'd1;

                    if (eff_proto && cnt_malformed != 32'hFFFFFFFF)
                        cnt_malformed <= cnt_malformed + 32'd1;

                    if (eff_flood && cnt_flood != 32'hFFFFFFFF)
                        cnt_flood <= cnt_flood + 32'd1;

                    if (eff_scan && cnt_scan != 32'hFFFFFFFF)
                        cnt_scan <= cnt_scan + 32'd1;

                    if (eff_poly && cnt_bad_tag != 32'hFFFFFFFF)
                        cnt_bad_tag <= cnt_bad_tag + 32'd1;

                    if (eff_kem && cnt_handshake_key_invalid != 32'hFFFFFFFF)
                        cnt_handshake_key_invalid <= cnt_handshake_key_invalid + 32'd1;

                    // Telemetry Exception (v1.1.0 Section 6):
                    // Do NOT increment cnt_signature if eff_poly (RC_BAD_TAG) is asserted!
                    if (eff_cam && !eff_poly && cnt_signature != 32'hFFFFFFFF)
                        cnt_signature <= cnt_signature + 32'd1;

                end else begin
                    // Packet passed all required checks
                    if (cnt_total_passed != 32'hFFFFFFFF)
                        cnt_total_passed <= cnt_total_passed + 32'd1;
                end
            end
        end
    end

endmodule

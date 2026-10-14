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

module drop_engine #(
    // Liveness bound on a packet's evaluation window. Armed at pkt_sof and
    // restarted at pkt_eof, so for a packet with a payload it measures the stall
    // AFTER the payload ended, and for a zero-payload packet it still bounds the
    // window. It must exceed the bus time of the longest packet, because the
    // payload streams inside the window: a 1518-byte frame at 3 Mbaud occupies
    // about 505,000 clocks. The default, 2,000,000 clocks, is 20 ms at 100 MHz.
    //
    // The handshake KEM verdict is deliberately NOT one of the expected lanes,
    // so this bound does not have to cover its ~34,000 clocks -- see
    // "HANDSHAKE VERDICT" below.
    parameter [31:0] WATCHDOG_CYCLES = 32'd2_000_000
) (
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
    output reg  [31:0] cnt_total_passed,
    output reg  [31:0] cnt_lane_timeout,   // packets force-committed by the watchdog
    output reg  [31:0] cnt_stray_verdict
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

    // The deframer emits RC_CRC_FAIL, RC_FRAME_TIMEOUT or RC_MALFORMED on a
    // single verdict port, and crc32.v has no verdict port at all. Deriving the
    // code from which port fired therefore mislabelled every CRC failure and
    // every malformed frame as RC_FRAME_TIMEOUT. Latch what the lane actually
    // sent and use it.
    reg [3:0] deframe_code;

    // Watchdog: pkt_eof arms it, and if an expected lane never reports the
    // packet is force-committed instead of leaving in_packet set forever.
    reg [31:0] wd_cnt;
    reg        wd_armed;

    // The handshake verdict is asynchronous to the packet. mlkem_top reports
    // 17,658 to 33,814 clocks after the header (docs/Member C/Member-C-KEM-Cycle-
    // Counts.md), long after the packet window has
    // closed, so RC_HANDSHAKE_KEY_INVALID could never be emitted and a
    // structurally invalid handshake was counted as passed. It is handled
    // out-of-band here, deferred by one cycle if a packet commit is in flight.
    reg        kem_pending;

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

    // The deframe lane carries three different codes on one port, so its reason
    // field IS consumed (see "DEFRAME LANE" below). The other lanes each emit a
    // single fixed code, which the priority selector reproduces, so their reason
    // fields are redundant and sunk here to keep -Wall clean.
    wire _unused_ok = &{1'b0, v_crc_reason, v_proto_reason, v_cam_reason,
                        v_poly_reason, v_kem_reason};

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
    wire wd_expired         = wd_armed && in_packet && (wd_cnt >= WATCHDOG_CYCLES);

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
            deframe_code                <= `RC_FRAME_TIMEOUT;
            wd_cnt                      <= 32'd0;
            wd_armed                    <= 1'b0;
            kem_pending                 <= 1'b0;
            cnt_lane_timeout            <= 32'd0;
            cnt_stray_verdict           <= 32'd0;
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
                deframe_code     <= `RC_FRAME_TIMEOUT;

                fail_crc         <= 1'b0;
                fail_deframe     <= 1'b0;
                fail_proto       <= 1'b0;
                fail_cam         <= 1'b0;
                fail_cms_flood   <= 1'b0;
                fail_cms_scan    <= 1'b0;
                fail_poly        <= 1'b0;

                // Immediate reject if packet_type == 2'b11 (reserved)
                if (pkt_type == 2'b11) begin
                    fail_proto <= 1'b1;
                end
            end

            // -----------------------------------------------------------------
            // Latch incoming asynchronous verdict strobes from active lanes
            // -----------------------------------------------------------------
            // Latching is gated on the packet being open. A verdict that
            // arrives between packets used to be charged to whichever packet
            // started next, dropping a clean packet and leaving the real one
            // unadjudicated. Such strays are now counted and discarded.
            //
            // pkt_sof is included because in_packet only rises on that same
            // edge, and a lane may legitimately report in the sof cycle.
            if (in_packet || pkt_sof) begin
                if (v_crc_valid) begin
                    rep_crc <= 1'b1;
                    if (v_crc_fail) fail_crc <= 1'b1;
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
                        // Both this path and the same-cycle term in the commit
                        // block must decode identically, or a CMS verdict can be
                        // counted differently depending on when it lands.
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
            end else if (v_crc_valid || v_proto_valid || v_cam_valid ||
                         v_cms_valid || v_poly_valid) begin
                // Arrived with no packet open: not attributable to anything.
                if (cnt_stray_verdict != 32'hFFFFFFFF)
                    cnt_stray_verdict <= cnt_stray_verdict + 32'd1;
            end

            // The deframe lane is framing-level and legitimately fires outside a
            // packet window (a frame that never completed has no sof), so it is
            // not gated. Its reason code is carried, not inferred.
            if (v_deframe_valid && v_deframe_fail) begin
                fail_deframe <= 1'b1;
                deframe_code <= v_deframe_reason;
            end

            // Handshake verdict: out of band, see the declaration of kem_pending.
            if (v_kem_valid && v_kem_fail)
                kem_pending <= 1'b1;

            // Watchdog: armed as soon as the packet opens, and restarted at
            // pkt_eof so the bound is measured from the end of the payload when
            // there is one.
            if (pkt_sof) begin
                wd_armed <= 1'b1;
                wd_cnt   <= 32'd0;
            end else if (pkt_eof && in_packet) begin
                wd_cnt   <= 32'd0;
            end else if (wd_armed && in_packet) begin
                wd_cnt   <= wd_cnt + 32'd1;
            end

            // -----------------------------------------------------------------
            // Verdict Resolution & Commit
            // -----------------------------------------------------------------
            if (in_packet && (all_lanes_reported || eff_deframe_flag ||
                              (latched_pkt_type == 2'b11) || wd_expired)) begin : blk_commit
                // Combine current cycle arrivals with already latched flags
                // (ensures zero-latency same-cycle verdict latching)
                reg eff_crc, eff_deframe, eff_proto, eff_cam, eff_flood, eff_scan, eff_poly;
                reg eff_fail;
                reg [3:0] eff_reason;
                // A deframe verdict can arrive in the same cycle it commits, so
                // the latched copy is not yet updated: take the live code then.
                reg [3:0] eff_dcode;

                eff_crc     = fail_crc     || (v_crc_valid     && v_crc_fail);
                eff_deframe = fail_deframe || (v_deframe_valid && v_deframe_fail);
                eff_proto   = fail_proto   || (v_proto_valid   && v_proto_fail);
                eff_cam     = fail_cam     || (v_cam_valid     && v_cam_fail);
                eff_flood   = fail_cms_flood || (v_cms_valid   && v_cms_fail && (v_cms_reason == `RC_FLOOD));
                eff_scan    = fail_cms_scan  || (v_cms_valid   && v_cms_fail && (v_cms_reason == `RC_SCAN));
                eff_poly    = fail_poly    || (v_poly_valid    && v_poly_fail);
                eff_dcode   = (v_deframe_valid && v_deframe_fail) ? v_deframe_reason
                                                                  : deframe_code;

                // A lane that never reported is a timeout, not a pass: fail the
                // packet rather than forwarding something no detector cleared.
                eff_fail = eff_crc || eff_deframe || eff_proto || eff_poly ||
                           eff_cam || eff_flood || eff_scan || wd_expired;

                eff_reason = select_dominant_reason(
                    eff_crc, eff_deframe, eff_proto, eff_poly,
                    eff_cam, eff_flood, eff_scan, 1'b0
                );
                // The deframe lane carries its own code; honour it.
                if (eff_deframe && !eff_crc)
                    eff_reason = eff_dcode;
                // Nothing else failed but a lane went missing: report it as a
                // malformed packet, which is the closest honest code.
                if (!(eff_crc || eff_deframe || eff_proto || eff_poly ||
                      eff_cam || eff_flood || eff_scan) && wd_expired)
                    eff_reason = `RC_MALFORMED;

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

                    // The deframer reports CRC failures and malformed lengths on
                    // the same port as timeouts, so route by the code it sent.
                    if (eff_deframe) begin
                        if ((eff_dcode == `RC_CRC_FAIL) && cnt_crc_fail != 32'hFFFFFFFF)
                            cnt_crc_fail <= cnt_crc_fail + 32'd1;
                        else if ((eff_dcode == `RC_MALFORMED) && cnt_malformed != 32'hFFFFFFFF)
                            cnt_malformed <= cnt_malformed + 32'd1;
                        else if (cnt_frame_timeout != 32'hFFFFFFFF)
                            cnt_frame_timeout <= cnt_frame_timeout + 32'd1;
                    end

                    if (eff_proto && cnt_malformed != 32'hFFFFFFFF)
                        cnt_malformed <= cnt_malformed + 32'd1;

                    if (eff_flood && cnt_flood != 32'hFFFFFFFF)
                        cnt_flood <= cnt_flood + 32'd1;

                    if (eff_scan && cnt_scan != 32'hFFFFFFFF)
                        cnt_scan <= cnt_scan + 32'd1;

                    if (eff_poly && cnt_bad_tag != 32'hFFFFFFFF)
                        cnt_bad_tag <= cnt_bad_tag + 32'd1;

                    // Telemetry Exception (v1.1.0 Section 6):
                    // Do NOT increment cnt_signature if eff_poly (RC_BAD_TAG) is asserted!
                    if (eff_cam && !eff_poly && cnt_signature != 32'hFFFFFFFF)
                        cnt_signature <= cnt_signature + 32'd1;

                    if (wd_expired && cnt_lane_timeout != 32'hFFFFFFFF)
                        cnt_lane_timeout <= cnt_lane_timeout + 32'd1;

                end else begin
                    // Packet passed all required checks
                    if (cnt_total_passed != 32'hFFFFFFFF)
                        cnt_total_passed <= cnt_total_passed + 32'd1;
                end
            end else if (kem_pending && !in_packet) begin
                // -------------------------------------------------------------
                // HANDSHAKE VERDICT (out of band)
                // -------------------------------------------------------------
                // mlkem_top reports a structural handshake failure 17,658 to
                // 33,814 clocks after the header, by which time the packet
                // window has long closed. Inside the window this verdict was
                // unreachable: RC_HANDSHAKE_KEY_INVALID could never be emitted
                // and an invalid handshake was counted as passed. It is a
                // session-scoped failure rather than a packet-scoped one, so it
                // is reported on its own. It is held while a packet window is
                // open so the two never collide on drop_valid and the order is
                // deterministic: the packet's own verdict always comes first.
                drop_valid  <= 1'b1;
                drop_fail   <= 1'b1;
                drop_reason <= `RC_HANDSHAKE_KEY_INVALID;
                kem_pending <= 1'b0;
                if (cnt_handshake_key_invalid != 32'hFFFFFFFF)
                    cnt_handshake_key_invalid <= cnt_handshake_key_invalid + 32'd1;
                if (cnt_total_drops != 32'hFFFFFFFF)
                    cnt_total_drops <= cnt_total_drops + 32'd1;
            end
        end
    end

endmodule

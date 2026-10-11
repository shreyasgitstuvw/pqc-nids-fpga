// sim/cocotb/lane2_drop_top.v
//
// Integration harness wiring Lane 2 detectors to drop_engine.v (Task B12)
// Verifies that all three threat detection modules emit {valid, fail, reason_code}
// strictly adhering to Interface Contract v1.1.0 Section 6 and that drop_engine
// correctly arbitrates, prioritizes, and counts all Lane 2 verdicts.
//
// Target: ZedBoard XC7Z020 @ 100 MHz
// Owner: Member B (@detect)

`timescale 1ns / 1ps
`include "reason_codes.vh"

module lane2_drop_top (
    input  wire        clk,
    input  wire        rst,

    // ---- Framing Context -----------------------------------------------------
    input  wire        pkt_sof,
    input  wire        pkt_eof,
    input  wire [1:0]  pkt_type,

    // ---- Header Bus for Lane 2 -----------------------------------------------
    input  wire        header_valid,
    input  wire [15:0] eth_type,
    input  wire [7:0]  ip_version_ihl,
    input  wire [7:0]  ip_protocol,
    input  wire [15:0] ip_total_length,
    input  wire [31:0] src_ip,
    input  wire [31:0] dst_ip,
    input  wire [15:0] l4_src_port,
    input  wire [15:0] l4_dst_port,
    input  wire [15:0] l4_length,
    input  wire [7:0]  tcp_flags,
    input  wire [15:0] payload_len,

    // ---- Plaintext Stream for CAM Matcher (Contract §3.1) -------------------
    input  wire        pt_valid,
    input  wire [7:0]  pt_data,
    input  wire        pt_sof,
    input  wire        pt_eof,
    input  wire        pt_tag_ok,
    input  wire        pt_tag_valid,

    // ---- Mock Lane 1 Inputs (to isolate Lane 2) -----------------------------
    input  wire        v_crc_valid,
    input  wire        v_crc_fail,
    input  wire [3:0]  v_crc_reason,

    input  wire        v_deframe_valid,
    input  wire        v_deframe_fail,
    input  wire [3:0]  v_deframe_reason,

    input  wire        v_poly_valid,
    input  wire        v_poly_fail,
    input  wire [3:0]  v_poly_reason,

    input  wire        v_kem_valid,
    input  wire        v_kem_fail,
    input  wire [3:0]  v_kem_reason,

    // ---- Egress Drop Engine Verdict & Telemetry ------------------------------
    output wire        drop_valid,
    output wire        drop_fail,
    output wire [3:0]  drop_reason,

    output wire [31:0] cnt_crc_fail,
    output wire [31:0] cnt_frame_timeout,
    output wire [31:0] cnt_malformed,
    output wire [31:0] cnt_signature,
    output wire [31:0] cnt_flood,
    output wire [31:0] cnt_scan,
    output wire [31:0] cnt_bad_tag,
    output wire [31:0] cnt_handshake_key_invalid,
    output wire [31:0] cnt_total_drops,
    output wire [31:0] cnt_total_passed,

    // ---- Direct Lane 2 Diagnostic Probes -------------------------------------
    output wire        v_proto_valid,
    output wire        v_proto_fail,
    output wire [3:0]  v_proto_reason,

    output wire        v_cam_valid,
    output wire        v_cam_fail,
    output wire [3:0]  v_cam_reason,
    output wire [4:0]  match_sig_id,
    output wire [15:0] match_offset,

    output wire        v_cms_valid,
    output wire        v_cms_fail,
    output wire [3:0]  v_cms_reason,
    output wire [15:0] c_flow_out,
    output wire [15:0] c_host_out
);

    // =========================================================================
    // Module 1: Protocol Validator (Combinational Header Sanity Check)
    // =========================================================================
    protocol_validator u_proto (
        .clk             (clk),
        .rst             (rst),
        .header_valid    (header_valid),
        .eth_type        (eth_type),
        .ip_version_ihl  (ip_version_ihl),
        .ip_protocol     (ip_protocol),
        .ip_total_length (ip_total_length),
        .l4_src_port     (l4_src_port),
        .l4_dst_port     (l4_dst_port),
        .l4_length       (l4_length),
        .tcp_flags       (tcp_flags),
        .payload_len     (payload_len),
        .verdict_valid   (v_proto_valid),
        .verdict_fail    (v_proto_fail),
        .verdict_reason  (v_proto_reason)
    );

    // =========================================================================
    // Module 2: Signature CAM Matcher (Plaintext Streaming Inspection)
    // =========================================================================
    cam_matcher u_cam (
        .clk          (clk),
        .rst          (rst),
        .pt_valid     (pt_valid),
        .pt_data      (pt_data),
        .pt_sof       (pt_sof),
        .pt_eof       (pt_eof),
        .pt_tag_ok    (pt_tag_ok),
        .pt_tag_valid (pt_tag_valid),
        .v_cam_valid  (v_cam_valid),
        .v_cam_fail   (v_cam_fail),
        .v_cam_reason (v_cam_reason),
        .match_sig_id (match_sig_id),
        .match_offset (match_offset)
    );

    // =========================================================================
    // Module 3: Count-Min Sketch (BRAM Dual-Sketch Volumetric Detector)
    // =========================================================================
    count_min_sketch #(
        .THRESH_FLOOD (16'd512),
        .THRESH_SCAN  (16'd384),
        .FANOUT_MAX   (16'd96),
        .EPOCH_N      (16'd32768)
    ) u_cms (
        .clk            (clk),
        .rst            (rst),
        .header_valid   (header_valid),
        .src_ip         (src_ip),
        .dst_ip         (dst_ip),
        .dst_port       (l4_dst_port),
        .protocol       (ip_protocol),
        .eof            (pkt_eof),
        .ready          (),
        .verdict_valid  (v_cms_valid),
        .verdict_fail   (v_cms_fail),
        .verdict_reason (v_cms_reason),
        .c_flow_out     (c_flow_out),
        .c_host_out     (c_host_out)
    );

    // =========================================================================
    // Module 4: Drop Engine (Verdict Arbiter & Telemetry Counters)
    // =========================================================================
    drop_engine u_drop (
        .clk                         (clk),
        .rst                         (rst),
        .pkt_sof                     (pkt_sof),
        .pkt_eof                     (pkt_eof),
        .pkt_type                    (pkt_type),

        // Lane 1 Ingress Verdicts
        .v_crc_valid                 (v_crc_valid),
        .v_crc_fail                  (v_crc_fail),
        .v_crc_reason                (v_crc_reason),
        .v_deframe_valid             (v_deframe_valid),
        .v_deframe_fail              (v_deframe_fail),
        .v_deframe_reason            (v_deframe_reason),

        // Lane 2 Verdicts (Connected to Members B modules above)
        .v_proto_valid               (v_proto_valid),
        .v_proto_fail                (v_proto_fail),
        .v_proto_reason              (v_proto_reason),
        .v_cam_valid                 (v_cam_valid),
        .v_cam_fail                  (v_cam_fail),
        .v_cam_reason                (v_cam_reason),
        .v_cms_valid                 (v_cms_valid),
        .v_cms_fail                  (v_cms_fail),
        .v_cms_reason                (v_cms_reason),

        // Lane 1 Crypto Verdicts
        .v_poly_valid                (v_poly_valid),
        .v_poly_fail                 (v_poly_fail),
        .v_poly_reason               (v_poly_reason),
        .v_kem_valid                 (v_kem_valid),
        .v_kem_fail                  (v_kem_fail),
        .v_kem_reason                (v_kem_reason),

        // Egress Drop Engine Verdict & Telemetry
        .drop_valid                  (drop_valid),
        .drop_fail                   (drop_fail),
        .drop_reason                 (drop_reason),
        .cnt_crc_fail                (cnt_crc_fail),
        .cnt_frame_timeout           (cnt_frame_timeout),
        .cnt_malformed               (cnt_malformed),
        .cnt_signature               (cnt_signature),
        .cnt_flood                   (cnt_flood),
        .cnt_scan                    (cnt_scan),
        .cnt_bad_tag                 (cnt_bad_tag),
        .cnt_handshake_key_invalid   (cnt_handshake_key_invalid),
        .cnt_total_drops             (cnt_total_drops),
        .cnt_total_passed            (cnt_total_passed)
    );

endmodule

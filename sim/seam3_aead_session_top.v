//==========================================================================
// sim/seam3_aead_session_top.v
//
// Seam-3 test fixture: the REAL session_mgr.v -> REAL aead_framer.v ->
// REAL chacha_poly.v (and its real chacha20.v / poly1305.v), wired as
// rtl/top/pqc_nids_top.v wires them, with no model of any of them.
//
// What it exists to prove:
//   * a DATA packet's payload is correctly split into ciphertext and its
//     trailing 16-byte Poly1305 tag, which nothing did before;
//   * the session key and nonce reach chacha_poly.v from the session table;
//   * nonce_adv is actually pulsed, so a session does not reuse nonce 0;
//   * the ciphertext FIFO makes the result independent of packet-bus arrival
//     rate -- chacha_poly.v loses payload bytes when driven faster than it can
//     accept them, and the contract's bus has no backpressure.
//
// Simulation fixture only -- not part of the synthesised design.
//==========================================================================

`timescale 1ns / 1ps

module seam3_aead_session_top (
    input  wire         clk,
    input  wire         rst,

    // packet bus header context
    input  wire         hdr_valid,
    input  wire [1:0]   packet_type,
    input  wire [15:0]  payload_len,
    input  wire [15:0]  session_id,
    input  wire [31:0]  ip_src_addr,
    input  wire [31:0]  ip_dst_addr,
    input  wire [15:0]  l4_src_port,
    input  wire [15:0]  l4_dst_port,

    // packet bus payload stream
    input  wire         pb_valid,
    input  wire         pb_sof,
    input  wire         pb_eof,
    input  wire [7:0]   pb_data,

    // KEM completion, driven by the testbench in place of mlkem_top.v
    input  wire         kem_done,
    input  wire [15:0]  kem_session_id,
    input  wire [255:0] kem_shared_secret,

    // plaintext inspection bus (contract section 3.1) -> cam_matcher
    output wire         pt_valid,
    output wire [7:0]   pt_data,
    output wire         pt_sof,
    output wire         pt_eof,
    output wire         pt_tag_ok,
    output wire         pt_tag_valid,

    // uniform verdict to drop_engine (owned by aead_framer)
    output wire         v_poly_valid,
    output wire         v_poly_fail,
    output wire [3:0]   v_poly_reason,

    // observation
    output wire         cp_ready,
    output wire         cp_done,
    output wire         fifo_overflow,
    output wire         no_session_drop,
    output wire         nonce_adv_o,
    output wire [95:0]  dbg_nonce,

    // direct session table read port for the testbench
    input  wire         lk_req_tb,
    input  wire [15:0]  lk_id_tb,
    output wire         lk_valid_tb,
    output wire         lk_ok_tb,
    output wire [95:0]  lk_nonce_tb,
    output wire [1:0]   lk_state_tb
);

    // ---- session_mgr lookup port is shared: framer owns it, testbench peeks
    // between packets. Arbitration is simply "framer wins", which is safe
    // because the testbench only reads while the framer is idle.
    wire        fr_lk_req;
    wire [15:0] fr_lk_id;
    wire        sm_lk_valid, sm_lk_ok;
    wire [255:0] sm_lk_key;
    wire [95:0] sm_lk_nonce;
    wire [1:0]  sm_lk_state;

    wire        lk_req_mux = fr_lk_req | lk_req_tb;
    wire [15:0] lk_id_mux  = fr_lk_req ? fr_lk_id : lk_id_tb;

    assign lk_valid_tb = sm_lk_valid;
    assign lk_ok_tb    = sm_lk_ok;
    assign lk_nonce_tb = sm_lk_nonce;
    assign lk_state_tb = sm_lk_state;
    assign dbg_nonce   = sm_lk_nonce;

    wire        fr_nonce_adv;
    wire [15:0] fr_nonce_adv_id;
    assign nonce_adv_o = fr_nonce_adv;

    session_mgr u_sess (
        .clk(clk), .rst(rst),
        .kem_done(kem_done), .kem_session_id(kem_session_id),
        .kem_shared_secret(kem_shared_secret), .kem_key_invalid(1'b0),
        .lk_req(lk_req_mux), .lk_id(lk_id_mux),
        .lk_valid(sm_lk_valid), .lk_ok(sm_lk_ok), .lk_key(sm_lk_key),
        .lk_nonce(sm_lk_nonce), .lk_state(sm_lk_state),
        .nonce_adv(fr_nonce_adv), .nonce_adv_id(fr_nonce_adv_id)
    );

    wire         fr_key_valid;
    wire [255:0] fr_key;
    wire [95:0]  fr_nonce;
    wire [127:0] fr_aad;
    wire [4:0]   fr_aad_len;
    wire         fr_ct_valid, fr_ct_sof, fr_ct_eof;
    wire [7:0]   fr_ct_data;
    wire [127:0] fr_exp_tag;
    wire         cp_vpv, cp_vpf;
    wire [3:0]   cp_vpr;
    wire         cp_busy;
    wire [127:0] cp_tag_out;
    wire         cp_tag_ok;

    aead_framer u_framer (
        .clk(clk), .rst(rst),
        .hdr_valid(hdr_valid), .packet_type(packet_type),
        .payload_len(payload_len), .session_id(session_id),
        .ip_src_addr(ip_src_addr), .ip_dst_addr(ip_dst_addr),
        .l4_src_port(l4_src_port), .l4_dst_port(l4_dst_port),
        .pb_valid(pb_valid), .pb_sof(pb_sof), .pb_eof(pb_eof), .pb_data(pb_data),
        .lk_req(fr_lk_req), .lk_id(fr_lk_id),
        .lk_valid(sm_lk_valid), .lk_ok(sm_lk_ok),
        .lk_key(sm_lk_key), .lk_nonce(sm_lk_nonce),
        .nonce_adv(fr_nonce_adv), .nonce_adv_id(fr_nonce_adv_id),
        .key_valid(fr_key_valid), .key(fr_key), .nonce(fr_nonce),
        .aad_data(fr_aad), .aad_len(fr_aad_len),
        .ct_valid(fr_ct_valid), .ct_data(fr_ct_data),
        .ct_sof(fr_ct_sof), .ct_eof(fr_ct_eof), .expected_tag(fr_exp_tag),
        .cp_ready(cp_ready), .cp_done(cp_done),
        .cp_v_poly_valid(cp_vpv), .cp_v_poly_fail(cp_vpf), .cp_v_poly_reason(cp_vpr),
        .v_poly_valid(v_poly_valid), .v_poly_fail(v_poly_fail),
        .v_poly_reason(v_poly_reason),
        .fifo_overflow(fifo_overflow), .no_session_drop(no_session_drop)
    );

    chacha_poly u_cp (
        .clk(clk), .rst(rst),
        .key_valid(fr_key_valid), .key(fr_key), .nonce(fr_nonce),
        .aad_data(fr_aad), .aad_len(fr_aad_len),
        .ct_valid(fr_ct_valid), .ct_data(fr_ct_data),
        .ct_sof(fr_ct_sof), .ct_eof(fr_ct_eof),
        .expected_tag(fr_exp_tag),
        .ready(cp_ready), .busy(cp_busy), .done(cp_done),
        .pt_valid(pt_valid), .pt_data(pt_data), .pt_sof(pt_sof), .pt_eof(pt_eof),
        .pt_tag_ok(pt_tag_ok), .pt_tag_valid(pt_tag_valid),
        .v_poly_valid(cp_vpv), .v_poly_fail(cp_vpf), .v_poly_reason(cp_vpr),
        .tag_out(cp_tag_out), .tag_ok(cp_tag_ok)
    );

    wire _unused_ok = &{1'b0, cp_busy, cp_tag_out, cp_tag_ok};

endmodule

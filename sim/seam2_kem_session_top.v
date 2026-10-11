//==========================================================================
// sim/seam2_kem_session_top.v
//
// Test fixture for C17 (Seam 2): mlkem_top.v (Member C) wired directly to
// session_mgr.v (Member D) exactly as contract sec 5.1 specifies:
//     kem_done / kem_session_id / kem_shared_secret / kem_key_invalid
// are connected 1:1, with NO logic in between. Everything else is a
// pass-through so the testbench drives the real packet bus and observes the
// real session_mgr lookup port (the boundary chacha_poly sees).
//
// This file is a simulation fixture only; it is not part of the synthesised
// design and adds no behaviour of its own.
//==========================================================================
`timescale 1ns / 1ps

module seam2_kem_session_top (
    input  wire         clk,
    input  wire         rst,

    input  wire         packet_bus_valid,
    input  wire         packet_bus_sof,
    input  wire         packet_bus_eof,
    input  wire [7:0]   packet_bus_data,
    input  wire [15:0]  packet_bus_payload_len,
    input  wire [15:0]  packet_bus_session_id,
    input  wire [1:0]   packet_bus_packet_type,

    output wire         kem_done,
    output wire [15:0]  kem_session_id,
    output wire [255:0] kem_shared_secret,
    output wire         kem_key_invalid,
    output wire         v_kem_valid,
    output wire         v_kem_fail,
    output wire [3:0]   v_kem_reason,
    output wire         busy,
    output wire         rng_take,
    output wire         kem_pkt_dropped_busy,

    input  wire         cmd_start,
    input  wire [1:0]   cmd_op,
    input  wire [15:0]  cmd_session_id,
    input  wire [255:0] seed_d,
    input  wire [255:0] seed_z,
    input  wire [255:0] seed_m,
    input  wire         rng_valid,
    input  wire [255:0] rng_data,

    input  wire [7:0]   dk_ram_rd_addr,
    output wire [63:0]  dk_ram_rdata,
    input  wire         dk_ram_wr_en,
    input  wire [7:0]   dk_ram_wr_addr_ext,
    input  wire [63:0]  dk_ram_wr_data_ext,
    input  wire         ek_ram_wr_en,
    input  wire [6:0]   ek_ram_wr_addr_ext,
    input  wire [63:0]  ek_ram_wr_data_ext,
    input  wire [6:0]   c_ram_rd_addr_ext,
    output wire [63:0]  c_ram_rdata_ext,
    input  wire         c_ram_wr_en,
    input  wire [6:0]   c_ram_wr_addr_ext,
    input  wire [63:0]  c_ram_wr_data_ext,

    // session_mgr lookup port (what chacha_poly.v sees)
    input  wire         lk_req,
    input  wire [15:0]  lk_id,
    output wire         lk_valid,
    output wire         lk_ok,
    output wire [255:0] lk_key,
    output wire [95:0]  lk_nonce,
    output wire [1:0]   lk_state
);

    mlkem_top u_kem (
        .clk(clk), .rst(rst),
        .packet_bus_valid(packet_bus_valid), .packet_bus_sof(packet_bus_sof),
        .packet_bus_eof(packet_bus_eof), .packet_bus_data(packet_bus_data),
        .packet_bus_payload_len(packet_bus_payload_len),
        .packet_bus_session_id(packet_bus_session_id),
        .packet_bus_packet_type(packet_bus_packet_type),
        .kem_done(kem_done), .kem_session_id(kem_session_id),
        .kem_shared_secret(kem_shared_secret), .kem_key_invalid(kem_key_invalid),
        .v_kem_valid(v_kem_valid), .v_kem_fail(v_kem_fail), .v_kem_reason(v_kem_reason),
        .cmd_start(cmd_start), .cmd_op(cmd_op), .cmd_session_id(cmd_session_id),
        .seed_d(seed_d), .seed_z(seed_z), .seed_m(seed_m), .busy(busy),
        .rng_valid(rng_valid), .rng_data(rng_data), .rng_take(rng_take),
        .kem_pkt_dropped_busy(kem_pkt_dropped_busy),
        .dk_ram_rd_addr(dk_ram_rd_addr), .dk_ram_rdata(dk_ram_rdata),
        .dk_ram_wr_en(dk_ram_wr_en), .dk_ram_wr_addr_ext(dk_ram_wr_addr_ext),
        .dk_ram_wr_data_ext(dk_ram_wr_data_ext),
        .ek_ram_wr_en(ek_ram_wr_en), .ek_ram_wr_addr_ext(ek_ram_wr_addr_ext),
        .ek_ram_wr_data_ext(ek_ram_wr_data_ext),
        .c_ram_rd_addr_ext(c_ram_rd_addr_ext), .c_ram_rdata_ext(c_ram_rdata_ext),
        .c_ram_wr_en(c_ram_wr_en), .c_ram_wr_addr_ext(c_ram_wr_addr_ext),
        .c_ram_wr_data_ext(c_ram_wr_data_ext)
    );

    session_mgr u_sess (
        .clk(clk), .rst(rst),
        .kem_done(kem_done), .kem_session_id(kem_session_id),
        .kem_shared_secret(kem_shared_secret), .kem_key_invalid(kem_key_invalid),
        .lk_req(lk_req), .lk_id(lk_id), .lk_valid(lk_valid), .lk_ok(lk_ok),
        .lk_key(lk_key), .lk_nonce(lk_nonce), .lk_state(lk_state),
        .nonce_adv(1'b0), .nonce_adv_id(16'd0)
    );

endmodule

//==========================================================================
// sim/seam1_ingress_session_top.v
//
// Seam-1 test fixture: the REAL parser.v, the REAL session_lookup.v and the
// REAL session_mgr.v wired together exactly as rtl/top/pqc_nids_top.v wires
// them, with no model of any of them.
//
// What it exists to prove: that a handshake packet arriving on the packet bus
// now resolves to a usable session id and the key actually lands in the session
// table. Before session_lookup.v existed, parser.v emitted session_id = 0 for
// every packet and session_mgr.v rejected 0 as out of range, so no session could
// ever reach ESTABLISHED and nothing downstream of the cipher could work.
//
// parser.v's own session_id output is deliberately left unconnected: it is a
// stub that always drives 0 (see session_lookup.v's header). session_lookup.v
// owns that packet-bus field.
//
// Simulation fixture only -- not part of the synthesised design.
//==========================================================================

`timescale 1ns / 1ps

module seam1_ingress_session_top (
    input  wire        clk,
    input  wire        rst,

    // raw post-deframer byte stream into parser.v
    input  wire        in_valid,
    input  wire [7:0]  in_data,
    input  wire        in_sof,
    input  wire        in_eof,

    // packet-bus observation
    output wire        hdr_valid,
    output wire        parsed_ok,
    output wire [1:0]  packet_type,
    output wire [15:0] payload_len,
    output wire [31:0] ip_src_addr,
    output wire [15:0] l4_dst_port,
    output wire        out_valid,
    output wire        out_sof,
    output wire        out_eof,
    output wire [7:0]  out_data,

    // resolved session id (the field session_lookup.v owns)
    output wire [15:0] session_id,
    output wire        sid_valid,
    output wire        sid_hit,
    output wire        sid_allocated,

    // KEM completion, driven by the testbench in place of mlkem_top.v
    input  wire        kem_done,
    input  wire [255:0] kem_shared_secret,
    input  wire        kem_key_invalid,

    // session table lookup port (what the AEAD framer sees)
    input  wire        lk_req,
    input  wire [15:0] lk_id,
    output wire        lk_valid,
    output wire        lk_ok,
    output wire [255:0] lk_key,
    output wire [95:0] lk_nonce,
    output wire [1:0]  lk_state,
    input  wire        nonce_adv,
    input  wire [15:0] nonce_adv_id,

    input  wire        clear_req,
    input  wire [15:0] clear_id
);

    wire [47:0] eth_dst_mac, eth_src_mac;
    wire [15:0] eth_type, ip_total_length, l4_src_port, l4_length;
    wire [7:0]  ip_version_ihl, ip_protocol, tcp_flags;
    wire [31:0] ip_dst_addr;
    wire [15:0] parser_session_id_unused;
    wire        sid_evicted_unused;

    // Header fields this fixture does not observe. Sunk explicitly so the
    // fixture lints as cleanly as the RTL it wires together.
    wire _unused_ok = &{1'b0, eth_dst_mac, eth_src_mac, eth_type,
                        ip_version_ihl, ip_total_length, ip_protocol,
                        ip_dst_addr, l4_src_port, tcp_flags, l4_length,
                        parser_session_id_unused, sid_evicted_unused};

    parser u_parser (
        .clk(clk), .rst(rst),
        .in_valid(in_valid), .in_data(in_data), .in_sof(in_sof), .in_eof(in_eof),
        .hdr_valid(hdr_valid), .parsed_ok(parsed_ok),
        .eth_dst_mac(eth_dst_mac), .eth_src_mac(eth_src_mac), .eth_type(eth_type),
        .ip_version_ihl(ip_version_ihl), .ip_total_length(ip_total_length),
        .ip_protocol(ip_protocol), .ip_src_addr(ip_src_addr), .ip_dst_addr(ip_dst_addr),
        .l4_src_port(l4_src_port), .l4_dst_port(l4_dst_port), .tcp_flags(tcp_flags),
        .l4_length(l4_length), .payload_len(payload_len),
        .session_id(parser_session_id_unused),   // stub, always 0 -- see header
        .packet_type(packet_type),
        .out_valid(out_valid), .out_sof(out_sof), .out_eof(out_eof), .out_data(out_data)
    );

    session_lookup u_lookup (
        .clk(clk), .rst(rst),
        .hdr_valid(hdr_valid), .ip_src_addr(ip_src_addr), .packet_type(packet_type),
        .session_id(session_id), .sid_valid(sid_valid), .sid_hit(sid_hit),
        .sid_allocated(sid_allocated), .sid_evicted(sid_evicted_unused),
        .clear_req(clear_req), .clear_id(clear_id)
    );

    session_mgr u_sess (
        .clk(clk), .rst(rst),
        .kem_done(kem_done), .kem_session_id(session_id),
        .kem_shared_secret(kem_shared_secret), .kem_key_invalid(kem_key_invalid),
        .lk_req(lk_req), .lk_id(lk_id), .lk_valid(lk_valid), .lk_ok(lk_ok),
        .lk_key(lk_key), .lk_nonce(lk_nonce), .lk_state(lk_state),
        .nonce_adv(nonce_adv), .nonce_adv_id(nonce_adv_id)
    );

endmodule

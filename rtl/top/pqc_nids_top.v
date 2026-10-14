//==========================================================================
// rtl/top/pqc_nids_top.v
//
// THE synthesis target. Wires every lane into one design:
//
//   uart_rx -> deframer -> parser ----+--> session_lookup --> session_id
//                                     |
//                                     +--> protocol_validator ---+
//                                     +--> count_min_sketch -----+
//                                     |                          |
//                                     +--> mlkem_top (handshake) +--> drop_engine
//                                     |                          |
//                                     +--> aead_framer -> chacha_poly
//                                                            |   |
//                                                     pt_* --+   +--> v_poly
//                                                            |
//                                                   cam_matcher +
//
//   mlkem_top  -> session_mgr  (shared secret in)
//   aead_framer <-> session_mgr (key/nonce out, nonce_adv in)
//   mlkem_top  -> handshake_tx -> uart_tx (the 768-byte ciphertext reply)
//   drop_engine -> led_driver, telemetry_tx -> uart_tx
//
// Before this file existed there was no top level at all: rtl/top/ held only a
// .gitkeep, chacha_poly was instantiated nowhere, and the only multi-module
// files in the tree were simulation fixtures.
//
// DESIGN NOTES THAT ARE NOT OBVIOUS FROM THE WIRING
//
//   parser.v's session_id output is left unconnected. It is a stub that always
//   drives 0, and session_mgr rejects 0 as out of range. session_lookup.v owns
//   that packet-bus field (contract section 3, amended v1.1.1).
//
//   drop_engine's v_crc_* port is tied off. crc32.v has no verdict interface;
//   deframer.v reports CRC failures, frame timeouts and malformed lengths on
//   its single verdict port, which lands on v_deframe_* and carries its own
//   reason code.
//
//   aead_framer owns v_poly_* rather than chacha_poly driving drop_engine
//   directly, so a DATA packet whose cipher never runs still reports exactly
//   once and cannot stall the engine.
//
//   A KeyGen runs once automatically after reset. Decaps needs this board's own
//   decapsulation key, and nothing else would ever produce one.
//
//   The UART transmitter is shared. handshake_tx has absolute priority because
//   the ciphertext reply is on the critical path of the handshake; telemetry
//   frames fill the gaps.
//
// Resource estimate: pre-synthesis, and deliberately not stated here. Every
// such figure in this repository is an estimate until scripts/build_bitstream.tcl
// has been run; the utilisation and timing reports it writes are the only real
// numbers.
//==========================================================================

`timescale 1ns / 1ps

`include "reason_codes.vh"

module pqc_nids_top #(
    parameter integer CLK_HZ    = 100_000_000,
    parameter integer BAUD_RATE = 3_000_000
) (
    input  wire       clk,          // 100 MHz, ZedBoard GCLK
    input  wire       btn_rst,      // active-high push button
    input  wire       uart_rx_pin,  // Pmod USB-UART, data from host
    output wire       uart_tx_pin,  // Pmod USB-UART, data to host
    output wire [7:0] led           // LD0..LD7
);

    // ---------------------------------------------------------------- reset
    // Two-stage synchroniser plus a power-on hold, so the whole design leaves
    // reset together and no register starts in X on hardware.
    reg [3:0] rst_sync;
    wire      rst = rst_sync[3];
    always @(posedge clk) rst_sync <= {rst_sync[2:0], btn_rst};
    // (rst_sync powers up at 0 in the fabric; the explicit hold below covers
    //  the first cycles after configuration.)
    reg [7:0] por_cnt;
    reg       por_rst;
    always @(posedge clk) begin
        if (por_cnt != 8'hFF) begin
            por_cnt <= por_cnt + 8'd1;
            por_rst <= 1'b1;
        end else begin
            por_rst <= 1'b0;
        end
    end
    wire rst_i = rst | por_rst;

    // ------------------------------------------------------------- ingress
    wire [7:0] rx_data;
    wire       rx_valid, rx_busy, rx_frame_err;

    uart_rx #(.CLK_FREQ(CLK_HZ), .BAUD_RATE(BAUD_RATE)) u_uart_rx (
        .clk(clk), .rst(rst_i), .rx_pin(uart_rx_pin),
        .rx_data(rx_data), .rx_valid(rx_valid), .rx_busy(rx_busy),
        .frame_err(rx_frame_err)
    );

    wire       df_valid, df_sof, df_eof;
    wire [7:0] df_data;
    wire       df_v_valid, df_v_fail;
    wire [3:0] df_v_code;

    deframer u_deframer (
        .clk(clk), .rst(rst_i),
        .in_valid(rx_valid), .in_data(rx_data),
        .out_valid(df_valid), .out_data(df_data),
        .out_sof(df_sof), .out_eof(df_eof),
        .verdict_valid(df_v_valid), .verdict_fail(df_v_fail),
        .verdict_code(df_v_code)
    );

    wire        hdr_valid, parsed_ok;
    wire [47:0] eth_dst_mac, eth_src_mac;
    wire [15:0] eth_type, ip_total_length, l4_src_port, l4_dst_port, l4_length;
    wire [7:0]  ip_version_ihl, ip_protocol, tcp_flags;
    wire [31:0] ip_src_addr, ip_dst_addr;
    wire [15:0] payload_len;
    wire [1:0]  packet_type;
    wire        pb_valid, pb_sof, pb_eof;
    wire [7:0]  pb_data;
    wire [15:0] parser_sid_stub;      // stub, always 0 -- see header

    parser u_parser (
        .clk(clk), .rst(rst_i),
        .in_valid(df_valid), .in_data(df_data), .in_sof(df_sof), .in_eof(df_eof),
        .hdr_valid(hdr_valid), .parsed_ok(parsed_ok),
        .eth_dst_mac(eth_dst_mac), .eth_src_mac(eth_src_mac), .eth_type(eth_type),
        .ip_version_ihl(ip_version_ihl), .ip_total_length(ip_total_length),
        .ip_protocol(ip_protocol), .ip_src_addr(ip_src_addr),
        .ip_dst_addr(ip_dst_addr), .l4_src_port(l4_src_port),
        .l4_dst_port(l4_dst_port), .tcp_flags(tcp_flags), .l4_length(l4_length),
        .payload_len(payload_len), .session_id(parser_sid_stub),
        .packet_type(packet_type),
        .out_valid(pb_valid), .out_sof(pb_sof), .out_eof(pb_eof), .out_data(pb_data)
    );

    // -------------------------------------------------------- session table
    wire [15:0] session_id;
    wire        sid_valid, sid_hit, sid_allocated, sid_evicted;

    session_lookup u_lookup (
        .clk(clk), .rst(rst_i),
        .hdr_valid(hdr_valid), .ip_src_addr(ip_src_addr), .packet_type(packet_type),
        .session_id(session_id), .sid_valid(sid_valid), .sid_hit(sid_hit),
        .sid_allocated(sid_allocated), .sid_evicted(sid_evicted),
        .clear_req(1'b0), .clear_id(16'd0)
    );

    wire         kem_done, kem_key_invalid;
    wire [15:0]  kem_session_id;
    wire [255:0] kem_shared_secret;

    wire         fr_lk_req, sm_lk_valid, sm_lk_ok;
    wire [15:0]  fr_lk_id;
    wire [255:0] sm_lk_key;
    wire [95:0]  sm_lk_nonce;
    wire [1:0]   sm_lk_state;
    wire         fr_nonce_adv;
    wire [15:0]  fr_nonce_adv_id;

    session_mgr u_sess (
        .clk(clk), .rst(rst_i),
        .kem_done(kem_done), .kem_session_id(kem_session_id),
        .kem_shared_secret(kem_shared_secret), .kem_key_invalid(kem_key_invalid),
        .lk_req(fr_lk_req), .lk_id(fr_lk_id),
        .lk_valid(sm_lk_valid), .lk_ok(sm_lk_ok), .lk_key(sm_lk_key),
        .lk_nonce(sm_lk_nonce), .lk_state(sm_lk_state),
        .nonce_adv(fr_nonce_adv), .nonce_adv_id(fr_nonce_adv_id)
    );

    // Any session up, for LD0. Set when a key is stored, cleared on a
    // structural rejection; this is display state, not a security decision.
    reg any_session_up;
    always @(posedge clk) begin
        if (rst_i)                 any_session_up <= 1'b0;
        else if (kem_key_invalid)  any_session_up <= 1'b0;
        else if (kem_done)         any_session_up <= 1'b1;
    end

    // ---------------------------------------------------------- ML-KEM lane
    wire         rng_valid, rng_take;
    wire [255:0] rng_data;

    entropy_src u_entropy (
        .clk(clk), .rst(rst_i),
        .jitter_strobe(rx_valid),
        .seed_load(1'b0), .seed_in(256'd0),
        .rng_valid(rng_valid), .rng_data(rng_data), .rng_take(rng_take)
    );

    // One KeyGen after reset so this board has a decapsulation key.
    reg        kg_start;
    reg [1:0]  kg_state;
    wire       kem_busy;
    always @(posedge clk) begin
        if (rst_i) begin
            kg_start <= 1'b0;
            kg_state <= 2'd0;
        end else begin
            kg_start <= 1'b0;
            case (kg_state)
                2'd0: if (!kem_busy) begin kg_start <= 1'b1; kg_state <= 2'd1; end
                2'd1: if (kem_busy)  kg_state <= 2'd2;        // accepted
                2'd2: if (!kem_busy) kg_state <= 2'd3;        // finished
                default: ;                                     // done forever
            endcase
        end
    end

    wire        v_kem_valid, v_kem_fail;
    wire [3:0]  v_kem_reason;
    wire        kem_pkt_dropped_busy;
    wire [63:0] dk_ram_rdata, c_ram_rdata;
    wire [6:0]  hs_c_rd_addr;

    mlkem_top u_kem (
        .clk(clk), .rst(rst_i),
        .packet_bus_valid(pb_valid), .packet_bus_sof(pb_sof),
        .packet_bus_eof(pb_eof), .packet_bus_data(pb_data),
        .packet_bus_payload_len(payload_len),
        .packet_bus_session_id(session_id),
        .packet_bus_packet_type(packet_type),
        .kem_done(kem_done), .kem_session_id(kem_session_id),
        .kem_shared_secret(kem_shared_secret), .kem_key_invalid(kem_key_invalid),
        .v_kem_valid(v_kem_valid), .v_kem_fail(v_kem_fail),
        .v_kem_reason(v_kem_reason),
        .cmd_start(kg_start), .cmd_op(2'b00), .cmd_session_id(16'd0),
        .seed_d(rng_data), .seed_z(~rng_data), .seed_m(256'd0),
        .busy(kem_busy),
        .rng_valid(rng_valid), .rng_data(rng_data), .rng_take(rng_take),
        .kem_pkt_dropped_busy(kem_pkt_dropped_busy),
        .dk_ram_rd_addr(8'd0), .dk_ram_rdata(dk_ram_rdata),
        .dk_ram_wr_en(1'b0), .dk_ram_wr_addr_ext(8'd0), .dk_ram_wr_data_ext(64'd0),
        .ek_ram_wr_en(1'b0), .ek_ram_wr_addr_ext(7'd0), .ek_ram_wr_data_ext(64'd0),
        .c_ram_rd_addr_ext(hs_c_rd_addr), .c_ram_rdata_ext(c_ram_rdata),
        .c_ram_wr_en(1'b0), .c_ram_wr_addr_ext(7'd0), .c_ram_wr_data_ext(64'd0)
    );

    // An Encaps triggered by an HS_INIT packet must send its ciphertext back.
    reg        pending_encaps;
    reg        hs_send_req;
    reg [47:0] hs_eth_src, hs_eth_dst;
    reg [31:0] hs_ip_src, hs_ip_dst;
    always @(posedge clk) begin
        if (rst_i) begin
            pending_encaps <= 1'b0;
            hs_send_req    <= 1'b0;
        end else begin
            hs_send_req <= 1'b0;
            if (hdr_valid && (packet_type == 2'b00)) begin
                pending_encaps <= 1'b1;
                hs_eth_src     <= eth_src_mac;
                hs_eth_dst     <= eth_dst_mac;
                hs_ip_src      <= ip_src_addr;
                hs_ip_dst      <= ip_dst_addr;
            end else if (kem_key_invalid) begin
                pending_encaps <= 1'b0;      // structural failure: nothing to send
            end else if (kem_done && pending_encaps) begin
                pending_encaps <= 1'b0;
                hs_send_req    <= 1'b1;
            end
        end
    end

    // ------------------------------------------------------------ AEAD lane
    wire         fr_key_valid, fr_ct_valid, fr_ct_sof, fr_ct_eof;
    wire [255:0] fr_key;
    wire [95:0]  fr_nonce;
    wire [127:0] fr_aad, fr_exp_tag;
    wire [4:0]   fr_aad_len;
    wire [7:0]   fr_ct_data;
    wire         cp_ready, cp_busy, cp_done;
    wire         cp_vpv, cp_vpf;
    wire [3:0]   cp_vpr;
    wire [127:0] cp_tag_out;
    wire         cp_tag_ok;
    wire         v_poly_valid, v_poly_fail;
    wire [3:0]   v_poly_reason;
    wire         fr_fifo_overflow, fr_no_session_drop, fr_cam_bypass;

    wire         pt_valid, pt_sof, pt_eof, pt_tag_ok, pt_tag_valid;
    wire [7:0]   pt_data;

    aead_framer u_framer (
        .clk(clk), .rst(rst_i),
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
        .fifo_overflow(fr_fifo_overflow), .no_session_drop(fr_no_session_drop),
        .cam_bypass(fr_cam_bypass)
    );

    chacha_poly u_cp (
        .clk(clk), .rst(rst_i),
        .key_valid(fr_key_valid), .key(fr_key), .nonce(fr_nonce),
        .aad_data(fr_aad), .aad_len(fr_aad_len),
        .ct_valid(fr_ct_valid), .ct_data(fr_ct_data),
        .ct_sof(fr_ct_sof), .ct_eof(fr_ct_eof), .expected_tag(fr_exp_tag),
        .ready(cp_ready), .busy(cp_busy), .done(cp_done),
        .pt_valid(pt_valid), .pt_data(pt_data), .pt_sof(pt_sof), .pt_eof(pt_eof),
        .pt_tag_ok(pt_tag_ok), .pt_tag_valid(pt_tag_valid),
        .v_poly_valid(cp_vpv), .v_poly_fail(cp_vpf), .v_poly_reason(cp_vpr),
        .tag_out(cp_tag_out), .tag_ok(cp_tag_ok)
    );

    // -------------------------------------------------------- detection lane
    wire       v_proto_valid, v_proto_fail;
    wire [3:0] v_proto_reason;

    protocol_validator u_proto (
        .clk(clk), .rst(rst_i),
        .header_valid(hdr_valid),
        .eth_type(eth_type), .ip_version_ihl(ip_version_ihl),
        .ip_protocol(ip_protocol), .ip_total_length(ip_total_length),
        .l4_src_port(l4_src_port), .l4_dst_port(l4_dst_port),
        .l4_length(l4_length), .tcp_flags(tcp_flags), .payload_len(payload_len),
        .verdict_valid(v_proto_valid), .verdict_fail(v_proto_fail),
        .verdict_reason(v_proto_reason)
    );

    wire        v_cms_valid, v_cms_fail, cms_ready;
    wire [3:0]  v_cms_reason;
    wire [15:0] cms_c_flow, cms_c_host;

    count_min_sketch u_cms (
        .clk(clk), .rst(rst_i),
        .header_valid(hdr_valid),
        .src_ip(ip_src_addr), .dst_ip(ip_dst_addr),
        .dst_port(l4_dst_port), .protocol(ip_protocol), .eof(pb_eof),
        .ready(cms_ready),
        .verdict_valid(v_cms_valid), .verdict_fail(v_cms_fail),
        .verdict_reason(v_cms_reason),
        .c_flow_out(cms_c_flow), .c_host_out(cms_c_host)
    );

    wire        cam_v_valid, cam_v_fail;
    wire [3:0]  cam_v_reason;
    wire [4:0]  cam_sig_id;
    wire [15:0] cam_offset;

    cam_matcher u_cam (
        .clk(clk), .rst(rst_i),
        .pt_valid(pt_valid), .pt_data(pt_data), .pt_sof(pt_sof), .pt_eof(pt_eof),
        .pt_tag_ok(pt_tag_ok), .pt_tag_valid(pt_tag_valid),
        .v_cam_valid(cam_v_valid), .v_cam_fail(cam_v_fail),
        .v_cam_reason(cam_v_reason),
        .match_sig_id(cam_sig_id), .match_offset(cam_offset)
    );

    // The CAM lane must report once per DATA packet or drop_engine never
    // commits it. cam_matcher only strobes when plaintext flowed, so a DATA
    // packet whose cipher never ran (no session, short payload, buffer
    // overrun) is covered by aead_framer's bypass, which is always a pass:
    // there was nothing to scan.
    wire       v_cam_valid  = cam_v_valid | fr_cam_bypass;
    wire       v_cam_fail   = cam_v_valid & cam_v_fail;
    wire [3:0] v_cam_reason = cam_v_valid ? cam_v_reason : `RC_NONE;

    // The link-layer lane. crc32.v has no verdict port; deframer.v emits one
    // verdict per frame carrying RC_CRC_FAIL, RC_FRAME_TIMEOUT or RC_MALFORMED.
    // A clean frame reports on v_crc_*, which is the lane drop_engine waits for;
    // a failing frame reports on v_deframe_*, which commits the packet
    // immediately and carries the lane's own reason code. Exactly one of the two
    // fires per frame, so a CRC failure is never counted twice.
    wire       v_crc_valid_i     = df_v_valid & ~df_v_fail;
    wire       v_deframe_valid_i = df_v_valid &  df_v_fail;

    // ----------------------------------------------------------- drop engine
    wire        drop_valid, drop_fail;
    wire [3:0]  drop_reason;
    wire [31:0] c_crc, c_to, c_mal, c_sig, c_fl, c_sc, c_bt, c_hki,
                c_drops, c_passed, c_lto, c_stray;

    drop_engine u_drop (
        .clk(clk), .rst(rst_i),
        // The packet window opens at hdr_valid, NOT at the first payload byte.
        // protocol_validator answers one cycle after the header and
        // count_min_sketch four, both of which are long before the payload
        // starts streaming (a whole byte-time later on the serial link). Opening
        // the window at the first payload byte made those two verdicts arrive
        // with no packet open, so they were discarded as strays and no DATA
        // packet could ever be committed.
        .pkt_sof(hdr_valid), .pkt_eof(pb_eof), .pkt_type(packet_type),
        .v_crc_valid(v_crc_valid_i), .v_crc_fail(1'b0), .v_crc_reason(`RC_NONE),
        .v_deframe_valid(v_deframe_valid_i), .v_deframe_fail(df_v_fail),
        .v_deframe_reason(df_v_code),
        .v_proto_valid(v_proto_valid), .v_proto_fail(v_proto_fail),
        .v_proto_reason(v_proto_reason),
        .v_cam_valid(v_cam_valid), .v_cam_fail(v_cam_fail),
        .v_cam_reason(v_cam_reason),
        .v_cms_valid(v_cms_valid), .v_cms_fail(v_cms_fail),
        .v_cms_reason(v_cms_reason),
        .v_poly_valid(v_poly_valid), .v_poly_fail(v_poly_fail),
        .v_poly_reason(v_poly_reason),
        .v_kem_valid(v_kem_valid), .v_kem_fail(v_kem_fail),
        .v_kem_reason(v_kem_reason),
        .drop_valid(drop_valid), .drop_fail(drop_fail), .drop_reason(drop_reason),
        .cnt_crc_fail(c_crc), .cnt_frame_timeout(c_to), .cnt_malformed(c_mal),
        .cnt_signature(c_sig), .cnt_flood(c_fl), .cnt_scan(c_sc),
        .cnt_bad_tag(c_bt), .cnt_handshake_key_invalid(c_hki),
        .cnt_total_drops(c_drops), .cnt_total_passed(c_passed),
        .cnt_lane_timeout(c_lto), .cnt_stray_verdict(c_stray)
    );

    // ------------------------------------------------------------------- I/O
    led_driver #(.CLK_HZ(CLK_HZ)) u_led (
        .clk(clk), .rst(rst_i),
        .drop_valid(drop_valid), .drop_fail(drop_fail), .drop_reason(drop_reason),
        .session_established(any_session_up),
        .led(led)
    );

    wire [7:0] hs_tx_data, tel_tx_data;
    wire       hs_tx_valid, tel_tx_valid, hs_busy;
    wire       tx_busy;
    wire       tx_done_unused;

    handshake_tx u_hs_tx (
        .clk(clk), .rst(rst_i),
        .send_req(hs_send_req),
        .rx_eth_src_mac(hs_eth_src), .rx_eth_dst_mac(hs_eth_dst),
        .rx_ip_src_addr(hs_ip_src), .rx_ip_dst_addr(hs_ip_dst),
        .c_ram_rd_addr(hs_c_rd_addr), .c_ram_rdata(c_ram_rdata),
        .tx_data(hs_tx_data), .tx_valid(hs_tx_valid), .tx_busy(tx_busy),
        .busy(hs_busy)
    );

    telemetry_tx #(.CLK_HZ(CLK_HZ)) u_tel (
        .clk(clk), .rst(rst_i),
        .cnt_crc_fail(c_crc), .cnt_frame_timeout(c_to), .cnt_malformed(c_mal),
        .cnt_signature(c_sig), .cnt_flood(c_fl), .cnt_scan(c_sc),
        .cnt_bad_tag(c_bt), .cnt_handshake_key_invalid(c_hki),
        .cnt_total_drops(c_drops), .cnt_total_passed(c_passed),
        .cnt_lane_timeout(c_lto), .cnt_stray_verdict(c_stray),
        .session_established(any_session_up),
        .fifo_overflow(fr_fifo_overflow), .kem_busy(kem_busy),
        // Held off while the ciphertext reply is going out, so a telemetry byte
        // can never be interleaved into the middle of a handshake frame.
        .tx_data(tel_tx_data), .tx_valid(tel_tx_valid), .tx_busy(tx_busy | hs_busy)
    );

    // handshake_tx wins the transmitter outright.
    wire [7:0] tx_mux_data  = hs_busy ? hs_tx_data  : tel_tx_data;
    wire       tx_mux_valid = hs_busy ? hs_tx_valid : tel_tx_valid;

    uart_tx #(.CLK_FREQ(CLK_HZ), .BAUD_RATE(BAUD_RATE)) u_uart_tx (
        .clk(clk), .rst(rst_i),
        .tx_data(tx_mux_data), .tx_valid(tx_mux_valid),
        .tx_pin(uart_tx_pin), .tx_busy(tx_busy), .tx_done(tx_done_unused)
    );

    // ---- signals observed only in simulation or reserved for the PS ----
    wire _unused_ok = &{1'b0, rst, rx_busy, rx_frame_err, parsed_ok,
                        parser_sid_stub, sid_valid, sid_hit, sid_allocated,
                        sid_evicted, sm_lk_state, cp_busy, cp_tag_out, cp_tag_ok,
                        cms_ready, cms_c_flow, cms_c_host, cam_sig_id, cam_offset,
                        dk_ram_rdata, kem_pkt_dropped_busy, fr_no_session_drop,
                        payload_len, tx_done_unused};

endmodule

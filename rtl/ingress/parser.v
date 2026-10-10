//==============================================================================
// rtl/ingress/parser.v
//
// Ingress Header Parser & Packet-Bus Multiplexer.
//
// Hardware Role:
//   Consumes deframed byte stream from deframer.v (in_valid, in_data, in_sof, in_eof).
//   Walks Ethernet -> IPv4 -> TCP/UDP headers and drives the parallel packet bus
//   (packet_bus_t in docs/Member A/interface_contract.md §3) to both processing lanes:
//     - Lane 1: Crypto Lane (mlkem_top.v, chacha_poly, session_mgr.v)
//     - Lane 2: Threat Lane (protocol_validator.v, count_min_sketch.v, cam_matcher.v)
//
// Standards & Specifications:
//   - docs/Member A/interface_contract.md (§3 Packet Bus, §4 Classification)
//   - model/pipeline.py (parse_headers bit-exact Python twin)
//   - rtl/control/reason_codes.vh
//
// Verilog Conventions (AGENTS.md §5):
//   - Verilog-2001, single 100 MHz clock domain (`clk`), synchronous reset (`rst`).
//   - Registered outputs, zero latches, no initial blocks in synthesizable code.
//
// Owner: Member A (Ingress, Parser, and Interface Contract)
//==============================================================================

`include "reason_codes.vh"

module parser (
    input  wire        clk,            // 100 MHz system clock
    input  wire        rst,            // Synchronous active-high reset

    // Input deframed byte stream from deframer.v
    input  wire        in_valid,       // Byte valid strobe
    input  wire [7:0]  in_data,        // Stream byte data
    input  wire        in_sof,         // Start of frame (Byte 0: Destination MAC MSB)
    input  wire        in_eof,         // End of frame (last byte of packet payload)

    // Header context strobe & status
    output reg         hdr_valid,      // 1-cycle strobe: headers parsed and fields latched
    output reg         parsed_ok,      // 1 = valid Ethernet/IPv4/TCP/UDP; 0 = malformed/unsupported

    // Parallel packet bus header context (packet_bus_t in interface_contract.md §3)
    output reg [47:0]  eth_dst_mac,    // Destination MAC (48 bits, big-endian)
    output reg [47:0]  eth_src_mac,    // Source MAC (48 bits, big-endian)
    output reg [15:0]  eth_type,       // EtherType (16 bits, 0x0800 = IPv4)

    output reg [7:0]   ip_version_ihl, // IP Version (4b) + IHL (4b); 0x45 expected
    output reg [15:0]  ip_total_length,// IPv4 Total Length in bytes (16 bits)
    output reg [7:0]   ip_protocol,    // Protocol (8 bits, 6=TCP, 17=UDP)
    output reg [31:0]  ip_src_addr,    // IPv4 Source Address (32 bits, big-endian)
    output reg [31:0]  ip_dst_addr,    // IPv4 Destination Address (32 bits, big-endian)

    output reg [15:0]  l4_src_port,    // TCP/UDP Source Port (16 bits, big-endian)
    output reg [15:0]  l4_dst_port,    // TCP/UDP Destination Port (16 bits, big-endian)
    output reg [7:0]   tcp_flags,      // TCP Flags (8 bits, 0x00 for UDP)
    output reg [15:0]  l4_length,      // TCP header length (bytes) or UDP length field

    output reg [15:0]  payload_len,    // Calculated payload length in bytes
    output reg [15:0]  session_id,     // Session ID from lookup (default 16'd0)
    output reg [1:0]   packet_type,    // Classification: 2'b00=EK, 2'b01=DATA, 2'b10=CT

    // Streaming payload bus (packet_bus_t streaming data)
    output reg         out_valid,      // Asserted for each valid payload byte cycle
    output reg         out_sof,        // Asserted on first payload byte cycle
    output reg         out_eof,        // Asserted on last payload byte cycle
    output reg  [7:0]  out_data        // Payload byte stream
);

    // Port Numbers (interface_contract.md §4)
    localparam PORT_HS_INIT = 16'd51001; // Handshake Initiator -> Responder: ek (800B)
    localparam PORT_HS_RESP = 16'd51002; // Handshake Responder -> Initiator: ct (768B)
    localparam PORT_DATA    = 16'd51010; // Established Session Data

    // Packet Types (interface_contract.md §4)
    localparam PKT_HANDSHAKE_EK = 2'b00;
    localparam PKT_DATA         = 2'b01;
    localparam PKT_HANDSHAKE_CT = 2'b10;

    // FSM State Encoding
    localparam STATE_IDLE      = 4'd0;
    localparam STATE_ETH       = 4'd1;
    localparam STATE_IP        = 4'd2;
    localparam STATE_IP_OPT    = 4'd3;
    localparam STATE_TCP       = 4'd4;
    localparam STATE_TCP_OPT   = 4'd5;
    localparam STATE_UDP       = 4'd6;
    localparam STATE_PAYLOAD   = 4'd7;
    localparam STATE_DRAIN     = 4'd8;

    reg [3:0]  state;

    // Sub-header index and option counters
    reg [5:0]  byte_sub_idx;
    reg [5:0]  opt_remaining;
    reg [3:0]  ip_ihl_reg;
    reg [3:0]  tcp_offset_reg;
    reg [15:0] total_bytes_seen;
    reg [15:0] payload_bytes_sent;

    // Combinational helper wires
    wire [15:0] eth_type_comb = {eth_type[15:8], in_data};
    wire [15:0] ip_ihl_bytes  = {10'd0, ip_ihl_reg, 2'b00};
    wire [15:0] tcp_hdr_bytes = {10'd0, tcp_offset_reg, 2'b00};
    wire [15:0] udp_len_comb  = {l4_length[15:8], in_data};

    always @(posedge clk) begin
        if (rst) begin
            state              <= STATE_IDLE;
            byte_sub_idx       <= 6'd0;
            opt_remaining      <= 6'd0;
            ip_ihl_reg         <= 4'd0;
            tcp_offset_reg     <= 4'd0;
            total_bytes_seen   <= 16'd0;
            payload_bytes_sent <= 16'd0;

            hdr_valid          <= 1'b0;
            parsed_ok          <= 1'b0;

            eth_dst_mac        <= 48'd0;
            eth_src_mac        <= 48'd0;
            eth_type           <= 16'd0;

            ip_version_ihl     <= 8'd0;
            ip_total_length    <= 16'd0;
            ip_protocol        <= 8'd0;
            ip_src_addr        <= 32'd0;
            ip_dst_addr        <= 32'd0;

            l4_src_port        <= 16'd0;
            l4_dst_port        <= 16'd0;
            tcp_flags          <= 8'd0;
            l4_length          <= 16'd0;

            payload_len        <= 16'd0;
            session_id         <= 16'd0;
            packet_type        <= PKT_DATA;

            out_valid          <= 1'b0;
            out_sof            <= 1'b0;
            out_eof            <= 1'b0;
            out_data           <= 8'd0;
        end else begin
            // Default 1-cycle output strobes
            hdr_valid <= 1'b0;
            out_valid <= 1'b0;
            out_sof   <= 1'b0;
            out_eof   <= 1'b0;

            // Global frame start recovery: any valid in_sof immediately resets FSM
            if (in_valid && in_sof) begin
                byte_sub_idx       <= 6'd1; // First byte (index 0) captured now
                total_bytes_seen   <= 16'd1;
                payload_bytes_sent <= 16'd0;
                parsed_ok          <= 1'b1;

                eth_dst_mac[47:40] <= in_data;
                eth_dst_mac[39:0]  <= 40'd0;
                eth_src_mac        <= 48'd0;
                eth_type           <= 16'd0;

                ip_version_ihl     <= 8'd0;
                ip_total_length    <= 16'd0;
                ip_protocol        <= 8'd0;
                ip_src_addr        <= 32'd0;
                ip_dst_addr        <= 32'd0;

                l4_src_port        <= 16'd0;
                l4_dst_port        <= 16'd0;
                tcp_flags          <= 8'd0;
                l4_length          <= 16'd0;

                payload_len        <= 16'd0;
                session_id         <= 16'd0;
                packet_type        <= PKT_DATA;

                if (in_eof) begin
                    // 1-byte truncated frame
                    parsed_ok <= 1'b0;
                    hdr_valid <= 1'b1;
                    state     <= STATE_IDLE;
                end else begin
                    state <= STATE_ETH;
                end
            end else if (in_valid) begin
                total_bytes_seen <= total_bytes_seen + 16'd1;

                case (state)
                    STATE_IDLE: begin
                        // Awaiting in_sof
                    end

                    //----------------------------------------------------------
                    // Ethernet Header (14 bytes, sub-indices 1..13)
                    //----------------------------------------------------------
                    STATE_ETH: begin
                        case (byte_sub_idx)
                            6'd1:  eth_dst_mac[39:32] <= in_data;
                            6'd2:  eth_dst_mac[31:24] <= in_data;
                            6'd3:  eth_dst_mac[23:16] <= in_data;
                            6'd4:  eth_dst_mac[15:8]  <= in_data;
                            6'd5:  eth_dst_mac[7:0]   <= in_data;
                            6'd6:  eth_src_mac[47:40] <= in_data;
                            6'd7:  eth_src_mac[39:32] <= in_data;
                            6'd8:  eth_src_mac[31:24] <= in_data;
                            6'd9:  eth_src_mac[23:16] <= in_data;
                            6'd10: eth_src_mac[15:8]  <= in_data;
                            6'd11: eth_src_mac[7:0]   <= in_data;
                            6'd12: eth_type[15:8]    <= in_data;
                            6'd13: eth_type[7:0]     <= in_data;
                            default: ;
                        endcase

                        if (in_eof && byte_sub_idx < 6'd13) begin
                            // Truncated mid-Ethernet header (<14B)
                            parsed_ok <= 1'b0;
                            hdr_valid <= 1'b1;
                            state     <= STATE_IDLE;
                        end else if (byte_sub_idx == 6'd13) begin
                            if (in_eof) begin
                                // Truncated: ended at Ethernet header, no IPv4
                                parsed_ok <= 1'b0;
                                hdr_valid <= 1'b1;
                                state     <= STATE_IDLE;
                            end else if (eth_type_comb == 16'h0800) begin
                                byte_sub_idx <= 6'd0;
                                state        <= STATE_IP;
                            end else begin
                                // Non-IPv4 frame (ARP, IPv6, LLDP, etc.) -> RC_MALFORMED
                                parsed_ok <= 1'b0;
                                hdr_valid <= 1'b1;
                                state     <= STATE_DRAIN;
                            end
                        end else begin
                            byte_sub_idx <= byte_sub_idx + 6'd1;
                        end
                    end

                    //----------------------------------------------------------
                    // IPv4 Header (20 bytes when IHL=5, sub-indices 0..19)
                    //----------------------------------------------------------
                    STATE_IP: begin
                        case (byte_sub_idx)
                            6'd0: begin
                                ip_version_ihl <= in_data;
                                ip_ihl_reg     <= in_data[3:0];
                                if (in_data[7:4] != 4'd4 || in_data[3:0] != 4'd5) begin
                                    parsed_ok <= 1'b0; // Bad version or IPv4 options present
                                end
                            end
                            6'd1:  ; // TOS / DSCP
                            6'd2:  ip_total_length[15:8] <= in_data;
                            6'd3:  ip_total_length[7:0]  <= in_data;
                            6'd4:  ; // Identification [15:8]
                            6'd5:  ; // Identification [7:0]
                            6'd6:  ; // Flags & Fragment Offset [15:8]
                            6'd7:  ; // Flags & Fragment Offset [7:0]
                            6'd8:  ; // TTL
                            6'd9: begin
                                ip_protocol <= in_data;
                                if (in_data != 8'd6 && in_data != 8'd17) begin
                                    parsed_ok <= 1'b0; // Unsupported L4 protocol (ICMP, IGMP, GRE)
                                end
                            end
                            6'd10: ; // Header Checksum [15:8]
                            6'd11: ; // Header Checksum [7:0]
                            6'd12: ip_src_addr[31:24] <= in_data;
                            6'd13: ip_src_addr[23:16] <= in_data;
                            6'd14: ip_src_addr[15:8]  <= in_data;
                            6'd15: ip_src_addr[7:0]   <= in_data;
                            6'd16: ip_dst_addr[31:24] <= in_data;
                            6'd17: ip_dst_addr[23:16] <= in_data;
                            6'd18: ip_dst_addr[15:8]  <= in_data;
                            6'd19: ip_dst_addr[7:0]   <= in_data;
                            default: ;
                        endcase

                        if (in_eof && byte_sub_idx < 6'd19) begin
                            // Truncated mid-IPv4 header (<34B)
                            parsed_ok <= 1'b0;
                            hdr_valid <= 1'b1;
                            state     <= STATE_IDLE;
                        end else if (byte_sub_idx == 6'd19) begin
                            if (in_eof) begin
                                // Truncated: ended at IPv4 header, missing L4
                                parsed_ok <= 1'b0;
                                hdr_valid <= 1'b1;
                                state     <= STATE_IDLE;
                            end else begin
                                byte_sub_idx <= 6'd0;
                                if (ip_ihl_reg > 4'd5) begin
                                    // IPv4 Options present -> drain options
                                    opt_remaining <= (ip_ihl_reg - 4'd5) * 4'd4 - 6'd1;
                                    state         <= STATE_IP_OPT;
                                end else if (ip_protocol == 8'd6) begin
                                    state <= STATE_TCP;
                                end else if (ip_protocol == 8'd17) begin
                                    state <= STATE_UDP;
                                end else begin
                                    // Unsupported L4 protocol
                                    parsed_ok <= 1'b0;
                                    hdr_valid <= 1'b1;
                                    state     <= STATE_DRAIN;
                                end
                            end
                        end else begin
                            byte_sub_idx <= byte_sub_idx + 6'd1;
                        end
                    end

                    //----------------------------------------------------------
                    // IPv4 Options Skip
                    //----------------------------------------------------------
                    STATE_IP_OPT: begin
                        if (in_eof && opt_remaining > 6'd0) begin
                            parsed_ok <= 1'b0;
                            hdr_valid <= 1'b1;
                            state     <= STATE_IDLE;
                        end else if (opt_remaining == 6'd0) begin
                            if (in_eof) begin
                                parsed_ok <= 1'b0;
                                hdr_valid <= 1'b1;
                                state     <= STATE_IDLE;
                            end else begin
                                byte_sub_idx <= 6'd0;
                                if (ip_protocol == 8'd6) begin
                                    state <= STATE_TCP;
                                end else if (ip_protocol == 8'd17) begin
                                    state <= STATE_UDP;
                                end else begin
                                    hdr_valid <= 1'b1;
                                    state     <= STATE_DRAIN;
                                end
                            end
                        end else begin
                            opt_remaining <= opt_remaining - 6'd1;
                        end
                    end

                    //----------------------------------------------------------
                    // TCP Header (20 bytes base, sub-indices 0..19)
                    //----------------------------------------------------------
                    STATE_TCP: begin
                        case (byte_sub_idx)
                            6'd0:  l4_src_port[15:8] <= in_data;
                            6'd1:  l4_src_port[7:0]  <= in_data;
                            6'd2:  l4_dst_port[15:8] <= in_data;
                            6'd3:  l4_dst_port[7:0]  <= in_data;
                            6'd4:  ; // Sequence Number [31:24]
                            6'd5:  ; // Sequence Number [23:16]
                            6'd6:  ; // Sequence Number [15:8]
                            6'd7:  ; // Sequence Number [7:0]
                            6'd8:  ; // Ack Number [31:24]
                            6'd9:  ; // Ack Number [23:16]
                            6'd10: ; // Ack Number [15:8]
                            6'd11: ; // Ack Number [7:0]
                            6'd12: begin
                                tcp_offset_reg <= in_data[7:4];
                                l4_length      <= {10'd0, in_data[7:4], 2'b00};
                                if (in_data[7:4] < 4'd5) begin
                                    parsed_ok <= 1'b0; // Malformed TCP Data Offset (<5)
                                end
                            end
                            6'd13: tcp_flags <= in_data;
                            6'd14: ; // Window Size [15:8]
                            6'd15: ; // Window Size [7:0]
                            6'd16: ; // Checksum [15:8]
                            6'd17: ; // Checksum [7:0]
                            6'd18: ; // Urgent Pointer [15:8]
                            6'd19: ; // Urgent Pointer [7:0]
                            default: ;
                        endcase

                        if (in_eof && byte_sub_idx < 6'd19) begin
                            // Truncated mid-TCP header (<54B)
                            parsed_ok <= 1'b0;
                            hdr_valid <= 1'b1;
                            state     <= STATE_IDLE;
                        end else if (byte_sub_idx == 6'd19) begin
                            if (tcp_offset_reg > 4'd5) begin
                                // TCP Options present
                                if (in_eof) begin
                                    parsed_ok <= 1'b0;
                                    hdr_valid <= 1'b1;
                                    state     <= STATE_IDLE;
                                end else begin
                                    opt_remaining <= (tcp_offset_reg - 4'd5) * 4'd4 - 6'd1;
                                    state         <= STATE_TCP_OPT;
                                end
                            end else begin
                                // Base TCP header complete: latch context & classify
                                hdr_valid <= 1'b1;

                                // Port-based classification (interface_contract.md §4)
                                if (l4_dst_port == PORT_HS_INIT)
                                    packet_type <= PKT_HANDSHAKE_EK;
                                else if (l4_dst_port == PORT_HS_RESP)
                                    packet_type <= PKT_HANDSHAKE_CT;
                                else
                                    packet_type <= PKT_DATA;

                                // Payload length calculation
                                if (ip_total_length >= (ip_ihl_bytes + 16'd20)) begin
                                    payload_len <= ip_total_length - ip_ihl_bytes - 16'd20;
                                    if (in_eof) begin
                                        if (ip_total_length > (ip_ihl_bytes + 16'd20)) begin
                                            parsed_ok <= 1'b0; // Truncated payload
                                        end
                                        state <= STATE_IDLE;
                                    end else if (ip_total_length == (ip_ihl_bytes + 16'd20)) begin
                                        state <= STATE_DRAIN; // Zero payload, drain padding
                                    end else begin
                                        state <= STATE_PAYLOAD;
                                    end
                                end else begin
                                    payload_len <= 16'd0;
                                    parsed_ok   <= 1'b0;
                                    if (in_eof)
                                        state <= STATE_IDLE;
                                    else
                                        state <= STATE_DRAIN;
                                end
                            end
                        end else begin
                            byte_sub_idx <= byte_sub_idx + 6'd1;
                        end
                    end

                    //----------------------------------------------------------
                    // TCP Options Skip (up to tcp_offset * 4)
                    //----------------------------------------------------------
                    STATE_TCP_OPT: begin
                        if (in_eof && opt_remaining > 6'd0) begin
                            parsed_ok <= 1'b0;
                            hdr_valid <= 1'b1;
                            state     <= STATE_IDLE;
                        end else if (opt_remaining == 6'd0) begin
                            hdr_valid <= 1'b1;

                            if (l4_dst_port == PORT_HS_INIT)
                                packet_type <= PKT_HANDSHAKE_EK;
                            else if (l4_dst_port == PORT_HS_RESP)
                                packet_type <= PKT_HANDSHAKE_CT;
                            else
                                packet_type <= PKT_DATA;

                            if (ip_total_length >= (ip_ihl_bytes + tcp_hdr_bytes)) begin
                                payload_len <= ip_total_length - ip_ihl_bytes - tcp_hdr_bytes;
                                if (in_eof) begin
                                    if (ip_total_length > (ip_ihl_bytes + tcp_hdr_bytes)) begin
                                        parsed_ok <= 1'b0;
                                    end
                                    state <= STATE_IDLE;
                                end else if (ip_total_length == (ip_ihl_bytes + tcp_hdr_bytes)) begin
                                    state <= STATE_DRAIN;
                                end else begin
                                    state <= STATE_PAYLOAD;
                                end
                            end else begin
                                payload_len <= 16'd0;
                                parsed_ok   <= 1'b0;
                                if (in_eof)
                                    state <= STATE_IDLE;
                                else
                                    state <= STATE_DRAIN;
                            end
                        end else begin
                            opt_remaining <= opt_remaining - 6'd1;
                        end
                    end

                    //----------------------------------------------------------
                    // UDP Header (8 bytes, sub-indices 0..7)
                    //----------------------------------------------------------
                    STATE_UDP: begin
                        case (byte_sub_idx)
                            6'd0: l4_src_port[15:8] <= in_data;
                            6'd1: l4_src_port[7:0]  <= in_data;
                            6'd2: l4_dst_port[15:8] <= in_data;
                            6'd3: l4_dst_port[7:0]  <= in_data;
                            6'd4: l4_length[15:8]   <= in_data;
                            6'd5: begin
                                l4_length[7:0] <= in_data;
                                if (udp_len_comb < 16'd8) begin
                                    parsed_ok <= 1'b0; // Malformed UDP Length (<8)
                                end
                            end
                            6'd6: ; // Checksum [15:8]
                            6'd7: ; // Checksum [7:0]
                            default: ;
                        endcase
                        tcp_flags <= 8'h00;

                        if (in_eof && byte_sub_idx < 6'd7) begin
                            // Truncated mid-UDP header (<42B)
                            parsed_ok <= 1'b0;
                            hdr_valid <= 1'b1;
                            state     <= STATE_IDLE;
                        end else if (byte_sub_idx == 6'd7) begin
                            // UDP Header complete: latch context & classify
                            hdr_valid <= 1'b1;

                            if (l4_dst_port == PORT_HS_INIT)
                                packet_type <= PKT_HANDSHAKE_EK;
                            else if (l4_dst_port == PORT_HS_RESP)
                                packet_type <= PKT_HANDSHAKE_CT;
                            else
                                packet_type <= PKT_DATA;

                            if (ip_total_length < (ip_ihl_bytes + 16'd8) || l4_length < 16'd8) begin
                                payload_len <= 16'd0;
                                parsed_ok   <= 1'b0;
                                if (in_eof)
                                    state <= STATE_IDLE;
                                else
                                    state <= STATE_DRAIN;
                            end else begin
                                payload_len <= l4_length - 16'd8;
                                if (in_eof) begin
                                    if (l4_length > 16'd8) begin
                                        parsed_ok <= 1'b0; // Truncated payload
                                    end
                                    state <= STATE_IDLE;
                                end else if (l4_length == 16'd8) begin
                                    state <= STATE_DRAIN; // Zero payload, drain padding
                                end else begin
                                    state <= STATE_PAYLOAD;
                                end
                            end
                        end else begin
                            byte_sub_idx <= byte_sub_idx + 6'd1;
                        end
                    end

                    //----------------------------------------------------------
                    // Payload Streaming (packet_bus_t data stream)
                    //----------------------------------------------------------
                    STATE_PAYLOAD: begin
                        out_valid          <= 1'b1;
                        out_data           <= in_data;
                        out_sof            <= (payload_bytes_sent == 16'd0);
                        out_eof            <= in_eof || (payload_bytes_sent == payload_len - 16'd1);
                        payload_bytes_sent <= payload_bytes_sent + 16'd1;

                        if (in_eof) begin
                            if (payload_bytes_sent + 16'd1 < payload_len) begin
                                parsed_ok <= 1'b0; // Truncated payload
                            end
                            state <= STATE_IDLE;
                        end else if (payload_bytes_sent == payload_len - 16'd1) begin
                            // All claimed payload bytes sent; drain any trailing padding
                            state <= STATE_DRAIN;
                        end
                    end

                    //----------------------------------------------------------
                    // Drain unparsed bytes or trailing Ethernet padding
                    //----------------------------------------------------------
                    STATE_DRAIN: begin
                        if (in_eof) begin
                            state <= STATE_IDLE;
                        end
                    end

                    default: begin
                        state <= STATE_IDLE;
                    end
                endcase
            end
        end
    end

endmodule

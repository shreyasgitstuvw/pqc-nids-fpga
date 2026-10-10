//=============================================================================
// rtl/detect/protocol_validator.v
//
// Threat Detection Lane (Lane 2) -- Header Sanity & Protocol Validator
//
// Bit-exact Verilog-2001 hardware implementation of model/detect.py
// (validate_protocol function).
//
// Inspects packet header fields presented on the parallel packet bus in
// 1 clock cycle:
//   - Rule 1: EtherType == 16'h0800 (IPv4 only; ARP, IPv6, 802.1Q rejected)
//   - Rule 2: IPv4 Version == 4 and IHL == 5 (ip_version_ihl == 8'h45; options rejected)
//   - Rule 3: IP Protocol in {6 (TCP), 17 (UDP)} (ICMP, IGMP, etc. rejected)
//   - Rule 4: Reserved Port 0 rejection (l4_src_port != 0 and l4_dst_port != 0)
//   - Rule 5: TCP Flag Sanitization (SYN+FIN, SYN+RST, NULL scan, FIN without ACK)
//   - Rule 6: Header & datagram length consistency (minimums & arithmetic sum)
//
// Target: ZedBoard, Xilinx Zynq-7000 XC7Z020 @ 100 MHz
// Latency: Exactly 1 clock cycle after header_valid strobe
// Output: Strobe-based verdict to drop_engine.v (RC_MALFORMED = 4'h3 or RC_NONE = 4'h0)
//
// Owner: Member B
// Reference: docs/Member A/interface_contract.md Sec 3, Sec 6
//            rtl/control/reason_codes.vh
//=============================================================================

`timescale 1ns / 1ps
`include "reason_codes.vh"

// =====================================================================
// START OF SECTION 1: MODULE DECLARATION & PORT LIST
// =====================================================================

module protocol_validator (
    input  wire        clk,
    input  wire        rst,

    input  wire        header_valid,
    input  wire [15:0] eth_type,
    input  wire [7:0]  ip_version_ihl,
    input  wire [7:0]  ip_protocol,
    input  wire [15:0] ip_total_length,
    input  wire [15:0] l4_src_port,
    input  wire [15:0] l4_dst_port,
    input  wire [15:0] l4_length,
    input  wire [7:0]  tcp_flags,
    input  wire [15:0] payload_len,

    output reg         verdict_valid,
    output reg         verdict_fail,
    output reg  [3:0]  verdict_reason
);

// =====================================================================
// START OF SECTION 2: PROTOCOL CONSTANTS & SIGNAL UNPACKING
// =====================================================================

    localparam [15:0] ETHERTYPE_IPV4     = 16'h0800;

    localparam [3:0]  IPV4_VERSION_REQ   = 4'd4;
    localparam [3:0]  IPV4_IHL_REQ       = 4'd5;
    localparam [7:0]  IPV4_VER_IHL_REQ   = {IPV4_VERSION_REQ, IPV4_IHL_REQ};
    localparam [15:0] IPV4_MIN_TOTAL_LEN = 16'd20;

    localparam [7:0]  IP_PROTO_TCP       = 8'd6;
    localparam [7:0]  IP_PROTO_UDP       = 8'd17;

    localparam [15:0] UDP_MIN_HEADER_LEN = 16'd8;
    localparam [15:0] TCP_MIN_HEADER_LEN = 16'd20;

    wire is_tcp = (ip_protocol == IP_PROTO_TCP);
    wire is_udp = (ip_protocol == IP_PROTO_UDP);

    wire flag_fin = tcp_flags[0];
    wire flag_syn = tcp_flags[1];
    wire flag_rst = tcp_flags[2];
    wire flag_ack = tcp_flags[4];
    wire [5:0] ctrl_flags = tcp_flags[5:0];

    /* verilator lint_off UNUSED */
    wire [1:0] _unused_tcp_flags = tcp_flags[7:6];
    /* verilator lint_on UNUSED */

// =====================================================================
// START OF SECTION 3: COMBINATIONAL VALIDATION RULES (RULES 1 TO 6)
// =====================================================================

    // Rule 1: EtherType Sanitization (IPv4 only)
    wire rule1_fail = (eth_type != ETHERTYPE_IPV4);

    // Rule 2: IPv4 Version & IHL Sanitization (Version 4, IHL 5, no options)
    wire rule2_fail = (ip_version_ihl != IPV4_VER_IHL_REQ);

    // Rule 3: Supported Protocol Filter (TCP or UDP only)
    wire rule3_fail = (!is_tcp && !is_udp);

    // Rule 4: Reserved Port 0 Rejection
    wire rule4_fail = (l4_src_port == 16'd0) || (l4_dst_port == 16'd0);

    // Rule 5: TCP Control Flag Sanitization
    wire tcp_syn_fin_invalid = flag_syn && flag_fin;
    wire tcp_syn_rst_invalid = flag_syn && flag_rst;
    wire tcp_null_scan       = (ctrl_flags == 6'd0);
    wire tcp_fin_no_ack      = flag_fin && !flag_ack;

    wire rule5_fail = is_tcp && (
        tcp_syn_fin_invalid ||
        tcp_syn_rst_invalid ||
        tcp_null_scan       ||
        tcp_fin_no_ack
    );

    // Rule 6: Header & Total Length Consistency Checks
    wire [16:0] expected_total = 17'd20 + {1'b0, l4_length} + {1'b0, payload_len};

    wire len_too_short_ip  = (ip_total_length < IPV4_MIN_TOTAL_LEN);
    wire len_too_short_udp = is_udp && (l4_length < UDP_MIN_HEADER_LEN);
    wire len_too_short_tcp = is_tcp && (l4_length < TCP_MIN_HEADER_LEN);
    wire len_sum_mismatch  = ({1'b0, ip_total_length} != expected_total);

    wire rule6_fail = len_too_short_ip  ||
                      len_too_short_udp ||
                      len_too_short_tcp ||
                      len_sum_mismatch;

// =====================================================================
// START OF SECTION 4: FAULT AGGREGATION & REASON CODE GENERATION
// =====================================================================

    wire any_rule_fail = rule1_fail |
                         rule2_fail |
                         rule3_fail |
                         rule4_fail |
                         rule5_fail |
                         rule6_fail;

    wire [3:0] next_reason = any_rule_fail ? `RC_MALFORMED : `RC_NONE;

// =====================================================================
// START OF SECTION 5: SYNCHRONOUS OUTPUT REGISTERING & RESET LOGIC
// =====================================================================

    always @(posedge clk) begin
        if (rst) begin
            verdict_valid  <= 1'b0;
            verdict_fail   <= 1'b0;
            verdict_reason <= `RC_NONE;
        end else begin
            verdict_valid <= header_valid;

            if (header_valid) begin
                verdict_fail   <= any_rule_fail;
                verdict_reason <= next_reason;
            end else begin
                verdict_fail   <= 1'b0;
                verdict_reason <= `RC_NONE;
            end
        end
    end

endmodule

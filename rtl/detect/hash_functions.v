// ============================================================================
// Module: hash_functions
// Description: Parallel 2-Universal Hash Generators for Dual Count-Min Sketch
//   3-stage pipeline (3-cycle latency, 1 result per cycle). The original single
//   stage was parser reg -> 16x32 multiply -> xor -> 32x32 multiply -> add in
//   one 10 ns cycle (15.8 ns routed). Now:
//     S1: port_diffused = port * PORT_DIFFUSER           (registered)
//     S2: key = src_ip ^ port_diffused; partial products (registered)
//           A*key mod 2^32 = A*key[15:0] + ((A[15:0]*key[31:16]) mod 2^16) << 16
//     S3: sum partials + B, take the index bits           (registered)
// Target: ZedBoard XC7Z020 @ 100 MHz
// Owner: Member B (Lane 2 - Threat Detection)
// Bit-exact with model/detect.py (Section 2 & Section 4)
// ============================================================================

`timescale 1ns / 1ps

// ============================================================================
// SECTION 1: Module Declaration and Port Definitions
// ============================================================================
module hash_functions (
    input  wire        clk,
    input  wire        rst,
    input  wire        in_valid,
    input  wire [31:0] src_ip,
    input  wire [15:0] dst_port,
    output wire        pending,    // 1 while a packet is inside stages 1-2
    output reg         out_valid,
    output reg  [10:0] flow_idx_0,
    output reg  [10:0] flow_idx_1,
    output reg  [10:0] flow_idx_2,
    output reg  [10:0] flow_idx_3,
    output reg  [9:0]  host_idx_0,
    output reg  [9:0]  host_idx_1,
    output reg  [9:0]  host_idx_2,
    output reg  [9:0]  host_idx_3
);

// ============================================================================
// SECTION 2: Hash Seeds and Multiplier Constants
// ============================================================================
localparam [31:0] PORT_DIFFUSER = 32'h85EBCA6B;

localparam [31:0] FLOW_A_0      = 32'h5BD1E995;
localparam [31:0] FLOW_B_0      = 32'h1B873593;
localparam [31:0] FLOW_A_1      = 32'h85EBCA6B;
localparam [31:0] FLOW_B_1      = 32'h48BB74C5;
localparam [31:0] FLOW_A_2      = 32'hC2B2AE35;
localparam [31:0] FLOW_B_2      = 32'h9E3779B9;
localparam [31:0] FLOW_A_3      = 32'h7FEB352D;
localparam [31:0] FLOW_B_3      = 32'h27D4EB2F;

localparam [31:0] HOST_A_0      = 32'h21F0AAAD;
localparam [31:0] HOST_B_0      = 32'h7322F225;
localparam [31:0] HOST_A_1      = 32'h3B643793;
localparam [31:0] HOST_B_1      = 32'h1A23D457;
localparam [31:0] HOST_A_2      = 32'h992B5F1B;
localparam [31:0] HOST_B_2      = 32'h5678ABCD;
localparam [31:0] HOST_A_3      = 32'h4C871A31;
localparam [31:0] HOST_B_3      = 32'h9ABCDEF1;

// ============================================================================
// SECTION 3: Pipeline Stage 1 -- port diffusion
// ============================================================================
reg        v1;
reg [31:0] src_q1;
reg [31:0] pd_q1;

wire [31:0] port_ext = {16'h0000, dst_port};
wire [31:0] port_diffused = port_ext * PORT_DIFFUSER;

always @(posedge clk) begin
    if (rst) begin
        v1     <= 1'b0;
        src_q1 <= 32'd0;
        pd_q1  <= 32'd0;
    end else begin
        v1     <= in_valid;
        src_q1 <= src_ip;
        pd_q1  <= port_diffused;
    end
end

// ============================================================================
// SECTION 4: Pipeline Stage 2 -- keys and partial products
// ============================================================================
wire [31:0] flow_key = src_q1 ^ pd_q1;
wire [31:0] host_key = src_q1;

// A*key (mod 2^32) = A*key[15:0] + (((A[15:0]*key[31:16]) mod 2^16) << 16)
wire [31:0] fl_lo_0 = FLOW_A_0 * flow_key[15:0];
wire [31:0] fl_lo_1 = FLOW_A_1 * flow_key[15:0];
wire [31:0] fl_lo_2 = FLOW_A_2 * flow_key[15:0];
wire [31:0] fl_lo_3 = FLOW_A_3 * flow_key[15:0];
wire [31:0] fl_hi_0 = FLOW_A_0[15:0] * flow_key[31:16];
wire [31:0] fl_hi_1 = FLOW_A_1[15:0] * flow_key[31:16];
wire [31:0] fl_hi_2 = FLOW_A_2[15:0] * flow_key[31:16];
wire [31:0] fl_hi_3 = FLOW_A_3[15:0] * flow_key[31:16];

wire [31:0] ht_lo_0 = HOST_A_0 * host_key[15:0];
wire [31:0] ht_lo_1 = HOST_A_1 * host_key[15:0];
wire [31:0] ht_lo_2 = HOST_A_2 * host_key[15:0];
wire [31:0] ht_lo_3 = HOST_A_3 * host_key[15:0];
wire [31:0] ht_hi_0 = HOST_A_0[15:0] * host_key[31:16];
wire [31:0] ht_hi_1 = HOST_A_1[15:0] * host_key[31:16];
wire [31:0] ht_hi_2 = HOST_A_2[15:0] * host_key[31:16];
wire [31:0] ht_hi_3 = HOST_A_3[15:0] * host_key[31:16];

reg        v2;
reg [31:0] p_fl_lo_0, p_fl_lo_1, p_fl_lo_2, p_fl_lo_3;
reg [15:0] p_fl_hi_0, p_fl_hi_1, p_fl_hi_2, p_fl_hi_3;
reg [31:0] p_ht_lo_0, p_ht_lo_1, p_ht_lo_2, p_ht_lo_3;
reg [15:0] p_ht_hi_0, p_ht_hi_1, p_ht_hi_2, p_ht_hi_3;

always @(posedge clk) begin
    if (rst) v2 <= 1'b0;
    else     v2 <= v1;

    p_fl_lo_0 <= fl_lo_0;  p_fl_hi_0 <= fl_hi_0[15:0];
    p_fl_lo_1 <= fl_lo_1;  p_fl_hi_1 <= fl_hi_1[15:0];
    p_fl_lo_2 <= fl_lo_2;  p_fl_hi_2 <= fl_hi_2[15:0];
    p_fl_lo_3 <= fl_lo_3;  p_fl_hi_3 <= fl_hi_3[15:0];
    p_ht_lo_0 <= ht_lo_0;  p_ht_hi_0 <= ht_hi_0[15:0];
    p_ht_lo_1 <= ht_lo_1;  p_ht_hi_1 <= ht_hi_1[15:0];
    p_ht_lo_2 <= ht_lo_2;  p_ht_hi_2 <= ht_hi_2[15:0];
    p_ht_lo_3 <= ht_lo_3;  p_ht_hi_3 <= ht_hi_3[15:0];
end

assign pending = v1 | v2;

// ============================================================================
// SECTION 5: Pipeline Stage 3 -- sum, add seed, take index bits
// ============================================================================
wire [31:0] flow_val_0 = p_fl_lo_0 + {p_fl_hi_0, 16'h0000} + FLOW_B_0;
wire [31:0] flow_val_1 = p_fl_lo_1 + {p_fl_hi_1, 16'h0000} + FLOW_B_1;
wire [31:0] flow_val_2 = p_fl_lo_2 + {p_fl_hi_2, 16'h0000} + FLOW_B_2;
wire [31:0] flow_val_3 = p_fl_lo_3 + {p_fl_hi_3, 16'h0000} + FLOW_B_3;

wire [31:0] host_val_0 = p_ht_lo_0 + {p_ht_hi_0, 16'h0000} + HOST_B_0;
wire [31:0] host_val_1 = p_ht_lo_1 + {p_ht_hi_1, 16'h0000} + HOST_B_1;
wire [31:0] host_val_2 = p_ht_lo_2 + {p_ht_hi_2, 16'h0000} + HOST_B_2;
wire [31:0] host_val_3 = p_ht_lo_3 + {p_ht_hi_3, 16'h0000} + HOST_B_3;

wire [10:0] flow_idx_comb_0 = flow_val_0[31:21];
wire [10:0] flow_idx_comb_1 = flow_val_1[31:21];
wire [10:0] flow_idx_comb_2 = flow_val_2[31:21];
wire [10:0] flow_idx_comb_3 = flow_val_3[31:21];

wire [9:0]  host_idx_comb_0 = host_val_0[31:22];
wire [9:0]  host_idx_comb_1 = host_val_1[31:22];
wire [9:0]  host_idx_comb_2 = host_val_2[31:22];
wire [9:0]  host_idx_comb_3 = host_val_3[31:22];

// Unused bits sink to satisfy Verilator -Wall
wire _unused_bits = &{1'b0,
    fl_hi_0[31:16], fl_hi_1[31:16], fl_hi_2[31:16], fl_hi_3[31:16],
    ht_hi_0[31:16], ht_hi_1[31:16], ht_hi_2[31:16], ht_hi_3[31:16],
    flow_val_0[20:0], flow_val_1[20:0], flow_val_2[20:0], flow_val_3[20:0],
    host_val_0[21:0], host_val_1[21:0], host_val_2[21:0], host_val_3[21:0]
};

always @(posedge clk) begin
    if (rst) begin
        out_valid  <= 1'b0;
        flow_idx_0 <= 11'd0;
        flow_idx_1 <= 11'd0;
        flow_idx_2 <= 11'd0;
        flow_idx_3 <= 11'd0;
        host_idx_0 <= 10'd0;
        host_idx_1 <= 10'd0;
        host_idx_2 <= 10'd0;
        host_idx_3 <= 10'd0;
    end else begin
        out_valid <= v2;
        if (v2) begin
            flow_idx_0 <= flow_idx_comb_0;
            flow_idx_1 <= flow_idx_comb_1;
            flow_idx_2 <= flow_idx_comb_2;
            flow_idx_3 <= flow_idx_comb_3;
            host_idx_0 <= host_idx_comb_0;
            host_idx_1 <= host_idx_comb_1;
            host_idx_2 <= host_idx_comb_2;
            host_idx_3 <= host_idx_comb_3;
        end else begin
            flow_idx_0 <= 11'd0;
            flow_idx_1 <= 11'd0;
            flow_idx_2 <= 11'd0;
            flow_idx_3 <= 11'd0;
            host_idx_0 <= 10'd0;
            host_idx_1 <= 10'd0;
            host_idx_2 <= 10'd0;
            host_idx_3 <= 10'd0;
        end
    end
end

endmodule

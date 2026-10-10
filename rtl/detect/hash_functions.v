// ============================================================================
// Module: hash_functions
// Description: Parallel 2-Universal Hash Generators for Dual Count-Min Sketch
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
// SECTION 3: Key Generation Logic (Host Key & Flow Key)
// ============================================================================
wire [31:0] port_ext      = {16'h0000, dst_port};
wire [31:0] port_diffused = port_ext * PORT_DIFFUSER;
wire [31:0] flow_key      = src_ip ^ port_diffused;
wire [31:0] host_key      = src_ip;

// ============================================================================
// SECTION 4: Combinational Hash Calculation Channels
// ============================================================================
wire [31:0] flow_val_0 = (FLOW_A_0 * flow_key) + FLOW_B_0;
wire [31:0] flow_val_1 = (FLOW_A_1 * flow_key) + FLOW_B_1;
wire [31:0] flow_val_2 = (FLOW_A_2 * flow_key) + FLOW_B_2;
wire [31:0] flow_val_3 = (FLOW_A_3 * flow_key) + FLOW_B_3;

wire [31:0] host_val_0 = (HOST_A_0 * host_key) + HOST_B_0;
wire [31:0] host_val_1 = (HOST_A_1 * host_key) + HOST_B_1;
wire [31:0] host_val_2 = (HOST_A_2 * host_key) + HOST_B_2;
wire [31:0] host_val_3 = (HOST_A_3 * host_key) + HOST_B_3;

wire [10:0] flow_idx_comb_0 = flow_val_0[31:21];
wire [10:0] flow_idx_comb_1 = flow_val_1[31:21];
wire [10:0] flow_idx_comb_2 = flow_val_2[31:21];
wire [10:0] flow_idx_comb_3 = flow_val_3[31:21];

wire [9:0]  host_idx_comb_0 = host_val_0[31:22];
wire [9:0]  host_idx_comb_1 = host_val_1[31:22];
wire [9:0]  host_idx_comb_2 = host_val_2[31:22];
wire [9:0]  host_idx_comb_3 = host_val_3[31:22];

// ============================================================================
// SECTION 5: Output Pipeline Registers (1-Cycle Latency)
// ============================================================================
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
        out_valid <= in_valid;
        if (in_valid) begin
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

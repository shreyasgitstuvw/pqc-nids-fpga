// ============================================================================
// Module: count_min_sketch
// Description: Dual-Sketch Volumetric Threat Detection Engine (Flood & Scan)
// Target: ZedBoard XC7Z020 @ 100 MHz
// Owner: Member B (Lane 2 - Threat Detection)
// Bit-exact with model/detect.py (Section 3 & Section 4)
// ============================================================================

`timescale 1ns / 1ps
`include "reason_codes.vh"

// ============================================================================
// SECTION 1: Module Declaration, Parameters and Port Definitions
// ============================================================================
module count_min_sketch #(
    parameter [15:0] THRESH_FLOOD = 16'd512,
    parameter [15:0] THRESH_SCAN  = 16'd384,
    parameter [15:0] FANOUT_MAX   = 16'd96,
    parameter [15:0] EPOCH_N      = 16'd32768
) (
    input  wire        clk,
    input  wire        rst,
    input  wire        header_valid,
    input  wire [31:0] src_ip,
    input  wire [31:0] dst_ip,
    input  wire [15:0] dst_port,
    input  wire [7:0]  protocol,
    input  wire        eof,
    output reg         ready,
    output reg         verdict_valid,
    output reg         verdict_fail,
    output reg  [3:0]  verdict_reason,
    output reg  [15:0] c_flow_out,
    output reg  [15:0] c_host_out
);

// ============================================================================
// SECTION 2: Dual BRAM Arrays and Hardware Clearing Engine
// ============================================================================
// Flow Sketch: 4 rows x 2048 entries x 16-bit counters (4 x RAMB36E1)
(* ram_style = "block" *) reg [15:0] flow_mem_0 [0:2047];
(* ram_style = "block" *) reg [15:0] flow_mem_1 [0:2047];
(* ram_style = "block" *) reg [15:0] flow_mem_2 [0:2047];
(* ram_style = "block" *) reg [15:0] flow_mem_3 [0:2047];

// Host Sketch: 4 rows x 1024 entries x 16-bit counters (2 x RAMB36E1)
(* ram_style = "block" *) reg [15:0] host_mem_0 [0:1023];
(* ram_style = "block" *) reg [15:0] host_mem_1 [0:1023];
(* ram_style = "block" *) reg [15:0] host_mem_2 [0:1023];
(* ram_style = "block" *) reg [15:0] host_mem_3 [0:1023];

`ifdef COCOTB_SIM
integer init_i;
initial begin
    for (init_i = 0; init_i < 2048; init_i = init_i + 1) begin
        flow_mem_0[init_i] = 16'd0;
        flow_mem_1[init_i] = 16'd0;
        flow_mem_2[init_i] = 16'd0;
        flow_mem_3[init_i] = 16'd0;
    end
    for (init_i = 0; init_i < 1024; init_i = init_i + 1) begin
        host_mem_0[init_i] = 16'd0;
        host_mem_1[init_i] = 16'd0;
        host_mem_2[init_i] = 16'd0;
        host_mem_3[init_i] = 16'd0;
    end
end
`endif

// Hardware clearing engine sweeps memory sequentially on reset or epoch rollover
reg [11:0] clear_addr;
reg        clearing;
reg [15:0] epoch_pkt_count;

// ============================================================================
// SECTION 3: Hash Calculation Stage & Address Pipeline
// ============================================================================
wire        hash_out_valid;
wire [10:0] flow_hash_0, flow_hash_1, flow_hash_2, flow_hash_3;
wire [9:0]  host_hash_0, host_hash_1, host_hash_2, host_hash_3;

hash_functions u_hash (
    .clk        (clk),
    .rst        (rst),
    .in_valid   (header_valid && ready && !clearing),
    .src_ip     (src_ip),
    .dst_port   (dst_port),
    .out_valid  (hash_out_valid),
    .flow_idx_0 (flow_hash_0),
    .flow_idx_1 (flow_hash_1),
    .flow_idx_2 (flow_hash_2),
    .flow_idx_3 (flow_hash_3),
    .host_idx_0 (host_hash_0),
    .host_idx_1 (host_hash_1),
    .host_idx_2 (host_hash_2),
    .host_idx_3 (host_hash_3)
);

// Pipeline Stage 1 registers (BRAM Read Address)
reg        pipe_rd_en;
reg [10:0] rd_flow_idx_0, rd_flow_idx_1, rd_flow_idx_2, rd_flow_idx_3;
reg [9:0]  rd_host_idx_0, rd_host_idx_1, rd_host_idx_2, rd_host_idx_3;

always @(posedge clk) begin
    if (rst) begin
        pipe_rd_en    <= 1'b0;
        rd_flow_idx_0 <= 11'd0;
        rd_flow_idx_1 <= 11'd0;
        rd_flow_idx_2 <= 11'd0;
        rd_flow_idx_3 <= 11'd0;
        rd_host_idx_0 <= 10'd0;
        rd_host_idx_1 <= 10'd0;
        rd_host_idx_2 <= 10'd0;
        rd_host_idx_3 <= 10'd0;
    end else begin
        pipe_rd_en    <= hash_out_valid;
        rd_flow_idx_0 <= flow_hash_0;
        rd_flow_idx_1 <= flow_hash_1;
        rd_flow_idx_2 <= flow_hash_2;
        rd_flow_idx_3 <= flow_hash_3;
        rd_host_idx_0 <= host_hash_0;
        rd_host_idx_1 <= host_hash_1;
        rd_host_idx_2 <= host_hash_2;
        rd_host_idx_3 <= host_hash_3;
    end
end

// ============================================================================
// SECTION 4: BRAM Read-Modify-Write Pipeline & Forwarding Logic
// ============================================================================
// Synchronous BRAM Read Outputs
reg [15:0] b_flow_rd_0, b_flow_rd_1, b_flow_rd_2, b_flow_rd_3;
reg [15:0] b_host_rd_0, b_host_rd_1, b_host_rd_2, b_host_rd_3;

always @(posedge clk) begin
    b_flow_rd_0 <= flow_mem_0[rd_flow_idx_0];
    b_flow_rd_1 <= flow_mem_1[rd_flow_idx_1];
    b_flow_rd_2 <= flow_mem_2[rd_flow_idx_2];
    b_flow_rd_3 <= flow_mem_3[rd_flow_idx_3];

    b_host_rd_0 <= host_mem_0[rd_host_idx_0];
    b_host_rd_1 <= host_mem_1[rd_host_idx_1];
    b_host_rd_2 <= host_mem_2[rd_host_idx_2];
    b_host_rd_3 <= host_mem_3[rd_host_idx_3];
end

// Pipeline Stage 2 registers (Address forwarding & writeback target)
reg        pipe_upd_en;
reg [10:0] upd_flow_idx_0, upd_flow_idx_1, upd_flow_idx_2, upd_flow_idx_3;
reg [9:0]  upd_host_idx_0, upd_host_idx_1, upd_host_idx_2, upd_host_idx_3;

always @(posedge clk) begin
    if (rst) begin
        pipe_upd_en    <= 1'b0;
        upd_flow_idx_0 <= 11'd0;
        upd_flow_idx_1 <= 11'd0;
        upd_flow_idx_2 <= 11'd0;
        upd_flow_idx_3 <= 11'd0;
        upd_host_idx_0 <= 10'd0;
        upd_host_idx_1 <= 10'd0;
        upd_host_idx_2 <= 10'd0;
        upd_host_idx_3 <= 10'd0;
    end else begin
        pipe_upd_en    <= pipe_rd_en;
        upd_flow_idx_0 <= rd_flow_idx_0;
        upd_flow_idx_1 <= rd_flow_idx_1;
        upd_flow_idx_2 <= rd_flow_idx_2;
        upd_flow_idx_3 <= rd_flow_idx_3;
        upd_host_idx_0 <= rd_host_idx_0;
        upd_host_idx_1 <= rd_host_idx_1;
        upd_host_idx_2 <= rd_host_idx_2;
        upd_host_idx_3 <= rd_host_idx_3;
    end
end

// Forwarding / Bypassing registers from previous write
reg        fwd_valid;
reg [10:0] fwd_flow_idx_0, fwd_flow_idx_1, fwd_flow_idx_2, fwd_flow_idx_3;
reg [9:0]  fwd_host_idx_0, fwd_host_idx_1, fwd_host_idx_2, fwd_host_idx_3;
reg [15:0] fwd_flow_val_0, fwd_flow_val_1, fwd_flow_val_2, fwd_flow_val_3;
reg [15:0] fwd_host_val_0, fwd_host_val_1, fwd_host_val_2, fwd_host_val_3;

// Resolve read hazards with zero-cycle forwarding
wire [15:0] cur_flow_0 = (fwd_valid && (fwd_flow_idx_0 == upd_flow_idx_0)) ? fwd_flow_val_0 : b_flow_rd_0;
wire [15:0] cur_flow_1 = (fwd_valid && (fwd_flow_idx_1 == upd_flow_idx_1)) ? fwd_flow_val_1 : b_flow_rd_1;
wire [15:0] cur_flow_2 = (fwd_valid && (fwd_flow_idx_2 == upd_flow_idx_2)) ? fwd_flow_val_2 : b_flow_rd_2;
wire [15:0] cur_flow_3 = (fwd_valid && (fwd_flow_idx_3 == upd_flow_idx_3)) ? fwd_flow_val_3 : b_flow_rd_3;

wire [15:0] cur_host_0 = (fwd_valid && (fwd_host_idx_0 == upd_host_idx_0)) ? fwd_host_val_0 : b_host_rd_0;
wire [15:0] cur_host_1 = (fwd_valid && (fwd_host_idx_1 == upd_host_idx_1)) ? fwd_host_val_1 : b_host_rd_1;
wire [15:0] cur_host_2 = (fwd_valid && (fwd_host_idx_2 == upd_host_idx_2)) ? fwd_host_val_2 : b_host_rd_2;
wire [15:0] cur_host_3 = (fwd_valid && (fwd_host_idx_3 == upd_host_idx_3)) ? fwd_host_val_3 : b_host_rd_3;

// Saturating Incrementers (Hold at 16'hFFFF, never wrap)
wire [15:0] nxt_flow_0 = (cur_flow_0 == 16'hFFFF) ? 16'hFFFF : (cur_flow_0 + 16'd1);
wire [15:0] nxt_flow_1 = (cur_flow_1 == 16'hFFFF) ? 16'hFFFF : (cur_flow_1 + 16'd1);
wire [15:0] nxt_flow_2 = (cur_flow_2 == 16'hFFFF) ? 16'hFFFF : (cur_flow_2 + 16'd1);
wire [15:0] nxt_flow_3 = (cur_flow_3 == 16'hFFFF) ? 16'hFFFF : (cur_flow_3 + 16'd1);

wire [15:0] nxt_host_0 = (cur_host_0 == 16'hFFFF) ? 16'hFFFF : (cur_host_0 + 16'd1);
wire [15:0] nxt_host_1 = (cur_host_1 == 16'hFFFF) ? 16'hFFFF : (cur_host_1 + 16'd1);
wire [15:0] nxt_host_2 = (cur_host_2 == 16'hFFFF) ? 16'hFFFF : (cur_host_2 + 16'd1);
wire [15:0] nxt_host_3 = (cur_host_3 == 16'hFFFF) ? 16'hFFFF : (cur_host_3 + 16'd1);

// Writeback and Memory Management
always @(posedge clk) begin
    if (rst) begin
        clearing         <= 1'b1;
        clear_addr       <= 12'd0;
        ready            <= 1'b0;
        epoch_pkt_count  <= 16'd0;
        fwd_valid        <= 1'b0;
        fwd_flow_idx_0   <= 11'd0;
        fwd_flow_idx_1   <= 11'd0;
        fwd_flow_idx_2   <= 11'd0;
        fwd_flow_idx_3   <= 11'd0;
        fwd_host_idx_0   <= 10'd0;
        fwd_host_idx_1   <= 10'd0;
        fwd_host_idx_2   <= 10'd0;
        fwd_host_idx_3   <= 10'd0;
        fwd_flow_val_0   <= 16'd0;
        fwd_flow_val_1   <= 16'd0;
        fwd_flow_val_2   <= 16'd0;
        fwd_flow_val_3   <= 16'd0;
        fwd_host_val_0   <= 16'd0;
        fwd_host_val_1   <= 16'd0;
        fwd_host_val_2   <= 16'd0;
        fwd_host_val_3   <= 16'd0;
    end else if (clearing) begin
        flow_mem_0[clear_addr[10:0]] <= 16'd0;
        flow_mem_1[clear_addr[10:0]] <= 16'd0;
        flow_mem_2[clear_addr[10:0]] <= 16'd0;
        flow_mem_3[clear_addr[10:0]] <= 16'd0;
        if (clear_addr < 12'd1024) begin
            host_mem_0[clear_addr[9:0]] <= 16'd0;
            host_mem_1[clear_addr[9:0]] <= 16'd0;
            host_mem_2[clear_addr[9:0]] <= 16'd0;
            host_mem_3[clear_addr[9:0]] <= 16'd0;
        end
        if (clear_addr == 12'd2047) begin
            clearing   <= 1'b0;
            clear_addr <= 12'd0;
            ready      <= 1'b1;
        end else begin
            clear_addr <= clear_addr + 12'd1;
        end
    end else if (pipe_upd_en) begin
        // Write updated counters to BRAM
        flow_mem_0[upd_flow_idx_0] <= nxt_flow_0;
        flow_mem_1[upd_flow_idx_1] <= nxt_flow_1;
        flow_mem_2[upd_flow_idx_2] <= nxt_flow_2;
        flow_mem_3[upd_flow_idx_3] <= nxt_flow_3;

        host_mem_0[upd_host_idx_0] <= nxt_host_0;
        host_mem_1[upd_host_idx_1] <= nxt_host_1;
        host_mem_2[upd_host_idx_2] <= nxt_host_2;
        host_mem_3[upd_host_idx_3] <= nxt_host_3;

        // Register forwarding state
        fwd_valid      <= 1'b1;
        fwd_flow_idx_0 <= upd_flow_idx_0;
        fwd_flow_idx_1 <= upd_flow_idx_1;
        fwd_flow_idx_2 <= upd_flow_idx_2;
        fwd_flow_idx_3 <= upd_flow_idx_3;
        fwd_host_idx_0 <= upd_host_idx_0;
        fwd_host_idx_1 <= upd_host_idx_1;
        fwd_host_idx_2 <= upd_host_idx_2;
        fwd_host_idx_3 <= upd_host_idx_3;

        fwd_flow_val_0 <= nxt_flow_0;
        fwd_flow_val_1 <= nxt_flow_1;
        fwd_flow_val_2 <= nxt_flow_2;
        fwd_flow_val_3 <= nxt_flow_3;
        fwd_host_val_0 <= nxt_host_0;
        fwd_host_val_1 <= nxt_host_1;
        fwd_host_val_2 <= nxt_host_2;
        fwd_host_val_3 <= nxt_host_3;

        // Epoch packet counter tracking
        if (epoch_pkt_count >= (EPOCH_N - 16'd1)) begin
            epoch_pkt_count <= 16'd0;
            clearing        <= 1'b1;
            clear_addr      <= 12'd0;
            ready           <= 1'b0;
        end else begin
            epoch_pkt_count <= epoch_pkt_count + 16'd1;
        end
    end else begin
        fwd_valid <= 1'b0;
    end
end

// ============================================================================
// SECTION 5: 4-Way Minimum Trees, Threshold Classifier & Verdict Output
// ============================================================================
// 4-Way Minimum Tree for Flow Sketch
wire [15:0] min_f_01 = (nxt_flow_0 < nxt_flow_1) ? nxt_flow_0 : nxt_flow_1;
wire [15:0] min_f_23 = (nxt_flow_2 < nxt_flow_3) ? nxt_flow_2 : nxt_flow_3;
wire [15:0] calc_min_flow = (min_f_01 < min_f_23) ? min_f_01 : min_f_23;

// 4-Way Minimum Tree for Host Sketch
wire [15:0] min_h_01 = (nxt_host_0 < nxt_host_1) ? nxt_host_0 : nxt_host_1;
wire [15:0] min_h_23 = (nxt_host_2 < nxt_host_3) ? nxt_host_2 : nxt_host_3;
wire [15:0] calc_min_host = (min_h_01 < min_h_23) ? min_h_01 : min_h_23;

// Threshold Evaluation Logic
wire is_flood = (calc_min_flow >= THRESH_FLOOD);
wire is_scan  = (calc_min_host >= THRESH_SCAN) && (calc_min_flow <= FANOUT_MAX);
wire comb_fail = is_flood || is_scan;
wire [3:0] comb_reason = is_flood ? `RC_FLOOD :
                         is_scan  ? `RC_SCAN  :
                                    `RC_NONE;

// Synchronous Output Registering with 1-Cycle Strobe
always @(posedge clk) begin
    if (rst) begin
        verdict_valid  <= 1'b0;
        verdict_fail   <= 1'b0;
        verdict_reason <= `RC_NONE;
        c_flow_out     <= 16'd0;
        c_host_out     <= 16'd0;
    end else if (pipe_upd_en) begin
        verdict_valid  <= 1'b1;
        verdict_fail   <= comb_fail;
        verdict_reason <= comb_reason;
        c_flow_out     <= calc_min_flow;
        c_host_out     <= calc_min_host;
    end else begin
        verdict_valid  <= 1'b0;
        verdict_fail   <= 1'b0;
        verdict_reason <= `RC_NONE;
        c_flow_out     <= 16'd0;
        c_host_out     <= 16'd0;
    end
end

endmodule

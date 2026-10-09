//==========================================================================
// rtl/crypto/ntt/modmul.v
//
// Pipelined Modular Multiplier mod q = 3329 for ML-KEM-512.
// Bit-exact synthesizable RTL twin of model/modmul_hw.py.
//
// Arithmetic:
//   Inputs: a, b in [0, 3328] (12-bit unsigned)
//   Product: P = a * b (24 bits unsigned, fits 1 DSP48E1)
//   Reduction: Barrett reduction with M = floor(2^24 / 3329) = 5039
//              5039 = 2^12 + 2^10 - 2^6 - 2^4 - 1
//              3329 = 2^11 + 2^10 + 2^8 + 1
//   All intermediate values are strictly unsigned.
//   Guaranteed remainder r in [0, 4903] < 2*Q, requiring at most 1 conditional subtraction.
//
// Timing & Resource Estimates (XC7Z020 @ 100 MHz, estimated, pre-synthesis):
//   Latency: PIPE_DEPTH = 3 clock cycles (nominal)
//   DSP48E1: 1 slice (12x12 -> 24 multiply)
//   Slice LUTs: ~110-130 LUTs (shift-add reduction trees and subtractor)
//   Slice FFs: ~65 registers
//==========================================================================

`timescale 1ns / 1ps

module modmul #(
    parameter integer PIPE_DEPTH = 3
) (
    input  wire        clk,
    input  wire        rst,
    input  wire        en,        // Input valid
    input  wire [11:0] a,         // Operand a in [0, 3328]
    input  wire [11:0] b,         // Operand b in [0, 3328]
    output wire        valid_out, // Output valid after PIPE_DEPTH cycles
    output wire [11:0] res        // (a * b) mod 3329 in [0, 3328]
);

    // Suppress unused param if module depth is fixed at 3
    /* verilator lint_off UNUSEDPARAM */
    localparam integer LATENCY = PIPE_DEPTH;
    /* verilator lint_on UNUSEDPARAM */

    localparam [11:0] Q = 12'd3329;

    // -------------------------------------------------------------------------
    // Stage 1: DSP Multiplication (P = a * b)
    // -------------------------------------------------------------------------
    reg [23:0] prod_s1;
    reg        val_s1;

    always @(posedge clk) begin
        if (rst) begin
            prod_s1 <= 24'd0;
            val_s1  <= 1'b0;
        end else begin
            val_s1  <= en;
            if (en) begin
                prod_s1 <= a * b;
            end
        end
    end

    // -------------------------------------------------------------------------
    // Stage 2: Barrett Quotient Estimation
    //   prod_m = P * 5039 = (P << 12) + (P << 10) - (P << 6) - (P << 4) - P
    //   q_est = prod_m >> 24
    // -------------------------------------------------------------------------
    wire [36:0] term_12 = {1'b0, prod_s1, 12'b0};
    wire [36:0] term_10 = {3'b0, prod_s1, 10'b0};
    wire [36:0] term_06 = {7'b0, prod_s1, 6'b0};
    wire [36:0] term_04 = {9'b0, prod_s1, 4'b0};
    wire [36:0] term_00 = {13'b0, prod_s1};

    wire [37:0] sum_pos = {1'b0, term_12} + {1'b0, term_10};
    wire [37:0] sum_neg = {1'b0, term_06} + {1'b0, term_04} + {1'b0, term_00};
    wire [37:0] prod_m  = sum_pos - sum_neg;

    /* verilator lint_off UNUSEDSIGNAL */
    wire [23:0] unused_prod_low = prod_m[23:0];
    /* verilator lint_on UNUSEDSIGNAL */

    reg [13:0] q_est_s2;
    reg [23:0] p_s2;
    reg        val_s2;

    always @(posedge clk) begin
        if (rst) begin
            q_est_s2 <= 14'd0;
            p_s2     <= 24'd0;
            val_s2   <= 1'b0;
        end else begin
            val_s2   <= val_s1;
            if (val_s1) begin
                q_est_s2 <= prod_m[37:24];
                p_s2     <= prod_s1;
            end
        end
    end

    // -------------------------------------------------------------------------
    // Stage 3: Remainder & Conditional Subtraction
    //   q_mult = q_est * 3329 = (q_est << 11) + (q_est << 10) + (q_est << 8) + q_est
    //   r = P - q_mult
    //   res = (r >= 3329) ? r - 3329 : r
    // -------------------------------------------------------------------------
    wire [24:0] q_term_11 = {q_est_s2, 11'b0};
    wire [24:0] q_term_10 = {1'b0, q_est_s2, 10'b0};
    wire [24:0] q_term_08 = {3'b0, q_est_s2, 8'b0};
    wire [24:0] q_term_00 = {11'b0, q_est_s2};
    wire [24:0] q_mult    = q_term_11 + q_term_10 + q_term_08 + q_term_00;

    /* verilator lint_off UNUSEDSIGNAL */
    wire unused_qmult_msb = q_mult[24];
    /* verilator lint_on UNUSEDSIGNAL */

    wire [23:0] r_raw = p_s2 - q_mult[23:0];
    wire [11:0] r_corr = (r_raw >= {12'b0, Q}) ? (r_raw[11:0] - Q) : r_raw[11:0];

    reg [11:0] res_s3;
    reg        val_s3;

    always @(posedge clk) begin
        if (rst) begin
            res_s3 <= 12'd0;
            val_s3 <= 1'b0;
        end else begin
            val_s3 <= val_s2;
            if (val_s2) begin
                res_s3 <= r_corr;
            end
        end
    end

    // Output assignment (3 stages)
    assign valid_out = val_s3;
    assign res       = res_s3;

endmodule

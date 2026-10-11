//==========================================================================
// rtl/crypto/kem/compress.v
//
// Polynomial Coefficient Compression Core for ML-KEM-512 (FIPS 203 Eq 4.7).
// Bit-exact synthesizable RTL twin of model/mlkem/pke.py:compress
// and model/compress_hw.py:compress_hw.
//
// Arithmetic:
//   Compress_d(x) = round(2^d * x / q) mod 2^d
//                 = floor(((x << d) + 1664) / 3329) mod 2^d
//   Division by 3329 is performed division-free via reciprocal multiplication
//   with minimum exact (M, S) pairs and Canonical Signed Digit (CSD) shift-add trees:
//     - D = 1:  S = 20, M = 315 = (2^8 + 2^6) - (2^2 + 1)
//     - D = 4:  S = 26, M = 20159 = (2^14 + 2^12) - (2^8 + 2^6 + 1)
//     - D = 10: S = 33, M = 2580335 = (2^21 + 2^19) - (2^15 + 2^13 + 2^7 + 2^4 + 1)
//
// Pipeline Architecture (3 Stages, Latency L = 3 clock cycles):
//   - Stage 1: Compute P = (x << D) + 1664, registered into p_r (22 bits)
//   - Stage 2: Compute CSD positive and negative partial sums, registered into
//              t_pos_r and t_neg_r (44 bits wide)
//   - Stage 3: Subtract Prod = t_pos_r - t_neg_r (44 bits wide), right-shift
//              by S, extract D-bit mask, registered into out_data
//
// Timing & Latency (XC7Z020 @ 100 MHz, estimated, pre-synthesis):
//   - Fixed latency: L = 3 clock cycles for all D in {1, 4, 10}
//   - Throughput: 1 coefficient per clock cycle (zero backpressure, zero bubbles)
//   - 256-coefficient polynomial completes in exactly 256 + L = 259 cycles
//   - Timing: Expected to meet 100 MHz, to be confirmed by synthesis
//
// Resources (estimated, pre-synthesis):
//   - D = 1:  0 DSP48E1, ~45 LUTs, ~28 FFs
//   - D = 4:  0 DSP48E1, ~70 LUTs, ~35 FFs
//   - D = 10: 0 DSP48E1, ~175 LUTs, ~78 FFs
//==========================================================================

`timescale 1ns / 1ps

module compress #(
    parameter integer D = 10  // Valid values: 1, 4, 10
) (
    input  wire         clk,
    input  wire         rst,

    // Streaming Input Port
    input  wire         in_valid,
    input  wire [11:0]  in_data,

    // Streaming Output Port (Latency L = 3 cycles)
    output reg          out_valid,
    output reg  [D-1:0] out_data
);

    // Shift constant S per parameter D
    localparam integer S = (D == 10) ? 33 :
                           (D == 4)  ? 26 : 20;

    //----------------------------------------------------------------------
    // Stage 1: Add half-modulus rounding offset 1664
    //   P = (in_data << D) + 1664
    //   Maximum P: (3328 << 10) + 1664 = 3,409,536 (22 bits)
    //----------------------------------------------------------------------
    wire [21:0] x_scaled = {10'd0, in_data} << D;
    wire [21:0] p_comb   = x_scaled + 22'd1664;

    reg [21:0] p_r;
    reg        v1_r;

    always @(posedge clk) begin
        if (rst) begin
            p_r  <= 22'd0;
            v1_r <= 1'b0;
        end else begin
            p_r  <= p_comb;
            v1_r <= in_valid;
        end
    end

    //----------------------------------------------------------------------
    // Stage 2: CSD Partial Sums
    //   Intermediates sized at 44 bits for D=10 (P << 21 is ~43 bits)
    //----------------------------------------------------------------------
    wire [43:0] p_ext = {{22{1'b0}}, p_r};

    wire [43:0] t_pos_comb = (D == 10) ? ((p_ext << 21) + (p_ext << 19)) :
                             (D == 4)  ? ((p_ext << 14) + (p_ext << 12)) :
                                         ((p_ext << 8)  + (p_ext << 6));

    wire [43:0] t_neg_comb = (D == 10) ? ((p_ext << 15) + (p_ext << 13) + (p_ext << 7) + (p_ext << 4) + p_ext) :
                             (D == 4)  ? ((p_ext << 8)  + (p_ext << 6)  + p_ext) :
                                         ((p_ext << 2)  + p_ext);

    reg [43:0] t_pos_r;
    reg [43:0] t_neg_r;
    reg        v2_r;

    always @(posedge clk) begin
        if (rst) begin
            t_pos_r <= 44'd0;
            t_neg_r <= 44'd0;
            v2_r    <= 1'b0;
        end else begin
            t_pos_r <= t_pos_comb;
            t_neg_r <= t_neg_comb;
            v2_r    <= v1_r;
        end
    end

    //----------------------------------------------------------------------
    // Stage 3: Final CSD Difference, Right Shift by S, and Mod 2^D Mask
    //----------------------------------------------------------------------
    wire [43:0] prod_comb = t_pos_r - t_neg_r;
    /* verilator lint_off UNUSEDSIGNAL */
    wire [43:0] prod_shifted = prod_comb >> S;
    /* verilator lint_on UNUSEDSIGNAL */
    wire [D-1:0] result_comb = prod_shifted[D-1:0];

    always @(posedge clk) begin
        if (rst) begin
            out_valid <= 1'b0;
            out_data  <= {D{1'b0}};
        end else begin
            out_valid <= v2_r;
            out_data  <= v2_r ? result_comb : {D{1'b0}};
        end
    end

endmodule

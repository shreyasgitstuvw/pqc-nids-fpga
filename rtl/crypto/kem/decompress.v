//==========================================================================
// rtl/crypto/kem/decompress.v
//
// Polynomial Coefficient Decompression Core for ML-KEM-512 (FIPS 203 Eq 4.8).
// Bit-exact synthesizable RTL twin of model/mlkem/pke.py:decompress
// and model/compress_hw.py:decompress_hw.
//
// Arithmetic:
//   Decompress_d(y) = round(q * y / 2^d)
//                   = floor((y * 3329 + 2^(d-1)) / 2^d)
//   Division by 2^d is an exact right-shift in hardware.
//   Shift-add decomposition of q = 3329:
//     y * 3329 = (y << 11) + (y << 10) + (y << 8) + y
//
// Timing & Latency (XC7Z020 @ 100 MHz, estimated, pre-synthesis):
//   - Fixed latency: L = 1 clock cycle for all D in {1, 4, 10}
//   - Throughput: 1 coefficient per clock cycle (zero backpressure, zero bubbles)
//   - 256-coefficient polynomial completes in exactly 256 + L = 257 cycles
//   - Timing: Expected to meet 100 MHz, to be confirmed by synthesis
//
// Resources (estimated, pre-synthesis):
//   - D = 1:  0 DSP48E1, ~12 LUTs, 13 FFs
//   - D = 4:  0 DSP48E1, ~35 LUTs, 13 FFs
//   - D = 10: 0 DSP48E1, ~55 LUTs, 13 FFs
//==========================================================================

`timescale 1ns / 1ps

module decompress #(
    parameter integer D = 10  // Valid values: 1, 4, 10
) (
    input  wire         clk,
    input  wire         rst,

    // Streaming Input Port
    input  wire         in_valid,
    input  wire [D-1:0] in_data,

    // Streaming Output Port (Latency L = 1 cycle)
    output reg          out_valid,
    output reg  [11:0]  out_data
);

    // Zero-extend input to 22 bits (max y * 3329 + bias is < 2^22)
    wire [21:0] y_ext = {{(22-D){1'b0}}, in_data};

    // Rounding bias 2^(D-1)
    wire [21:0] round_bias = 22'd1 << (D - 1);

    // Shift-add multiply by 3329 + rounding bias
    // 3329 = 2048 + 1024 + 256 + 1
    wire [21:0] sum_scaled = (y_ext << 11) + (y_ext << 10) + (y_ext << 8) + y_ext + round_bias;

    // Shift by D to complete division by 2^D
    /* verilator lint_off UNUSEDSIGNAL */
    wire [21:0] sum_shifted = sum_scaled >> D;
    /* verilator lint_on UNUSEDSIGNAL */

    // Output registration: fixed latency L = 1
    always @(posedge clk) begin
        if (rst) begin
            out_valid <= 1'b0;
            out_data  <= 12'd0;
        end else begin
            out_valid <= in_valid;
            out_data  <= in_valid ? sum_shifted[11:0] : 12'd0;
        end
    end

endmodule

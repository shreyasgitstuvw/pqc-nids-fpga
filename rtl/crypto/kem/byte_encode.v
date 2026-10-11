//==========================================================================
// rtl/crypto/kem/byte_encode.v
//
// Polynomial Byte Encoder Core for ML-KEM-512 (FIPS 203 Algorithm 5).
// Bit-exact synthesizable RTL twin of model/mlkem/pke.py:byte_encode.
// Packs 256 coefficients of bit-width D in {1, 4, 10, 12} into 64-bit words,
// LSB-first throughout (FIPS 203 sec 4.2.1).
//
// Protocol & Timing:
//   - Parameter D: compile-time parameter in {1, 4, 10, 12}.
//   - Input port: valid-only streaming datapath from mlkem_top/poly_ram.
//     Zero backpressure on coefficient side.
//   - Output port: 64-bit words with out_valid / out_ready handshake matching
//     shake_wrapper.v absorb port.
//   - poly_last: 1-cycle strobe asserted alongside the final word of the poly.
//     (mlkem_top drives shake_wrapper in_last on true message boundary).
//   - Output registration: out_data and out_valid are registered.
//     First-word latency from first in_valid:
//       D=12: 6 clock cycles (after 6 coeffs ingested)
//       D=10: 7 clock cycles (after 7 coeffs ingested)
//       D=4:  16 clock cycles (after 16 coeffs ingested)
//       D=1:  64 clock cycles (after 64 coeffs ingested)
//   - Total duration: 256 cycles under zero backpressure (final 64-bit word
//     registered at cycle 256 alongside poly_last strobe).
//   - Accumulator buffer: 128 bits wide. Provides >= 6 coefficients of slack
//     if out_ready drops, tolerating mlkem_top BRAM read halt latency.
//   - Overflow detection: sticky overflow output asserts if an incoming coefficient
//     arrives when it would exceed the 128-bit accumulator buffer capacity.
//     Cleared by start_poly or rst.
//   - Note: start_poly overrides a simultaneous in_valid. mlkem_top must never
//     overlap start_poly and in_valid.
//
// Resources (XC7Z020 @ 100 MHz, estimated, pre-synthesis):
//   - 0 DSP48E1 slices
//   - 0 BRAMs
//   - ~215 Slice Registers (128-bit acc + 64-bit out + 8-bit acc_count + 9-bit coeff_count + 7-bit words_emitted + control flags, estimated, pre-synthesis)
//   - ~80-120 Slice LUTs (estimated, pre-synthesis)
//==========================================================================

`timescale 1ns / 1ps

module byte_encode #(
    parameter integer D = 12   // Valid values: 1, 4, 10, 12
) (
    input  wire         clk,
    input  wire         rst,

    // Control
    input  wire         start_poly,
    output reg          busy,
    output reg          overflow,

    // Coefficient Input (Streaming, valid-only)
    input  wire         in_valid,
    input  wire [D-1:0] in_data,

    // 64-bit Word Output (Valid/Ready handshake)
    output reg  [63:0]  out_data,
    output reg          out_valid,
    input  wire         out_ready,
    output reg          poly_last
);

    // Total 64-bit words per 256-coefficient polynomial
    localparam integer TOTAL_WORDS = (256 * D) / 64;

    // Internal Accumulator & Counters
    reg [127:0] acc_reg;
    reg [7:0]   acc_count_reg;
    reg [8:0]   coeff_count_reg;
    reg [6:0]   words_emitted_reg;

    // Combinational next-state variables
    reg [127:0] next_acc;
    reg [7:0]   next_acc_count;
    reg [8:0]   next_coeff_count;
    reg [6:0]   next_words_emitted;
    reg [63:0]  next_out_data;
    reg         next_out_valid;
    reg         next_poly_last;
    reg         next_busy;
    reg         next_overflow;

    // Shift in_data by current acc_count
    wire [127:0] in_shifted = {{(128-D){1'b0}}, in_data} << acc_count_reg;

    always @(*) begin
        next_acc           = acc_reg;
        next_acc_count     = acc_count_reg;
        next_coeff_count   = coeff_count_reg;
        next_words_emitted = words_emitted_reg;
        next_out_data      = out_data;
        next_out_valid     = out_valid;
        next_poly_last     = poly_last;
        next_busy          = busy;
        next_overflow      = overflow;

        // 1. Handle handshake on current output word
        if (out_valid && out_ready) begin
            next_out_valid = 1'b0;
            next_poly_last = 1'b0;
        end

        // 2. Ingest incoming coefficient if active and within 256 coeffs
        if (busy && in_valid && (coeff_count_reg < 9'd256)) begin
            // Check for accumulator overflow (ingested coefficient exceeds 128-bit capacity)
            if (acc_count_reg + D[7:0] > 8'd128) begin
                next_overflow = 1'b1;
            end
            next_acc         = next_acc | in_shifted;
            next_acc_count   = next_acc_count + D[7:0];
            next_coeff_count = coeff_count_reg + 9'd1;
        end

        // 3. Emit 64-bit word if output register is free (or retiring this cycle)
        if (!next_out_valid && (next_acc_count >= 8'd64) && (next_words_emitted < TOTAL_WORDS[6:0])) begin
            next_out_data      = next_acc[63:0];
            next_out_valid     = 1'b1;
            next_acc           = next_acc >> 64;
            next_acc_count     = next_acc_count - 8'd64;
            next_words_emitted = next_words_emitted + 7'd1;
            if (next_words_emitted == TOTAL_WORDS[6:0]) begin
                next_poly_last = 1'b1;
            end
        end

        // 4. Update busy flag: clear once all words transferred
        if (next_words_emitted == TOTAL_WORDS[6:0] && !next_out_valid) begin
            next_busy = 1'b0;
        end
    end

    // Synchronous state register
    always @(posedge clk) begin
        if (rst) begin
            busy              <= 1'b0;
            overflow          <= 1'b0;
            out_valid         <= 1'b0;
            out_data          <= 64'd0;
            poly_last         <= 1'b0;
            acc_reg           <= 128'd0;
            acc_count_reg     <= 8'd0;
            coeff_count_reg   <= 9'd0;
            words_emitted_reg <= 7'd0;
        end else if (start_poly) begin
            // start_poly overrides simultaneous in_valid. mlkem_top must never overlap start_poly and in_valid.
            busy              <= 1'b1;
            overflow          <= 1'b0;
            out_valid         <= 1'b0;
            out_data          <= 64'd0;
            poly_last         <= 1'b0;
            acc_reg           <= 128'd0;
            acc_count_reg     <= 8'd0;
            coeff_count_reg   <= 9'd0;
            words_emitted_reg <= 7'd0;
        end else begin
            busy              <= next_busy;
            overflow          <= next_overflow;
            out_valid         <= next_out_valid;
            out_data          <= next_out_data;
            poly_last         <= next_poly_last;
            acc_reg           <= next_acc;
            acc_count_reg     <= next_acc_count;
            coeff_count_reg   <= next_coeff_count;
            words_emitted_reg <= next_words_emitted;
        end
    end

endmodule

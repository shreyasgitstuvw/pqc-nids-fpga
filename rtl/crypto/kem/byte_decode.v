//==========================================================================
// rtl/crypto/kem/byte_decode.v
//
// Polynomial Byte Decoder Core for ML-KEM-512 (FIPS 203 Algorithm 6).
// Bit-exact synthesizable RTL twin of model/mlkem/pke.py:byte_decode.
// Unpacks 64-bit words into 256 coefficients of bit-width D in {1, 4, 10, 12},
// LSB-first throughout (FIPS 203 sec 4.2.1).
//
// Protocol & Timing:
//   - Parameter D: compile-time parameter in {1, 4, 10, 12}.
//   - Input port: 64-bit words with in_valid / in_ready handshake.
//   - Output port: streaming valid-only coefficient datapath (12-bit out_data).
//   - Modulus check & reduction (D=12, q=3329):
//       - Unconditionally reduces mod q: (raw_coeff >= 3329) ? (raw_coeff - 3329) : raw_coeff.
//       - If raw_coeff >= 3329 and check_modulus == 1: asserts sticky err_non_canonical.
//       - err_non_canonical cleared on rst or start_poly.
//   - For D in {1, 4, 10}: values are zero-extended to 12 bits; all values < 3329.
//   - Serialization: 128-bit internal shift buffer. Seamlessly unpacks across
//     all word boundaries and straddles without stalls when words are available.
//
// Resources (XC7Z020 @ 100 MHz, estimated, pre-synthesis):
//   - 0 DSP48E1 slices
//   - 0 BRAMs
//   - ~170 Slice Registers (128-bit buffer + 12-bit out + 8-bit buf_len + 9-bit coeffs_out + 7-bit words_in + control flags, estimated, pre-synthesis)
//   - ~90-130 Slice LUTs (estimated, pre-synthesis)
//==========================================================================

`timescale 1ns / 1ps

module byte_decode #(
    parameter integer D = 12   // Valid values: 1, 4, 10, 12
) (
    input  wire         clk,
    input  wire         rst,

    // Control & Status
    input  wire         start_poly,
    output reg          busy,
    input  wire         check_modulus,
    output reg          err_non_canonical,

    // 64-bit Word Input (Valid/Ready handshake)
    input  wire [63:0]  in_data,
    input  wire         in_valid,
    output wire         in_ready,

    // Decoded Coefficient Output (Streaming, valid-only)
    output reg          out_valid,
    output reg  [11:0]  out_data
);

    // Total 64-bit words per 256-coefficient polynomial
    localparam integer TOTAL_WORDS = (256 * D) / 64;

    // Internal State Registers
    reg [127:0] bit_buf_reg;
    reg [7:0]   buf_len_reg;
    reg [8:0]   coeffs_out_reg;
    reg [6:0]   words_in_reg;

    // in_ready asserted when internal buffer can accept a 64-bit word
    assign in_ready = busy && (buf_len_reg <= 8'd64) && (words_in_reg < TOTAL_WORDS[6:0]);

    // Combinational next-state variables
    reg [127:0] next_bit_buf;
    reg [7:0]   next_buf_len;
    reg [8:0]   next_coeffs_out;
    reg [6:0]   next_words_in;
    reg         next_out_valid;
    reg [11:0]  next_out_data;
    reg         next_err_non_canonical;
    reg         next_busy;

    // Temporary variables for evaluation
    reg [D-1:0] raw_coeff;
    reg [11:0]  reduced_coeff;

    always @(*) begin
        next_bit_buf           = bit_buf_reg;
        next_buf_len           = buf_len_reg;
        next_coeffs_out        = coeffs_out_reg;
        next_words_in          = words_in_reg;
        next_out_valid         = 1'b0;
        next_out_data          = 12'd0;
        next_err_non_canonical = err_non_canonical;
        next_busy              = busy;
        raw_coeff              = {D{1'b0}};
        reduced_coeff          = 12'd0;

        // 1. Ingest new 64-bit word if handshake fires
        if (in_valid && in_ready) begin
            next_bit_buf = next_bit_buf | ({64'd0, in_data} << next_buf_len);
            next_buf_len = next_buf_len + 8'd64;
            next_words_in = words_in_reg + 7'd1;
        end

        // 2. Extract coefficient if buffer has >= D bits and coeffs_out < 256
        if (busy && (next_buf_len >= D[7:0]) && (next_coeffs_out < 9'd256)) begin
            raw_coeff = next_bit_buf[D-1:0];
            next_bit_buf = next_bit_buf >> D;
            next_buf_len = next_buf_len - D[7:0];
            next_coeffs_out = next_coeffs_out + 9'd1;
            next_out_valid = 1'b1;

            // Modulus check and reduction
            if (D == 12) begin
                if (raw_coeff >= 12'd3329) begin
                    reduced_coeff = raw_coeff - 12'd3329;
                    if (check_modulus) begin
                        next_err_non_canonical = 1'b1;
                    end
                end else begin
                    reduced_coeff = raw_coeff;
                end
                next_out_data = reduced_coeff;
            end else begin
                next_out_data = {{(12-D){1'b0}}, raw_coeff};
            end
        end

        // 3. Complete decoding when all 256 coefficients emitted
        if (next_coeffs_out == 9'd256) begin
            next_busy = 1'b0;
        end
    end

    // Synchronous state register
    always @(posedge clk) begin
        if (rst) begin
            busy               <= 1'b0;
            err_non_canonical  <= 1'b0;
            out_valid          <= 1'b0;
            out_data           <= 12'd0;
            bit_buf_reg        <= 128'd0;
            buf_len_reg        <= 8'd0;
            coeffs_out_reg     <= 9'd0;
            words_in_reg       <= 7'd0;
        end else if (start_poly) begin
            busy               <= 1'b1;
            err_non_canonical  <= 1'b0;
            out_valid          <= 1'b0;
            out_data           <= 12'd0;
            bit_buf_reg        <= 128'd0;
            buf_len_reg        <= 8'd0;
            coeffs_out_reg     <= 9'd0;
            words_in_reg       <= 7'd0;
        end else begin
            busy               <= next_busy;
            err_non_canonical  <= next_err_non_canonical;
            out_valid          <= next_out_valid;
            out_data           <= next_out_data;
            bit_buf_reg        <= next_bit_buf;
            buf_len_reg        <= next_buf_len;
            coeffs_out_reg     <= next_coeffs_out;
            words_in_reg       <= next_words_in;
        end
    end

endmodule

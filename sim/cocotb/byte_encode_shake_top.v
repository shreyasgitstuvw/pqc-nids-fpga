//==========================================================================
// sim/cocotb/byte_encode_shake_top.v
//
// Real-neighbour integration test wrapper connecting byte_encode.v (D=12)
// directly to shake_wrapper.v for hardware hashing of ML-KEM-512 public keys.
// Simulates mlkem_top control over poly_last, in_last, and in_bytes.
//==========================================================================

`timescale 1ns / 1ps

module byte_encode_shake_top (
    input  wire        clk,
    input  wire        rst,

    // Encoder controls
    input  wire        start_poly,
    input  wire        in_valid,
    input  wire [11:0] in_data,
    output wire        encoder_busy,
    output wire        encoder_overflow,
    output wire        poly_last,

    // Sponge configuration & controls (from mlkem_top)
    input  wire        shake_init,
    input  wire [1:0]  shake_mode,     // 00: SHA3-256
    input  wire [9:0]  squeeze_words,  // 4 words for SHA3-256
    input  wire        msg_in_last,    // Driven on true message boundary (Word 99 for ek)
    input  wire [3:0]  msg_in_bytes,   // 8 bytes for full words

    // Squeeze output from shake_wrapper
    output wire [63:0] shake_out_data,
    output wire        shake_out_valid,
    output wire        shake_out_last,
    input  wire        shake_out_ready,
    output wire        shake_busy,
    output wire        shake_in_ready,

    // Seed rho injection for full 800-byte ek hashing
    input  wire        rho_inject_valid,
    input  wire [63:0] rho_inject_data
);

    wire [63:0] enc_out_data;
    wire        enc_out_valid;

    // Multiplex between byte_encode and rho injection
    wire [63:0] shake_in_data_mux  = rho_inject_valid ? rho_inject_data : enc_out_data;
    wire        shake_in_valid_mux = rho_inject_valid ? 1'b1 : enc_out_valid;

    // Instantiate real byte_encode (D=12)
    byte_encode #(
        .D(12)
    ) u_encode (
        .clk(clk),
        .rst(rst),
        .start_poly(start_poly),
        .busy(encoder_busy),
        .overflow(encoder_overflow),
        .in_valid(in_valid),
        .in_data(in_data),
        .out_data(enc_out_data),
        .out_valid(enc_out_valid),
        .out_ready(shake_in_ready && !rho_inject_valid),
        .poly_last(poly_last)
    );

    // Instantiate real shake_wrapper
    shake_wrapper u_shake (
        .clk(clk),
        .rst(rst),
        .mode(shake_mode),
        .init(shake_init),
        .squeeze_words(squeeze_words),
        .in_data(shake_in_data_mux),
        .in_bytes(msg_in_bytes),
        .in_valid(shake_in_valid_mux),
        .in_last(msg_in_last),
        .in_ready(shake_in_ready),
        .out_data(shake_out_data),
        .out_mask(),
        .out_valid(shake_out_valid),
        .out_last(shake_out_last),
        .out_ready(shake_out_ready),
        .busy(shake_busy)
    );

endmodule

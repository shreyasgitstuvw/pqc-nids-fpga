//==========================================================================
// rtl/crypto/kem/pack_8_to_64.v
//
// 8-bit to 64-bit Byte Stream Packer for ML-KEM-512 Handshake Ingest.
// Bridges the byte-wide packet bus (packet_bus.data[7:0]) to 64-bit word
// interfaces (byte_decode.v, shake_wrapper.v, or Ciphertext BRAM).
//
// Protocol & Byte Ordering:
//   - Ingests 8-bit bytes via in_valid / in_data[7:0] with in_ready handshaking.
//   - Emits 64-bit words via out_valid / out_data[63:0] with out_ready handshaking.
//   - Byte packing convention: Little-endian per FIPS 203 Section 4.2.1
//     and byte_decode.v convention:
//       out_data[ 7: 0] = Byte 0
//       out_data[15: 8] = Byte 1
//       out_data[23:16] = Byte 2
//       out_data[31:24] = Byte 3
//       out_data[39:32] = Byte 4
//       out_data[47:40] = Byte 5
//       out_data[55:48] = Byte 6
//       out_data[63:56] = Byte 7
//
// Handshaking & Skid Buffering:
//   - Assembles 8 bytes into an internal shift register.
//   - When 8 bytes are collected, transfers to a registered output stage.
//   - Uses a registered skid buffer (skid_data, skid_valid) so that if
//     downstream asserts backpressure (!out_ready), the current word is held
//     in out_data, and the next assembled word is safely latched in skid_data.
//   - in_ready is strictly !skid_valid (registered state, no combinational loop
//     and no combinational dependency on in_valid).
//   - Supports in_eof (end-of-frame): flushes partial or full word if in_eof is asserted,
//     flagging out_last alongside the final word.
//
// Timing & Resource Estimates (XC7Z020 @ 100 MHz, estimated, pre-synthesis):
//   - Latency: Exactly 8 cycles to accumulate first 64-bit word
//   - DSP48E1: 0 slices
//   - Slice LUTs: ~45-65 LUTs (estimated, pre-synthesis)
//   - Slice FFs: ~195-205 registers (estimated, pre-synthesis)
//==========================================================================

`timescale 1ns / 1ps

module pack_8_to_64 (
    input  wire        clk,
    input  wire        rst,

    // Ingress Byte Stream (from packet bus / parser)
    input  wire        in_valid,
    input  wire [7:0]  in_data,
    input  wire        in_eof,      // End-of-frame strobe
    output wire        in_ready,

    // Egress 64-Bit Word Stream (to byte_decode / BRAM / shake_wrapper)
    output reg         out_valid,
    output reg  [63:0] out_data,
    output reg         out_last,    // Asserted with final word of frame
    output reg  [3:0]  out_bytes,   // Number of valid bytes in this word (1..8 when out_valid=1, 0 otherwise)
    input  wire        out_ready
);

    // Accumulator State (bytes 0..6; byte 7 is bypassed directly)
    reg [55:0] acc_reg;
    reg [2:0]  byte_cnt;

    // Skid Buffer State
    reg [63:0] skid_data;
    reg        skid_last;
    reg [3:0]  skid_bytes;
    reg        skid_valid;

    // in_ready is deasserted only when the skid buffer is holding a word
    assign in_ready = !rst && !skid_valid;

    wire byte_handshake = in_valid && in_ready;
    wire output_retire  = out_valid && out_ready;

    // Partial word assembly multiplexer
    reg [63:0] partial_word;
    reg [3:0]  partial_bytes;
    always @(*) begin
        case (byte_cnt)
            3'd0: begin partial_word = {56'd0, in_data}; partial_bytes = 4'd1; end
            3'd1: begin partial_word = {48'd0, in_data, acc_reg[ 7: 0]}; partial_bytes = 4'd2; end
            3'd2: begin partial_word = {40'd0, in_data, acc_reg[15: 0]}; partial_bytes = 4'd3; end
            3'd3: begin partial_word = {32'd0, in_data, acc_reg[23: 0]}; partial_bytes = 4'd4; end
            3'd4: begin partial_word = {24'd0, in_data, acc_reg[31: 0]}; partial_bytes = 4'd5; end
            3'd5: begin partial_word = {16'd0, in_data, acc_reg[39: 0]}; partial_bytes = 4'd6; end
            3'd6: begin partial_word = { 8'd0, in_data, acc_reg[47: 0]}; partial_bytes = 4'd7; end
            3'd7: begin partial_word = {       in_data, acc_reg[55: 0]}; partial_bytes = 4'd8; end
        endcase
    end

    wire word_ready      = byte_handshake && ((byte_cnt == 3'd7) || in_eof);
    wire [63:0] new_data = partial_word;
    wire [3:0]  new_bytes = partial_bytes;
    wire        new_last = in_eof;

    // -------------------------------------------------------------------------
    // Sequential Control & Datapath
    // -------------------------------------------------------------------------
    always @(posedge clk) begin
        if (rst) begin
            acc_reg     <= 56'd0;
            byte_cnt    <= 3'd0;
            skid_data   <= 64'd0;
            skid_last   <= 1'b0;
            skid_bytes  <= 4'd0;
            skid_valid  <= 1'b0;
            out_valid   <= 1'b0;
            out_data    <= 64'd0;
            out_last    <= 1'b0;
            out_bytes   <= 4'd0;
        end else begin
            // -----------------------------------------------------------------
            // 1. Output Register and Skid Buffer Management
            // -----------------------------------------------------------------
            if (output_retire) begin
                if (skid_valid) begin
                    // Skid buffer dumps to output
                    out_valid  <= 1'b1;
                    out_data   <= skid_data;
                    out_last   <= skid_last;
                    out_bytes  <= skid_bytes;
                    skid_valid <= 1'b0;
                end else if (word_ready) begin
                    // Direct bypass to output
                    out_valid  <= 1'b1;
                    out_data   <= new_data;
                    out_last   <= new_last;
                    out_bytes  <= new_bytes;
                end else begin
                    out_valid  <= 1'b0;
                    out_last   <= 1'b0;
                    out_bytes  <= 4'd0;
                end
            end else if (!out_valid) begin
                // Output register is currently empty
                if (skid_valid) begin
                    out_valid  <= 1'b1;
                    out_data   <= skid_data;
                    out_last   <= skid_last;
                    out_bytes  <= skid_bytes;
                    skid_valid <= 1'b0;
                end else if (word_ready) begin
                    out_valid  <= 1'b1;
                    out_data   <= new_data;
                    out_last   <= new_last;
                    out_bytes  <= new_bytes;
                end
            end else begin
                // Output is occupied and NOT retiring (stalled by downstream)
                if (word_ready) begin
                    skid_valid <= 1'b1;
                    skid_data  <= new_data;
                    skid_last  <= new_last;
                    skid_bytes <= new_bytes;
                end
            end

            // -----------------------------------------------------------------
            // 2. Accumulator Ingestion
            // -----------------------------------------------------------------
            if (byte_handshake) begin
                if ((byte_cnt == 3'd7) || in_eof) begin
                    byte_cnt <= 3'd0;
                end else begin
                    case (byte_cnt)
                        3'd0: acc_reg[ 7: 0] <= in_data;
                        3'd1: acc_reg[15: 8] <= in_data;
                        3'd2: acc_reg[23:16] <= in_data;
                        3'd3: acc_reg[31:24] <= in_data;
                        3'd4: acc_reg[39:32] <= in_data;
                        3'd5: acc_reg[47:40] <= in_data;
                        3'd6: acc_reg[55:48] <= in_data;
                        default: ;
                    endcase
                    byte_cnt <= byte_cnt + 3'd1;
                end
            end
        end
    end

endmodule

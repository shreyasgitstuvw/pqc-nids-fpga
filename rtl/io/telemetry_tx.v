//==========================================================================
// rtl/io/telemetry_tx.v
//
// Periodic counter readout over the Pmod USB-UART transmit pin, so the host can
// display live drop statistics. This is the source behind
// demo/config/demo_config.py's PORT_FPGA_DEBUG readout and the live
// command-line display in the execution plan's walkthrough step 7.
//
// FRAME FORMAT (52 bytes, big-endian counters)
//   byte  0      0xA5          magic
//   byte  1      0x5A          magic
//   byte  2      status        bit0 = a session is ESTABLISHED
//                              bit1 = fifo_overflow latched in aead_framer
//                              bit2 = kem busy
//                              bits 7:3 reserved, zero
//   bytes 3..50  12 counters, 4 bytes each, most significant byte first:
//                  crc_fail, frame_timeout, malformed, signature,
//                  flood, scan, bad_tag, handshake_key_invalid,
//                  total_drops, total_passed, lane_timeout, stray_verdict
//   byte  51     checksum: 8-bit sum of bytes 0..50, two's complement negated,
//                so the sum of the whole frame is zero mod 256
//
// A frame is emitted every PERIOD_MS. The counters are sampled once into a
// shadow register at the start of a frame, so a frame is always a coherent
// snapshot rather than a mix of values from different cycles.
//
// Resource estimate (XC7Z020, pre-synthesis): ~450 FFs (the shadow copy of
//   twelve 32-bit counters), ~120 LUTs. No BRAM, no DSP.
//==========================================================================

`timescale 1ns / 1ps

module telemetry_tx #(
    parameter integer CLK_HZ    = 100_000_000,
    parameter integer PERIOD_MS = 250           // demo_config.DISPLAY_REFRESH_S
) (
    input  wire        clk,
    input  wire        rst,

    input  wire [31:0] cnt_crc_fail,
    input  wire [31:0] cnt_frame_timeout,
    input  wire [31:0] cnt_malformed,
    input  wire [31:0] cnt_signature,
    input  wire [31:0] cnt_flood,
    input  wire [31:0] cnt_scan,
    input  wire [31:0] cnt_bad_tag,
    input  wire [31:0] cnt_handshake_key_invalid,
    input  wire [31:0] cnt_total_drops,
    input  wire [31:0] cnt_total_passed,
    input  wire [31:0] cnt_lane_timeout,
    input  wire [31:0] cnt_stray_verdict,

    input  wire        session_established,
    input  wire        fifo_overflow,
    input  wire        kem_busy,

    // uart_tx.v interface
    output reg  [7:0]  tx_data,
    output reg         tx_valid,
    input  wire        tx_busy
);

    localparam integer TICK_CYCLES = (CLK_HZ / 1000) * PERIOD_MS;
    localparam integer FRAME_BYTES = 52;

    reg [31:0] tick;
    reg [5:0]  idx;          // 0..51
    reg        sending;
    reg [7:0]  csum;

    // Coherent snapshot of everything the frame reports.
    reg [383:0] shadow;      // 12 counters x 32 bits
    reg [7:0]   status_r;

    // Counter i (0 = crc_fail) occupies shadow[(11-i)*32 +: 32], so byte
    // extraction below walks from the most significant word downwards.
    wire [383:0] live = {cnt_crc_fail, cnt_frame_timeout, cnt_malformed,
                         cnt_signature, cnt_flood, cnt_scan, cnt_bad_tag,
                         cnt_handshake_key_invalid, cnt_total_drops,
                         cnt_total_passed, cnt_lane_timeout, cnt_stray_verdict};

    // Byte 3 is the MSB of the first counter, so byte n (3..50) is
    // shadow[383 - 8*(n-3) -: 8].
    wire [5:0]  b_off   = idx - 6'd3;
    wire [8:0]  bit_top = 9'd383 - {b_off, 3'd0};

    reg [7:0] next_byte;
    always @(*) begin
        case (idx)
            6'd0:  next_byte = 8'hA5;
            6'd1:  next_byte = 8'h5A;
            6'd2:  next_byte = status_r;
            6'd51: next_byte = (~csum) + 8'd1;   // frame sums to zero mod 256
            default: next_byte = shadow[bit_top -: 8];
        endcase
    end

    always @(posedge clk) begin
        if (rst) begin
            tick     <= 32'd0;
            idx      <= 6'd0;
            sending  <= 1'b0;
            tx_valid <= 1'b0;
            tx_data  <= 8'd0;
            csum     <= 8'd0;
            shadow   <= 384'd0;
            status_r <= 8'd0;
        end else begin
            tx_valid <= 1'b0;

            if (!sending) begin
                if (tick >= TICK_CYCLES[31:0]) begin
                    tick     <= 32'd0;
                    sending  <= 1'b1;
                    idx      <= 6'd0;
                    csum     <= 8'd0;
                    // latch a coherent snapshot for the whole frame
                    shadow   <= live;
                    status_r <= {5'd0, kem_busy, fifo_overflow,
                                 session_established};
                end else begin
                    tick <= tick + 32'd1;
                end
            end else if (!tx_busy && !tx_valid) begin
                tx_data  <= next_byte;
                tx_valid <= 1'b1;
                if (idx != 6'd51)
                    csum <= csum + next_byte;
                if (idx == (FRAME_BYTES[5:0] - 6'd1)) begin
                    sending <= 1'b0;
                    idx     <= 6'd0;
                end else begin
                    idx <= idx + 6'd1;
                end
            end
        end
    end

endmodule

//==============================================================================
// rtl/ingress/deframer.v
//
// Ingress Wire Deframer, Length Decoder, CRC-32 Validator, and Watchdog Timer.
//
// Hardware Role:
//   Sits between the input byte stream (e.g. uart_rx or input FIFO) and the
//   Ethernet/IP/TCP/UDP header parser (parser.v).
//
// Wire Framing Scheme (docs/Member A/interface_contract.md §1 & §2):
//   [ 2 bytes: total_length (big-endian) ] [ payload bytes... ] [ 4 bytes: CRC-32 ]
//   where total_length includes the 2-byte header, the payload, and the 4-byte CRC.
//   Minimum valid frame length is 6 bytes (2B length + 0B payload + 4B CRC).
//
// Link-Layer Integrity & Drop-Engine Verdict:
//   - Instantiates rtl/ingress/crc32.v to compute CRC-32 inline across payload bytes.
//   - Compares calculated CRC with received 4-byte big-endian CRC.
//   - On CRC mismatch: pulses verdict_valid with RC_CRC_FAIL (4'h1).
//   - On length < 6: pulses verdict_valid with RC_MALFORMED (4'h3).
//   - On mid-frame stall exceeding TIMEOUT_CYCLES (50,000 cycles = 500 us at 100 MHz):
//     resets FSM to IDLE, flushes state, does NOT assert eof, and pulses
//     verdict_valid with RC_FRAME_TIMEOUT (4'h2).
//
// Interface Conventions:
//   - Verilog-2001, single 100 MHz clock domain (`clk`), synchronous reset (`rst`).
//   - Zero latches, registered outputs, clean 1-cycle strobes.
//
// Owner: Member A (Ingress, Parser, and Interface Contract)
//==============================================================================

`include "reason_codes.vh"

module deframer #(
    parameter TIMEOUT_CYCLES = 50000   // 500 us at 100 MHz (interface_contract.md §1)
) (
    input  wire        clk,            // 100 MHz system clock
    input  wire        rst,            // Synchronous active-high reset

    // Input byte stream from PHY / UART
    input  wire        in_valid,       // Incoming byte valid qualifier
    input  wire [7:0]  in_data,        // Incoming byte data

    // Deframed Ethernet payload stream to parser.v
    output reg         out_valid,      // Asserted for each valid payload byte
    output reg  [7:0]  out_data,       // Deframed payload byte
    output reg         out_sof,        // Start-of-frame strobe (first payload byte)
    output reg         out_eof,        // End-of-frame strobe (last payload byte)

    // Drop-engine verdict interface (interface_contract.md §6)
    output reg         verdict_valid,  // 1-cycle strobe: verdict ready
    output reg         verdict_fail,   // 1 = reject/drop frame; 0 = pass
    output reg  [3:0]  verdict_code    // Reason code (RC_* from reason_codes.vh)
);

    // FSM State Encoding
    localparam STATE_IDLE    = 3'd0;   // Awaiting high byte of total_length
    localparam STATE_LEN_LO  = 3'd1;   // Awaiting low byte of total_length
    localparam STATE_PAYLOAD = 3'd2;   // Streaming payload bytes & accumulating CRC
    localparam STATE_CRC0    = 3'd3;   // Receiving CRC byte 0 [31:24]
    localparam STATE_CRC1    = 3'd4;   // Receiving CRC byte 1 [23:16]
    localparam STATE_CRC2    = 3'd5;   // Receiving CRC byte 2 [15:8]
    localparam STATE_CRC3    = 3'd6;   // Receiving CRC byte 3 [7:0] & comparing

    reg [2:0]  state;

    // Length and progress counters
    reg [7:0]  len_hi;
    reg [15:0] payload_len;
    reg [15:0] payload_cnt;

    // CRC receive buffer (holds first 3 incoming CRC bytes)
    reg [23:0] rx_crc_buf;

    // Watchdog timeout counter
    reg [31:0] watchdog_cnt;

    // Instantiation signals for crc32.v
    reg         crc_init;
    reg         crc_in_valid;
    reg  [7:0]  crc_in_data;
    reg         crc_eof;
    wire [31:0] crc_out;
    wire        crc_ready;

    // Instantiate Parallel 8-bit CRC-32 Engine
    crc32 u_crc32 (
        .clk       (clk),
        .rst       (rst),
        .init      (crc_init),
        .in_valid  (crc_in_valid),
        .in_data   (crc_in_data),
        .eof       (crc_eof),
        .crc_out   (crc_out),
        .crc_valid (crc_ready)
    );

    // Combinational length and CRC comparison signals
    wire [15:0] total_len_comb = {len_hi, in_data};
    wire [31:0] full_rx_crc    = {rx_crc_buf, in_data};
    wire [31:0] expected_crc   = (payload_len == 16'd0) ? 32'h00000000 : crc_out;
    wire        crc_matches    = (full_rx_crc == expected_crc);

    always @(posedge clk) begin
        if (rst) begin
            state         <= STATE_IDLE;
            len_hi        <= 8'h00;
            payload_len   <= 16'd0;
            payload_cnt   <= 16'd0;
            rx_crc_buf    <= 24'h000000;
            watchdog_cnt  <= 32'd0;

            out_valid     <= 1'b0;
            out_data      <= 8'h00;
            out_sof       <= 1'b0;
            out_eof       <= 1'b0;

            verdict_valid <= 1'b0;
            verdict_fail  <= 1'b0;
            verdict_code  <= `RC_NONE;

            crc_init      <= 1'b0;
            crc_in_valid  <= 1'b0;
            crc_in_data   <= 8'h00;
            crc_eof       <= 1'b0;
        end else begin
            // Default 1-cycle output strobes
            out_valid     <= 1'b0;
            out_sof       <= 1'b0;
            out_eof       <= 1'b0;
            verdict_valid <= 1'b0;
            crc_init      <= 1'b0;
            crc_in_valid  <= 1'b0;
            crc_eof       <= 1'b0;

            // Watchdog Timeout Monitor
            // Active whenever a frame is in-progress (state != STATE_IDLE).
            // Resets to 0 whenever a valid byte arrives; increments every idle cycle.
            if (state != STATE_IDLE) begin
                if (in_valid) begin
                    watchdog_cnt <= 32'd0;
                end else begin
                    watchdog_cnt <= watchdog_cnt + 32'd1;
                    if (watchdog_cnt + 32'd1 >= TIMEOUT_CYCLES) begin
                        // Frame arrival timed out: abort partial frame
                        state         <= STATE_IDLE;
                        watchdog_cnt  <= 32'd0;
                        verdict_valid <= 1'b1;
                        verdict_fail  <= 1'b1;
                        verdict_code  <= `RC_FRAME_TIMEOUT;
                    end
                end
            end else begin
                watchdog_cnt <= 32'd0;
            end

            // Main FSM Processing
            case (state)
                STATE_IDLE: begin
                    if (in_valid) begin
                        len_hi       <= in_data;
                        watchdog_cnt <= 32'd0;
                        state        <= STATE_LEN_LO;
                    end
                end

                STATE_LEN_LO: begin
                    if (in_valid) begin
                        if (total_len_comb < 16'd6) begin
                            // Malformed length: frame cannot even hold length + CRC
                            verdict_valid <= 1'b1;
                            verdict_fail  <= 1'b1;
                            verdict_code  <= `RC_MALFORMED;
                            state         <= STATE_IDLE;
                        end else begin
                            payload_len  <= total_len_comb - 16'd6;
                            payload_cnt  <= 16'd0;
                            if (total_len_comb == 16'd6) begin
                                // 0-byte payload: proceed straight to CRC
                                crc_init <= 1'b1;
                                state    <= STATE_CRC0;
                            end else begin
                                state    <= STATE_PAYLOAD;
                            end
                        end
                    end
                end

                STATE_PAYLOAD: begin
                    if (in_valid) begin
                        // Drive payload byte to parser.v
                        out_valid    <= 1'b1;
                        out_data     <= in_data;
                        out_sof      <= (payload_cnt == 16'd0);
                        out_eof      <= (payload_cnt == payload_len - 16'd1);

                        // Accumulate byte into crc32.v
                        crc_init     <= (payload_cnt == 16'd0);
                        crc_in_valid <= 1'b1;
                        crc_in_data  <= in_data;
                        crc_eof      <= (payload_cnt == payload_len - 16'd1);

                        if (payload_cnt == payload_len - 16'd1) begin
                            state <= STATE_CRC0;
                        end else begin
                            payload_cnt <= payload_cnt + 16'd1;
                        end
                    end
                end

                STATE_CRC0: begin
                    if (in_valid) begin
                        rx_crc_buf[23:16] <= in_data;
                        state             <= STATE_CRC1;
                    end
                end

                STATE_CRC1: begin
                    if (in_valid) begin
                        rx_crc_buf[15:8] <= in_data;
                        state            <= STATE_CRC2;
                    end
                end

                STATE_CRC2: begin
                    if (in_valid) begin
                        rx_crc_buf[7:0] <= in_data;
                        state           <= STATE_CRC3;
                    end
                end

                STATE_CRC3: begin
                    if (in_valid) begin
                        verdict_valid <= 1'b1;
                        if (crc_matches) begin
                            // Clean frame: link-layer integrity verified
                            verdict_fail <= 1'b0;
                            verdict_code <= `RC_NONE;
                        end else begin
                            // Corrupted frame: link CRC-32 mismatch
                            verdict_fail <= 1'b1;
                            verdict_code <= `RC_CRC_FAIL;
                        end
                        state <= STATE_IDLE;
                    end
                end

                default: begin
                    state <= STATE_IDLE;
                end
            endcase
        end
    end

endmodule

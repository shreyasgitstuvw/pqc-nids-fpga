//==============================================================================
// rtl/ingress/uart_rx.v
//
// 3 Mbaud UART Receiver with Fractional Baud Accumulator and Metastability Filter.
//
// Hardware Role:
//   Connects to the physical Pmod USB-UART RX pin on the ZedBoard (FTDI FT232RQ).
//   Deserializes incoming 8N1 serial frames and drives `rx_data[7:0]` and `rx_valid`
//   directly into `rtl/ingress/deframer.v`.
//
// Standards & Specifications:
//   - docs/Member A/interface_contract.md §1:
//     Baud rate: 3,000,000 baud (3 Mbaud), 8N1 (8 data bits, no parity, 1 stop bit).
//     Clock: 100 MHz system clock (`clk`), synchronous reset (`rst`).
//   - Fractional Baud Rate Timing:
//     100 MHz / 3 MHz = 33.3333... cycles per bit.
//     Uses an exact fractional accumulator to interleave 33 and 34 cycle bit
//     durations (33, 33, 34 cycles per 3-bit group = exactly 100 cycles),
//     guaranteeing 0.000% long-term accumulated phase error across long frames.
//   - Robustness:
//     2-stage flip-flop synchronizer on asynchronous `rx_pin` to eliminate metastability.
//     Start-bit glitch filtering at mid-bit center.
//     Framing error detection on missing/corrupted stop bit.
//
// Owner: Member A (Ingress, Parser, and Interface Contract)
//==============================================================================

module uart_rx #(
    parameter CLK_FREQ  = 100000000, // 100 MHz system clock
    parameter BAUD_RATE = 3000000    // 3 Mbaud serial link
) (
    input  wire       clk,        // 100 MHz system clock
    input  wire       rst,        // Synchronous active-high reset
    input  wire       rx_pin,     // Asynchronous serial RX line from Pmod

    output reg  [7:0] rx_data,    // Deserialized byte
    output reg        rx_valid,   // 1-cycle strobe: byte successfully received
    output reg        rx_busy,    // High while receiving a frame
    output reg        frame_err   // 1-cycle strobe: stop bit missing/invalid (low)
);

    // Compute integer and remainder counts for fractional divider
    localparam CLKS_PER_BIT = CLK_FREQ / BAUD_RATE;          // 33 for 100M/3M
    localparam REMAINDER    = CLK_FREQ % BAUD_RATE;          // 1,000,000 for 100M/3M

    // FSM States
    localparam STATE_IDLE  = 2'd0;
    localparam STATE_START = 2'd1;
    localparam STATE_DATA  = 2'd2;
    localparam STATE_STOP  = 2'd3;

    reg [1:0]  state;

    // 2-stage synchronizer for asynchronous input pin
    reg        rx_sync_1;
    reg        rx_sync_2;
    reg        rx_sync_prev;

    // Cycle counter within current bit
    reg [15:0] cycle_cnt;
    reg [15:0] target_cycles;

    // Fractional remainder accumulator
    reg [31:0] frac_acc;

    // Data reception registers
    reg [2:0]  bit_idx;
    reg [7:0]  rx_shift;

    // Calculate current bit duration with fractional remainder
    function [15:0] get_bit_period;
        input [31:0] acc;
        begin
            if (acc + REMAINDER >= BAUD_RATE)
                get_bit_period = CLKS_PER_BIT + 1;
            else
                get_bit_period = CLKS_PER_BIT;
        end
    endfunction

    always @(posedge clk) begin
        if (rst) begin
            rx_sync_1     <= 1'b1;
            rx_sync_2     <= 1'b1;
            rx_sync_prev  <= 1'b1;

            state         <= STATE_IDLE;
            cycle_cnt     <= 16'd0;
            target_cycles <= 16'd0;
            frac_acc      <= 32'd0;
            bit_idx       <= 3'd0;
            rx_shift      <= 8'h00;

            rx_data       <= 8'h00;
            rx_valid      <= 1'b0;
            rx_busy       <= 1'b0;
            frame_err     <= 1'b0;
        end else begin
            // Synchronize asynchronous input pin
            rx_sync_1    <= rx_pin;
            rx_sync_2    <= rx_sync_1;
            rx_sync_prev <= rx_sync_2;

            // Default 1-cycle strobes
            rx_valid  <= 1'b0;
            frame_err <= 1'b0;

            case (state)
                STATE_IDLE: begin
                    rx_busy   <= 1'b0;
                    cycle_cnt <= 16'd0;
                    bit_idx   <= 3'd0;

                    // Detect falling edge of start bit (1 -> 0)
                    if (rx_sync_prev == 1'b1 && rx_sync_2 == 1'b0) begin
                        rx_busy       <= 1'b1;
                        frac_acc      <= 32'd0;
                        // Half-bit sampling point for start bit center
                        target_cycles <= (CLKS_PER_BIT / 2); // Cycle 16 at 100M/3M
                        state         <= STATE_START;
                    end
                end

                STATE_START: begin
                    rx_busy <= 1'b1;
                    if (cycle_cnt >= target_cycles) begin
                        cycle_cnt <= 16'd0;
                        // Verify start bit is still low at bit center (glitch filter)
                        if (rx_sync_2 == 1'b0) begin
                            // Calculate full bit period for Data Bit 0
                            target_cycles <= get_bit_period(frac_acc);
                            if (frac_acc + REMAINDER >= BAUD_RATE)
                                frac_acc <= frac_acc + REMAINDER - BAUD_RATE;
                            else
                                frac_acc <= frac_acc + REMAINDER;

                            state <= STATE_DATA;
                        end else begin
                            // Glitch detected: false start bit
                            state <= STATE_IDLE;
                        end
                    end else begin
                        cycle_cnt <= cycle_cnt + 16'd1;
                    end
                end

                STATE_DATA: begin
                    rx_busy <= 1'b1;
                    if (cycle_cnt >= target_cycles - 16'd1) begin
                        cycle_cnt <= 16'd0;
                        // Sample data bit LSB-first at bit center
                        rx_shift[bit_idx] <= rx_sync_2;

                        if (bit_idx == 3'd7) begin
                            // All 8 data bits sampled; compute Stop bit period
                            target_cycles <= get_bit_period(frac_acc);
                            if (frac_acc + REMAINDER >= BAUD_RATE)
                                frac_acc <= frac_acc + REMAINDER - BAUD_RATE;
                            else
                                frac_acc <= frac_acc + REMAINDER;

                            state <= STATE_STOP;
                        end else begin
                            bit_idx <= bit_idx + 3'd1;
                            target_cycles <= get_bit_period(frac_acc);
                            if (frac_acc + REMAINDER >= BAUD_RATE)
                                frac_acc <= frac_acc + REMAINDER - BAUD_RATE;
                            else
                                frac_acc <= frac_acc + REMAINDER;
                        end
                    end else begin
                        cycle_cnt <= cycle_cnt + 16'd1;
                    end
                end

                STATE_STOP: begin
                    rx_busy <= 1'b1;
                    if (cycle_cnt >= target_cycles - 16'd1) begin
                        cycle_cnt <= 16'd0;
                        rx_busy   <= 1'b0;

                        // Check stop bit at center: must be high (1'b1)
                        if (rx_sync_2 == 1'b1) begin
                            rx_data  <= rx_shift;
                            rx_valid <= 1'b1;
                        end else begin
                            frame_err <= 1'b1;
                        end

                        state <= STATE_IDLE;
                    end else begin
                        cycle_cnt <= cycle_cnt + 16'd1;
                    end
                end

                default: begin
                    state <= STATE_IDLE;
                end
            endcase
        end
    end

endmodule

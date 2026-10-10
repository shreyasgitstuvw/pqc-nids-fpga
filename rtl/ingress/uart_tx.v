//==============================================================================
// rtl/ingress/uart_tx.v
//
// 3 Mbaud UART Transmitter with Fractional Baud Accumulator.
//
// Hardware Role:
//   Connects to the physical Pmod USB-UART TX pin on the ZedBoard (FTDI FT232RQ).
//   Serializes outgoing 8N1 frames for egress telemetry, packet reporting, and drop alerts.
//
// Standards & Specifications:
//   - docs/Member A/interface_contract.md §1:
//     Baud rate: 3,000,000 baud (3 Mbaud), 8N1 (8 data bits, no parity, 1 stop bit).
//     Clock: 100 MHz system clock (`clk`), synchronous reset (`rst`).
//   - Fractional Baud Rate Timing:
//     100 MHz / 3 MHz = 33.3333... cycles per bit.
//     Uses matching modulo-3 fractional accumulator to interleave 33 and 34 cycle bit
//     durations (33, 33, 34 cycles per 3-bit group = exactly 100 cycles),
//     guaranteeing 0.000% long-term accumulated phase error.
//
// Owner: Member A (Ingress, Parser, and Interface Contract)
//==============================================================================

module uart_tx #(
    parameter CLK_FREQ  = 100000000, // 100 MHz system clock
    parameter BAUD_RATE = 3000000    // 3 Mbaud serial link
) (
    input  wire       clk,        // 100 MHz system clock
    input  wire       rst,        // Synchronous active-high reset

    input  wire [7:0] tx_data,    // Byte to transmit
    input  wire       tx_valid,   // 1-cycle strobe: begin transmission

    output reg        tx_pin,     // Serial TX line to Pmod (idle high)
    output reg        tx_busy,    // High while transmitting
    output reg        tx_done     // 1-cycle strobe: transmission complete
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

    // Cycle counter within current bit
    reg [15:0] cycle_cnt;
    reg [15:0] target_cycles;

    // Fractional remainder accumulator
    reg [31:0] frac_acc;

    // Transmission shift register and index
    reg [2:0]  bit_idx;
    reg [7:0]  tx_shift;

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
            state         <= STATE_IDLE;
            cycle_cnt     <= 16'd0;
            target_cycles <= 16'd0;
            frac_acc      <= 32'd0;
            bit_idx       <= 3'd0;
            tx_shift      <= 8'h00;

            tx_pin        <= 1'b1; // Idle high
            tx_busy       <= 1'b0;
            tx_done       <= 1'b0;
        end else begin
            // Default 1-cycle strobe
            tx_done <= 1'b0;

            case (state)
                STATE_IDLE: begin
                    tx_pin    <= 1'b1; // Idle high
                    tx_busy   <= 1'b0;
                    cycle_cnt <= 16'd0;
                    bit_idx   <= 3'd0;

                    if (tx_valid) begin
                        tx_shift      <= tx_data;
                        tx_busy       <= 1'b1;
                        tx_pin        <= 1'b0; // Drive Start bit (low)
                        frac_acc      <= 32'd0;

                        target_cycles <= get_bit_period(32'd0);
                        if (REMAINDER >= BAUD_RATE)
                            frac_acc <= REMAINDER - BAUD_RATE;
                        else
                            frac_acc <= REMAINDER;

                        state <= STATE_START;
                    end
                end

                STATE_START: begin
                    tx_busy <= 1'b1;
                    tx_pin  <= 1'b0; // Hold Start bit low

                    if (cycle_cnt >= target_cycles - 16'd1) begin
                        cycle_cnt     <= 16'd0;
                        bit_idx       <= 3'd0;
                        tx_pin        <= tx_shift[0]; // Drive first data bit LSB

                        target_cycles <= get_bit_period(frac_acc);
                        if (frac_acc + REMAINDER >= BAUD_RATE)
                            frac_acc <= frac_acc + REMAINDER - BAUD_RATE;
                        else
                            frac_acc <= frac_acc + REMAINDER;

                        state <= STATE_DATA;
                    end else begin
                        cycle_cnt <= cycle_cnt + 16'd1;
                    end
                end

                STATE_DATA: begin
                    tx_busy <= 1'b1;
                    tx_pin  <= tx_shift[bit_idx];

                    if (cycle_cnt >= target_cycles - 16'd1) begin
                        cycle_cnt <= 16'd0;

                        if (bit_idx == 3'd7) begin
                            // All data bits sent; drive Stop bit (high)
                            tx_pin        <= 1'b1;
                            target_cycles <= get_bit_period(frac_acc);
                            if (frac_acc + REMAINDER >= BAUD_RATE)
                                frac_acc <= frac_acc + REMAINDER - BAUD_RATE;
                            else
                                frac_acc <= frac_acc + REMAINDER;

                            state <= STATE_STOP;
                        end else begin
                            bit_idx       <= bit_idx + 3'd1;
                            tx_pin        <= tx_shift[bit_idx + 3'd1];
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
                    tx_busy <= 1'b1;
                    tx_pin  <= 1'b1; // Stop bit high

                    if (cycle_cnt >= target_cycles - 16'd1) begin
                        cycle_cnt <= 16'd0;
                        tx_done   <= 1'b1; // 1-cycle completion strobe

                        // Check if another byte is ready to transmit immediately
                        if (tx_valid) begin
                            tx_shift      <= tx_data;
                            tx_busy       <= 1'b1;
                            tx_pin        <= 1'b0; // Immediate start bit for next frame
                            target_cycles <= get_bit_period(frac_acc);
                            if (frac_acc + REMAINDER >= BAUD_RATE)
                                frac_acc <= frac_acc + REMAINDER - BAUD_RATE;
                            else
                                frac_acc <= frac_acc + REMAINDER;

                            state <= STATE_START;
                        end else begin
                            tx_busy <= 1'b0;
                            tx_pin  <= 1'b1;
                            state   <= STATE_IDLE;
                        end
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

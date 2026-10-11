//==============================================================================
// sim/uart_loopback.v
//
// Simulation Loopback & Fault-Injection Wrapper for uart_rx.v and uart_tx.v.
//
// Hardware Role:
//   Connects uart_tx to uart_rx in loopback for cocotb verification and standalone
//   regression testing, while providing an override port for injecting line faults,
//   start-bit glitches, and framing errors.
//
// Owner: Member A (Ingress, Parser, and Interface Contract)
//==============================================================================

`timescale 1ns / 1ps

module uart_loopback #(
    parameter CLK_FREQ  = 100000000,
    parameter BAUD_RATE = 3000000
) (
    input  wire       clk,             // 100 MHz system clock
    input  wire       rst,             // Synchronous active-high reset

    // Transmitter Interface
    input  wire [7:0] tx_data,         // Byte to transmit
    input  wire       tx_valid,        // 1-cycle transmit strobe
    output wire       tx_busy,         // Transmitter busy
    output wire       tx_done,         // 1-cycle transmit completion strobe
    output wire       tx_pin,          // Serial TX line

    // Receiver Fault-Injection Controls
    input  wire       rx_override_en,  // 1 = override serial line with rx_override_pin
    input  wire       rx_override_pin, // Direct wire drive for glitches / bad stop bits

    // Receiver Interface
    output wire [7:0] rx_data,         // Deserialized byte
    output wire       rx_valid,        // 1-cycle byte valid strobe
    output wire       rx_busy,         // Receiver busy
    output wire       frame_err        // 1-cycle framing error strobe
);

    wire serial_line;
    assign tx_pin = serial_line;

    wire rx_in_wire = rx_override_en ? rx_override_pin : serial_line;

    // Instantiate Transmitter
    uart_tx #(
        .CLK_FREQ  (CLK_FREQ),
        .BAUD_RATE (BAUD_RATE)
    ) u_tx (
        .clk      (clk),
        .rst      (rst),
        .tx_data  (tx_data),
        .tx_valid (tx_valid),
        .tx_pin   (serial_line),
        .tx_busy  (tx_busy),
        .tx_done  (tx_done)
    );

    // Instantiate Receiver
    uart_rx #(
        .CLK_FREQ  (CLK_FREQ),
        .BAUD_RATE (BAUD_RATE)
    ) u_rx (
        .clk       (clk),
        .rst       (rst),
        .rx_pin    (rx_in_wire),
        .rx_data   (rx_data),
        .rx_valid  (rx_valid),
        .rx_busy   (rx_busy),
        .frame_err (frame_err)
    );

endmodule

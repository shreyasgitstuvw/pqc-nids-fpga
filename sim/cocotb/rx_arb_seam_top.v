// Seam fixture: the REAL rx_arbiter feeding the REAL deframer (+crc32). No model
// of either. 10 clocks/bit and a short watchdog keep simulation time sane.
`timescale 1ns / 1ps
module rx_arb_seam_top #(
    parameter integer TIMEOUT = 3000
) (
    input  wire        clk,
    input  wire        rst,
    input  wire        a_valid,
    input  wire [7:0]  a_data,
    input  wire        b_valid,
    input  wire [7:0]  b_data,
    output wire        arb_valid,
    output wire [7:0]  arb_data,
    output wire        out_valid,
    output wire [7:0]  out_data,
    output wire        out_sof,
    output wire        out_eof,
    output wire        verdict_valid,
    output wire        verdict_fail,
    output wire [3:0]  verdict_code,
    output wire [15:0] drop_a,
    output wire [15:0] drop_b,
    output wire [15:0] fwd_a,
    output wire [15:0] fwd_b,
    output wire        drop_sticky
);
    rx_arbiter #(.CLK_HZ(100_000_000), .BAUD_RATE(10_000_000),
                 .DEFRAMER_TIMEOUT(TIMEOUT), .IDLE_TO(TIMEOUT)) u_arb (
        .clk(clk), .rst(rst),
        .a_valid(a_valid), .a_data(a_data), .b_valid(b_valid), .b_data(b_data),
        .out_valid(arb_valid), .out_data(arb_data),
        .drop_a(drop_a), .drop_b(drop_b), .fwd_a(fwd_a), .fwd_b(fwd_b),
        .drop_sticky(drop_sticky)
    );
    deframer #(.TIMEOUT_CYCLES(TIMEOUT)) u_df (
        .clk(clk), .rst(rst),
        .in_valid(arb_valid), .in_data(arb_data),
        .out_valid(out_valid), .out_data(out_data),
        .out_sof(out_sof), .out_eof(out_eof),
        .verdict_valid(verdict_valid), .verdict_fail(verdict_fail),
        .verdict_code(verdict_code)
    );
endmodule

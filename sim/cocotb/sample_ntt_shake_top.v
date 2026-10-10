//==========================================================================
// sim/cocotb/sample_ntt_shake_top.v
//
// Real-neighbour integration top-level connecting real shake_wrapper.v
// to real sample_ntt.v for ML-KEM-512 matrix A sampling.
//==========================================================================

`timescale 1ns / 1ps

module sample_ntt_shake_top (
    input  wire        clk,
    input  wire        rst,

    // shake_wrapper absorb controls
    input  wire        shake_init,
    input  wire [1:0]  shake_mode,
    input  wire [9:0]  squeeze_words,
    input  wire [63:0] in_data,
    input  wire [3:0]  in_bytes,
    input  wire        in_valid,
    input  wire        in_last,
    output wire        in_ready,
    output wire        shake_busy,

    // sample_ntt controls
    input  wire        sample_start,
    input  wire [2:0]  target_poly_id,
    output wire        sample_busy,
    output wire        sample_done,
    output wire        sample_err_truncated,

    // Shared BRAM write port
    output wire [10:0] poly_mem_addr,
    output wire        poly_mem_we,
    output wire [11:0] poly_mem_wdata
);

    /* verilator lint_off UNUSEDSIGNAL */
    wire [7:0]  shake_out_mask;
    /* verilator lint_on UNUSEDSIGNAL */
    wire [63:0] shake_out_data;
    wire        shake_out_valid;
    wire        shake_out_last;
    wire        sample_in_ready;

    shake_wrapper u_shake (
        .clk           (clk),
        .rst           (rst),
        .mode          (shake_mode),
        .init          (shake_init),
        .squeeze_words (squeeze_words),
        .in_data       (in_data),
        .in_bytes      (in_bytes),
        .in_valid      (in_valid),
        .in_last       (in_last),
        .in_ready      (in_ready),
        .out_data      (shake_out_data),
        .out_mask      (shake_out_mask),
        .out_valid     (shake_out_valid),
        .out_last      (shake_out_last),
        .out_ready     (sample_in_ready),
        .busy          (shake_busy)
    );

    sample_ntt u_sampler (
        .clk            (clk),
        .rst            (rst),
        .start          (sample_start),
        .target_poly_id (target_poly_id),
        .busy           (sample_busy),
        .done           (sample_done),
        .err_truncated  (sample_err_truncated),
        .in_data        (shake_out_data),
        .in_valid       (shake_out_valid),
        .in_ready       (sample_in_ready),
        .in_last        (shake_out_last),
        .poly_mem_addr  (poly_mem_addr),
        .poly_mem_we    (poly_mem_we),
        .poly_mem_wdata (poly_mem_wdata)
    );

endmodule

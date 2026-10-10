//==========================================================================
// rtl/crypto/kem/poly_bank_ram.v
//
// Dual-Port Polynomial RAM Bank (256 words x 12 bits) for ML-KEM-512.
// Implements 1 of the 8 shared polynomial banks.
// Maps to a single Xilinx Block RAM RAMB18E1 primitive on ZedBoard XC7Z020 (estimated, pre-synthesis).
//
// Architecture:
//   - Port A: Synchronous read/write (1-cycle read latency, estimated, pre-synthesis)
//   - Port B: Synchronous read/write (1-cycle read latency, estimated, pre-synthesis)
//   - Size: 256 x 12-bit words (estimated, pre-synthesis)
//==========================================================================

`timescale 1ns / 1ps

module poly_bank_ram (
    input  wire        clk,

    // Port A
    input  wire        we_a,
    input  wire [7:0]  addr_a,
    input  wire [11:0] din_a,
    output reg  [11:0] dout_a,

    // Port B
    input  wire        we_b,
    input  wire [7:0]  addr_b,
    input  wire [11:0] din_b,
    output reg  [11:0] dout_b
);

    reg [11:0] mem [0:255];

    always @(posedge clk) begin
        if (we_a) begin
            mem[addr_a] <= din_a;
        end
        dout_a <= mem[addr_a];
    end

    always @(posedge clk) begin
        if (we_b) begin
            mem[addr_b] <= din_b;
        end
        dout_b <= mem[addr_b];
    end

endmodule

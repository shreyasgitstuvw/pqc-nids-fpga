//==========================================================================
// rtl/control/entropy_src.v
//
// Seed source for mlkem_top.v's rng_valid / rng_data / rng_take handshake.
//
// *** READ THIS BEFORE QUOTING ANY SECURITY PROPERTY ***
//
// This is a DRBG, not a TRNG. It is a 256-bit Galois LFSR stirred with the low
// bits of a free-running counter sampled at every received UART byte. The only
// genuinely unpredictable input is the arrival jitter of host bytes on the
// serial link; everything else is deterministic from reset.
//
// What that is good enough for: a working demonstration in which each
// encapsulation uses a different, non-repeating message m, so the handshake is
// not trivially replayable and the datapath is exercised honestly.
//
// What it is NOT good enough for: any real deployment. ML-KEM's IND-CCA2
// security assumes m is drawn from a uniform distribution that an attacker
// cannot predict. An attacker who knows the reset time and the byte arrival
// pattern can narrow this generator's state. Do not present it as a TRNG in
// the report.
//
// The replacement is the Zynq PS: the PS-7 has a hardware RNG, and the proper
// design reads it over AXI and writes seeds into this module's load port. That
// needs a block design rather than pure RTL, which is why it is not here. The
// load port (seed_load / seed_in) exists so that swap is a wiring change.
//
// PROTOCOL: rng_valid is held high whenever a seed is available. mlkem_top
// pulses rng_take for one cycle when it consumes one; this module then advances
// its state, so no two encapsulations ever see the same word. rng_valid stays
// high because the next word is ready immediately.
//
// Resource estimate (XC7Z020, pre-synthesis): ~300 FFs, ~80 LUTs. No BRAM/DSP.
//==========================================================================

`timescale 1ns / 1ps

module entropy_src #(
    // Build-time constant. Non-zero is required: an all-zero LFSR state is a
    // fixed point and would never advance.
    // (Verilog numbers may not span lines, so this is built from 32-bit words.)
    parameter [255:0] INIT_STATE = {32'hA5A50F1E, 32'h2D3C4B5A, 32'h69788796,
                                    32'h94B5A2C4, 32'hD1E0C3F2, 32'hB40DA51C,
                                    32'h962B873A, 32'h78496958}
) (
    input  wire         clk,
    input  wire         rst,

    // Jitter input: strobe once per received byte (uart_rx.rx_valid).
    input  wire         jitter_strobe,

    // Optional seed injection, for a real RNG behind the PS.
    input  wire         seed_load,
    input  wire [255:0] seed_in,

    // mlkem_top.v entropy handshake
    output wire         rng_valid,
    output wire [255:0] rng_data,
    input  wire         rng_take
);

    reg [255:0] state;
    reg [31:0]  free_cnt;    // free-running, never reset after startup

    // Galois LFSR over GF(2) using the primitive polynomial
    //   x^256 + x^254 + x^251 + x^246 + 1
    // With a right shift the tap mask has bits 255, 253, 250 and 245 set, which
    // is 0xA4200000 in the top 32-bit word. Primitive means the state space is
    // 2^256 - 1, so it cannot short-cycle for any non-zero state.
    localparam [255:0] TAPS = {32'hA4200000, 224'd0};

    wire         feedback  = state[0];
    wire [255:0] lfsr_next = {1'b0, state[255:1]} ^ (feedback ? TAPS : 256'd0);

    // A seed is always available: the next word is ready the cycle after a take.
    assign rng_valid = 1'b1;
    assign rng_data  = state;

    always @(posedge clk) begin
        if (rst) begin
            state    <= INIT_STATE;
            free_cnt <= 32'd0;
        end else begin
            free_cnt <= free_cnt + 32'd1;

            if (seed_load) begin
                // A real RNG word replaces the state outright.
                state <= (seed_in == 256'd0) ? INIT_STATE : seed_in;
            end else if (jitter_strobe) begin
                // Stir in the arrival phase of this byte. This is the only
                // input an attacker does not control from reset alone.
                state <= lfsr_next ^ {224'd0, free_cnt};
            end else if (rng_take) begin
                // Consumed: advance so the next encapsulation sees a new word.
                state <= lfsr_next;
            end
        end
    end

endmodule

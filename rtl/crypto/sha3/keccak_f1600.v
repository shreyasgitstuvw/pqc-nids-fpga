//==========================================================================
// rtl/crypto/sha3/keccak_f1600.v
//
// 1600-bit Keccak permutation core (FIPS 202) for ML-KEM-512 Lane 1.
// Bit-exact synthesizable RTL twin of model/sha3.py (keccak_f1600).
//
// Architecture:
//   - Structure: Iterative datapath, 1 round per clock cycle (24 rounds total).
//   - Latency: Exactly 25 clock cycles from start pulse to done pulse:
//       Cycle 0:      start asserted -> latches din into state_reg, busy -> 1
//       Cycles 1..24: rounds 0..23 computed and registered into state_reg
//       Cycle 25:     done pulses 1, busy -> 0, dout valid and stable
//   - Resource footprint (estimated, XC7Z020 target, 100 MHz):
//       0 DSP slices (100% of DSP budget reserved for NTT/modmul)
//       0 BRAMs
//       ~7 Slice Registers (round_ctr 5 bits, FSM busy/done flags)
//       1600 Data Registers (state_reg 1600 bits, unreset to save routing)
//       ~2,800-3,200 Slice LUTs (~3-5 estimated logic levels for theta/chi/iota)
//   - Throughput (estimated lower bounds at 25 cycles / permutation):
//       KeyGen:  31 perms * 25 cycles = 775 cycles (~7.75 us @ 100 MHz)
//       Encaps:  30 perms * 25 cycles = 750 cycles (~7.50 us @ 100 MHz)
//       Decaps:  30 perms * 25 cycles = 750 cycles (~7.50 us @ 100 MHz)
//   - State register & dout:
//       Single 1600-bit state_reg. dout is continuously assigned to state_reg.
//       No secondary output register. dout is valid on done and remains stable.
//       state_reg does not reset on rst (loaded from din on start) to avoid
//       unnecessary reset routing on 1600 flip-flops.
//   - Safety:
//       start asserted while busy is strictly ignored.
//   - Constants & Rotation offsets:
//       Sourced directly from keccak_rc.vh inside the module scope.
//==========================================================================

module keccak_f1600 (
    input  wire          clk,
    input  wire          rst,       // synchronous active-high reset
    input  wire          start,     // 1-cycle pulse to load din and begin permutation
    input  wire [1599:0] din,       // initial state input
    output wire [1599:0] dout,      // permuted 1600-bit state (valid when done is high)
    output reg           busy,      // asserted while permutation is calculating
    output reg           done       // 1-cycle strobe asserted on completion
);

    `include "keccak_rc.vh"

    // -------------------------------------------------------------------------
    // Internal registers
    // -------------------------------------------------------------------------
    reg [1599:0] state_reg;
    reg [4:0]    round_ctr;

    assign dout = state_reg;

    // 64-bit circular left shift using integer parameter offset
    function [63:0] rotl64;
        input [63:0]  x;
        input integer n;
        begin
            if (n == 0)
                rotl64 = x;
            else
                rotl64 = (x << n[5:0]) | (x >> (7'd64 - {1'b0, n[5:0]}));
        end
    endfunction

    // -------------------------------------------------------------------------
    // State unpack: 25 lanes (64 bits each), addressed as [x][y] where
    // lane index = x + 5*y, x in 0..4, y in 0..4.
    // -------------------------------------------------------------------------
    wire [63:0] st[0:4][0:4];
    genvar gx, gy;
    generate
        for (gy = 0; gy < 5; gy = gy + 1) begin : gen_st_y
            for (gx = 0; gx < 5; gx = gx + 1) begin : gen_st_x
                assign st[gx][gy] = state_reg[64*(gx + 5*gy) +: 64];
            end
        end
    endgenerate

    // -------------------------------------------------------------------------
    // 1. Theta: column parity mixed back into every lane
    // -------------------------------------------------------------------------
    wire [63:0] c[0:4];
    wire [63:0] d[0:4];
    wire [63:0] theta_out[0:4][0:4];

    generate
        for (gx = 0; gx < 5; gx = gx + 1) begin : gen_theta_c
            assign c[gx] = st[gx][0] ^ st[gx][1] ^ st[gx][2] ^ st[gx][3] ^ st[gx][4];
        end

        assign d[0] = c[4] ^ rotl64(c[1], 1);
        assign d[1] = c[0] ^ rotl64(c[2], 1);
        assign d[2] = c[1] ^ rotl64(c[3], 1);
        assign d[3] = c[2] ^ rotl64(c[4], 1);
        assign d[4] = c[3] ^ rotl64(c[0], 1);

        for (gy = 0; gy < 5; gy = gy + 1) begin : gen_theta_out_y
            for (gx = 0; gx < 5; gx = gx + 1) begin : gen_theta_out_x
                assign theta_out[gx][gy] = st[gx][gy] ^ d[gx];
            end
        end
    endgenerate

    // -------------------------------------------------------------------------
    // 2. Rho & Pi: rotate each lane by ROTC[x][y], then permute coordinates:
    //    new_x = y, new_y = (2*x + 3*y) % 5
    //    B[new_x][new_y] = rotl64(theta_out[x][y], ROTC[x][y])
    // Sourced directly from generated keccak_rc.vh constants.
    // -------------------------------------------------------------------------
    wire [63:0] b[0:4][0:4];

    // Column 0: x = 0
    assign b[0][0] = rotl64(theta_out[0][0], KECCAK_ROT_0_0);
    assign b[1][3] = rotl64(theta_out[0][1], KECCAK_ROT_0_1);
    assign b[2][1] = rotl64(theta_out[0][2], KECCAK_ROT_0_2);
    assign b[3][4] = rotl64(theta_out[0][3], KECCAK_ROT_0_3);
    assign b[4][2] = rotl64(theta_out[0][4], KECCAK_ROT_0_4);

    // Column 1: x = 1
    assign b[0][2] = rotl64(theta_out[1][0], KECCAK_ROT_1_0);
    assign b[1][0] = rotl64(theta_out[1][1], KECCAK_ROT_1_1);
    assign b[2][3] = rotl64(theta_out[1][2], KECCAK_ROT_1_2);
    assign b[3][1] = rotl64(theta_out[1][3], KECCAK_ROT_1_3);
    assign b[4][4] = rotl64(theta_out[1][4], KECCAK_ROT_1_4);

    // Column 2: x = 2
    assign b[0][4] = rotl64(theta_out[2][0], KECCAK_ROT_2_0);
    assign b[1][2] = rotl64(theta_out[2][1], KECCAK_ROT_2_1);
    assign b[2][0] = rotl64(theta_out[2][2], KECCAK_ROT_2_2);
    assign b[3][3] = rotl64(theta_out[2][3], KECCAK_ROT_2_3);
    assign b[4][1] = rotl64(theta_out[2][4], KECCAK_ROT_2_4);

    // Column 3: x = 3
    assign b[0][1] = rotl64(theta_out[3][0], KECCAK_ROT_3_0);
    assign b[1][4] = rotl64(theta_out[3][1], KECCAK_ROT_3_1);
    assign b[2][2] = rotl64(theta_out[3][2], KECCAK_ROT_3_2);
    assign b[3][0] = rotl64(theta_out[3][3], KECCAK_ROT_3_3);
    assign b[4][3] = rotl64(theta_out[3][4], KECCAK_ROT_3_4);

    // Column 4: x = 4
    assign b[0][3] = rotl64(theta_out[4][0], KECCAK_ROT_4_0);
    assign b[1][1] = rotl64(theta_out[4][1], KECCAK_ROT_4_1);
    assign b[2][4] = rotl64(theta_out[4][2], KECCAK_ROT_4_2);
    assign b[3][2] = rotl64(theta_out[4][3], KECCAK_ROT_4_3);
    assign b[4][0] = rotl64(theta_out[4][4], KECCAK_ROT_4_4);

    // -------------------------------------------------------------------------
    // 3. Chi: nonlinear mixing along each row
    // -------------------------------------------------------------------------
    wire [63:0] chi_out[0:4][0:4];
    generate
        for (gy = 0; gy < 5; gy = gy + 1) begin : gen_chi_y
            assign chi_out[0][gy] = b[0][gy] ^ (~b[1][gy] & b[2][gy]);
            assign chi_out[1][gy] = b[1][gy] ^ (~b[2][gy] & b[3][gy]);
            assign chi_out[2][gy] = b[2][gy] ^ (~b[3][gy] & b[4][gy]);
            assign chi_out[3][gy] = b[3][gy] ^ (~b[4][gy] & b[0][gy]);
            assign chi_out[4][gy] = b[4][gy] ^ (~b[0][gy] & b[1][gy]);
        end
    endgenerate

    // -------------------------------------------------------------------------
    // 4. Iota: break round symmetry with per-round constant RC[round_ctr]
    // -------------------------------------------------------------------------
    wire [63:0] rc;
    assign rc = KECCAK_RC_FLAT[64*round_ctr +: 64];

    wire [63:0] round_next[0:4][0:4];
    generate
        for (gy = 0; gy < 5; gy = gy + 1) begin : gen_round_next_y
            for (gx = 0; gx < 5; gx = gx + 1) begin : gen_round_next_x
                if (gx == 0 && gy == 0) begin : gen_iota_0
                    assign round_next[0][0] = chi_out[0][0] ^ rc;
                end else begin : gen_iota_other
                    assign round_next[gx][gy] = chi_out[gx][gy];
                end
            end
        end
    endgenerate

    // Pack 25 lanes back into flat 1600-bit wire
    wire [1599:0] round_next_flat;
    generate
        for (gy = 0; gy < 5; gy = gy + 1) begin : gen_pack_y
            for (gx = 0; gx < 5; gx = gx + 1) begin : gen_pack_x
                assign round_next_flat[64*(gx + 5*gy) +: 64] = round_next[gx][gy];
            end
        end
    endgenerate

    // -------------------------------------------------------------------------
    // Sequential Control & Datapath
    // -------------------------------------------------------------------------
    always @(posedge clk) begin
        if (rst) begin
            round_ctr <= 5'd0;
            busy      <= 1'b0;
            done      <= 1'b0;
        end else begin
            done <= 1'b0; // done is a 1-cycle pulse
            if (!busy) begin
                if (start) begin
                    state_reg <= din;
                    round_ctr <= 5'd0;
                    busy      <= 1'b1;
                end
            end else begin
                // start while busy is strictly ignored
                state_reg <= round_next_flat;
                if (round_ctr == 5'd23) begin
                    round_ctr <= 5'd0;
                    busy      <= 1'b0;
                    done      <= 1'b1;
                end else begin
                    round_ctr <= round_ctr + 5'd1;
                end
            end
        end
    end

endmodule

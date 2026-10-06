// rtl/crypto/chacha_poly/poly1305.v
//
// Poly1305 One-Time MAC Authenticator -- RFC 8439 Section 2.5
// Member D (@control)
//
// Architecture & Mathematical Foundation:
// =======================================
// Computes a 16-byte authenticator for an arbitrary-length message using a
// 32-byte one-time key (r, s):
//   - r = clamped key[127:0]  (128-bit polynomial evaluation point)
//   - s = key[255:128]         (128-bit secret offset)
//
// Polynomial Accumulation over Prime Field GF(2^130 - 5):
//   For each 16-byte chunk:
//     n = chunk_bytes_as_le_int + 2^(8 * chunk_len)  (appends 0x01 byte)
//     acc = ((acc + n) * r) mod (2^130 - 5)
//
// Reduction modulo 2^130 - 5:
//   Exploits 2^130 = 5 mod (2^130 - 5).
//   For 259-bit product P = P_hi * 2^130 + P_lo:
//     S1 = P_lo + (P_hi * 5)
//     S2 = S1[129:0] + (S1[132:130] * 5)
//     Followed by conditional subtraction of (2^130 - 5).
//
// Final Tag Generation & Egress:
//   tag = (acc + s) mod 2^128
//   tag_ok = (tag == expected_tag)
//   Asserts uniform verdict interface to drop_engine.v (RC_BAD_TAG = 4'h7).
//   Drives Section 3.1 pt_tag_ok / pt_tag_valid to qualify cam_matcher.v.
//
// Constraints: Verilog-2001, single clk, sync active-high rst, registered outputs,
// no latches, no DSPs, no BRAMs.

`timescale 1ns / 1ps
`include "reason_codes.vh"

module poly1305 (
    input  wire         clk,
    input  wire         rst,

    // ---- Key Configuration ---------------------------------------------------
    input  wire         key_valid,      // 1-cycle strobe: load 32-byte one-time key
    input  wire [255:0] key,            // key[127:0]=r, key[255:128]=s

    // ---- Streaming Byte Interface (Inline with Packet / Ciphertext) ----------
    input  wire         msg_valid,      // Message byte valid
    input  wire [7:0]   msg_data,       // Message byte
    input  wire         msg_sof,        // First byte of message/packet
    input  wire         msg_eof,        // Last byte of message/packet

    // ---- Direct Block Interface (Alternative fast block feed) ----------------
    input  wire         blk_valid,      // 1-cycle strobe: feed 128-bit block
    input  wire [127:0] blk_data,       // Block data
    input  wire [4:0]   blk_len,        // Number of valid bytes (1..16)
    input  wire         blk_last,       // 1 if this is the final block of message

    // ---- Expected Tag for Verification ---------------------------------------
    input  wire [127:0] expected_tag,

    // ---- Outputs & Status ----------------------------------------------------
    output wire         blk_ready,      // 1 = ready to accept blk_valid
    output reg          busy,
    output reg          tag_valid,      // 1-cycle strobe: tag compute complete
    output reg  [127:0] tag_out,        // 16-byte computed Poly1305 tag
    output reg          tag_ok,         // 1 = tag matches expected_tag, 0 = bad tag

    // ---- Plaintext Inspection Bus Qualification (Contract v1.1.0 §3.1) -------
    output reg          pt_tag_ok,      // Qualifies packet scanned by cam_matcher
    output reg          pt_tag_valid,   // 1-cycle strobe: pt_tag_ok valid

    // ---- Uniform Drop Engine Verdict Interface (Contract Section 6) ----------
    output reg          v_poly_valid,   // 1-cycle strobe to drop_engine
    output reg          v_poly_fail,    // 1 = reject (bad tag), 0 = pass
    output reg  [3:0]   v_poly_reason   // 4'h7 (RC_BAD_TAG) if fail, else 4'h0
);

    // =========================================================================
    // Key clamping per RFC 8439 Section 2.5:
    // r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
    // =========================================================================
    localparam [127:0] R_CLAMP_MASK = 128'h0ffffffc0ffffffc0ffffffc0fffffff;
    localparam [130:0] P_PRIME      = {1'b1, 130'd0} - 131'd5; // 2^130 - 5

    reg [127:0] r_reg;
    reg [127:0] s_reg;

    // =========================================================================
    // State Machine
    // =========================================================================
    localparam [2:0] S_IDLE        = 3'd0;
    localparam [2:0] S_BUF_WAIT    = 3'd1;
    localparam [2:0] S_MUL_LO      = 3'd2;
    localparam [2:0] S_MUL_HI      = 3'd3;
    localparam [2:0] S_REDUCE      = 3'd4;
    localparam [2:0] S_FINALIZE    = 3'd5;

    reg [2:0] state;
    assign blk_ready = (state == S_IDLE) || (state == S_BUF_WAIT);

    // 130-bit polynomial accumulator
    reg [129:0] acc;

    // Byte assembly buffer
    reg [7:0]   buf_bytes [0:15];
    reg [3:0]   buf_count;
    reg         eof_seen;

    // Current chunk under evaluation
    reg [130:0] cur_a;      // acc + n (at most 131 bits)
    reg [194:0] prod_lo;    // cur_a * r[63:0]
    reg [258:0] full_prod;  // cur_a * r (at most 259 bits)
    reg         is_last_chunk;

    // =========================================================================
    // Construct 129-bit n from buffer bytes (little-endian + append 0x01 byte)
    // =========================================================================
    function [128:0] build_n;
        input [4:0] len;
        input [7:0] in_byte;
        input       use_in_byte;
        reg [127:0] bdata;
        reg [128:0] pad_bit;
        integer j;
        begin
            bdata = 128'd0;
            for (j = 0; j < 16; j = j + 1) begin
                if (use_in_byte && (j == ({27'd0, len} - 32'd1)))
                    bdata[j*8 +: 8] = in_byte;
                else if (j < len)
                    bdata[j*8 +: 8] = buf_bytes[j];
            end
            pad_bit = 129'd1 << (len * 8);
            build_n = {1'b0, bdata} | pad_bit;
        end
    endfunction

    // =========================================================================
    // Sequential Control Logic
    // =========================================================================
    integer idx;

    always @(posedge clk) begin
        if (rst) begin
            state         <= S_IDLE;
            busy          <= 1'b0;
            tag_valid     <= 1'b0;
            tag_out       <= 128'd0;
            tag_ok        <= 1'b0;
            pt_tag_ok     <= 1'b0;
            pt_tag_valid  <= 1'b0;
            v_poly_valid  <= 1'b0;
            v_poly_fail   <= 1'b0;
            v_poly_reason <= `RC_NONE;

            r_reg         <= 128'd0;
            s_reg         <= 128'd0;
            acc           <= 130'd0;
            buf_count     <= 4'd0;
            eof_seen      <= 1'b0;
            cur_a         <= 131'd0;
            prod_lo       <= 195'd0;
            full_prod     <= 259'd0;
            is_last_chunk <= 1'b0;

            for (idx = 0; idx < 16; idx = idx + 1)
                buf_bytes[idx] <= 8'd0;
        end else begin
            // Default: clear 1-cycle output strobes
            tag_valid    <= 1'b0;
            pt_tag_valid <= 1'b0;
            v_poly_valid <= 1'b0;

            // -----------------------------------------------------------------
            // Key Latch
            // -----------------------------------------------------------------
            if (key_valid) begin
                r_reg     <= key[127:0] & R_CLAMP_MASK;
                s_reg     <= key[255:128];
                acc       <= 130'd0;
                eof_seen  <= 1'b0;
                buf_count <= 4'd0;
            end

            // -----------------------------------------------------------------
            // Main Processing FSM
            // -----------------------------------------------------------------
            case (state)
                S_IDLE: begin
                    busy <= 1'b0;
                    if (msg_sof || (msg_valid && !busy)) begin
                        // Start of new streaming message
                        acc        <= 130'd0;
                        buf_count  <= 4'd0;
                        eof_seen   <= 1'b0;
                        busy       <= 1'b1;

                        if (msg_valid) begin
                            buf_bytes[0] <= msg_data;
                            buf_count    <= 4'd1;
                            if (msg_eof) begin
                                eof_seen <= 1'b1;
                                state    <= S_BUF_WAIT;
                            end else begin
                                state    <= S_BUF_WAIT;
                            end
                        end else begin
                            state <= S_BUF_WAIT;
                        end
                    end else if (blk_valid) begin : blk_direct
                        // Direct block injection
                        busy      <= 1'b1;
                        eof_seen  <= 1'b0;
                        buf_count <= 4'd0;
                        if (blk_len == 5'd0) begin
                            // Empty message: direct to finalize
                            acc   <= 130'd0;
                            state <= S_FINALIZE;
                        end else begin : blk_direct_calc
                            reg [128:0] n_blk;
                            n_blk = {1'b0, blk_data} | (129'd1 << (blk_len * 8));
                            cur_a <= {2'b00, n_blk};
                            is_last_chunk <= blk_last;
                            state <= S_MUL_LO;
                        end
                    end
                end

                S_BUF_WAIT: begin
                    // Accumulate streaming bytes into 16-byte chunks
                    if (msg_valid) begin
                        buf_bytes[buf_count] <= msg_data;
                        if (msg_eof) begin
                            // Last byte arrives
                            begin : blk_eof_trigger
                                reg [128:0] n_chunk;
                                n_chunk = build_n({1'b0, buf_count} + 5'd1, msg_data, 1'b1);
                                cur_a   <= acc + {2'b00, n_chunk};
                                is_last_chunk <= 1'b1;
                                buf_count     <= 4'd0;
                                state         <= S_MUL_LO;
                            end
                        end else if (buf_count == 4'd15) begin
                            // Full 16-byte chunk ready
                            begin : blk_full_chunk
                                reg [128:0] n_chunk;
                                n_chunk = build_n(5'd16, msg_data, 1'b1);
                                cur_a   <= acc + {2'b00, n_chunk};
                                is_last_chunk <= 1'b0;
                                buf_count     <= 4'd0;
                                state         <= S_MUL_LO;
                            end
                        end else begin
                            buf_count <= buf_count + 4'd1;
                        end
                    end else if (eof_seen) begin
                        // Final chunk trigger if eof arrived without byte in this cycle
                        if (buf_count > 4'd0) begin : blk_rem_chunk
                            reg [128:0] n_chunk;
                            n_chunk = build_n({1'b0, buf_count}, 8'd0, 1'b0);
                            cur_a   <= acc + {2'b00, n_chunk};
                            is_last_chunk <= 1'b1;
                            buf_count     <= 4'd0;
                            state         <= S_MUL_LO;
                        end else begin
                            // Empty remaining buffer, go straight to finalize
                            state <= S_FINALIZE;
                        end
                    end else if (blk_valid) begin : blk_wait_direct
                        reg [128:0] n_blk;
                        n_blk = {1'b0, blk_data} | (129'd1 << (blk_len * 8));
                        cur_a <= acc + {2'b00, n_blk};
                        is_last_chunk <= blk_last;
                        state <= S_MUL_LO;
                    end
                end

                S_MUL_LO: begin
                    // Stage 1 of multiplication: cur_a * r[63:0]
                    prod_lo <= cur_a * r_reg[63:0];
                    state   <= S_MUL_HI;

                    // Buffer any incoming streaming bytes during multiplication pipeline
                    if (msg_valid) begin
                        buf_bytes[buf_count] <= msg_data;
                        buf_count <= buf_count + 4'd1;
                        if (msg_eof) eof_seen <= 1'b1;
                    end
                end

                S_MUL_HI: begin
                    // Stage 2 of multiplication: add (cur_a * r[127:64] << 64)
                    full_prod <= {64'd0, prod_lo} + ((cur_a * r_reg[127:64]) << 64);
                    state     <= S_REDUCE;

                    // Buffer any incoming streaming bytes during multiplication pipeline
                    if (msg_valid) begin
                        buf_bytes[buf_count] <= msg_data;
                        buf_count <= buf_count + 4'd1;
                        if (msg_eof) eof_seen <= 1'b1;
                    end
                end

                S_REDUCE: begin
                    // Stage 3: Modular reduction modulo 2^130 - 5
                    // Exploits 2^130 = 5 mod p
                    begin : blk_red
                        reg [129:0] p_lo;
                        reg [128:0] p_hi;
                        reg [132:0] s1;
                        reg [129:0] s1_lo;
                        reg [2:0]   s1_hi;
                        reg [130:0] s2;
                        reg [129:0] sub1;
                        reg [129:0] res;

                        p_lo  = full_prod[129:0];
                        p_hi  = full_prod[258:130];
                        s1    = {3'd0, p_lo} + (({4'd0, p_hi} << 2) + {4'd0, p_hi}); // p_lo + p_hi * 5

                        s1_lo = s1[129:0];
                        s1_hi = s1[132:130];
                        s2    = {1'b0, s1_lo} + (({128'd0, s1_hi} << 2) + {128'd0, s1_hi}); // s1_lo + s1_hi * 5

                        // Conditional subtract of P = 2^130 - 5. When s2 >= P the true
                        // difference is < P < 2^130, so its low 130 bits are exact.
                        sub1  = s2[129:0] - P_PRIME[129:0];

                        if (s2 >= P_PRIME)
                            res = sub1;
                        else
                            res = s2[129:0];

                        acc <= res;

                        if (is_last_chunk) begin
                            state <= S_FINALIZE;
                        end else begin
                            state <= S_BUF_WAIT;
                        end
                    end

                    // Buffer any incoming streaming bytes during multiplication pipeline
                    if (msg_valid) begin
                        buf_bytes[buf_count] <= msg_data;
                        buf_count <= buf_count + 4'd1;
                        if (msg_eof) eof_seen <= 1'b1;
                    end
                end

                S_FINALIZE: begin
                    // Final tag: (acc + s) mod 2^128
                    begin : blk_fin
                        reg [127:0] final_tag;
                        reg         match;

                        final_tag = acc[127:0] + s_reg;
                        match     = (final_tag == expected_tag);

                        tag_out       <= final_tag;
                        tag_ok        <= match;
                        tag_valid     <= 1'b1;

                        // Qualify plaintext inspection bus (§3.1)
                        pt_tag_ok     <= match;
                        pt_tag_valid  <= 1'b1;

                        // Drive uniform verdict to drop engine
                        v_poly_valid  <= 1'b1;
                        v_poly_fail   <= !match;
                        v_poly_reason <= match ? `RC_NONE : `RC_BAD_TAG;

                        busy          <= 1'b0;
                        acc           <= 130'd0;
                        eof_seen      <= 1'b0;
                        buf_count     <= 4'd0;
                        state         <= S_IDLE;
                    end
                end

                default: state <= S_IDLE;
            endcase
        end
    end

endmodule

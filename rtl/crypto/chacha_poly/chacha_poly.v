// rtl/crypto/chacha_poly/chacha_poly.v
//
// ChaCha20-Poly1305 AEAD Authenticated Decryption Core -- RFC 8439 Section 2.8
// Member D (@control) -- pqc-nids-fpga
//
// Architecture & Dataflow:
// ========================
// 1. One-Time Key Generation (OTK):
//    On key_valid / packet start, triggers chacha20.v with counter = 0.
//    Takes 22 cycles. Output block bytes 0..31 provide the 32-byte OTK
//    (clamped r and secret s) loaded into poly1305.v.
//
// 2. Associated Data (AAD) Processing:
//    Zero-pads AAD to a 16-byte boundary and feeds into poly1305.v.
//
// 3. Streaming Decryption & MAC Accumulation:
//    Precomputes ChaCha20 keystream starting at counter = 1.
//    As ciphertext bytes stream in on ct_data:
//      - Decrypted into pt_data and streamed to cam_matcher.v (§3.1 inspection bus).
//      - Simultaneously assembled into 16-byte blocks and fed to poly1305.v.
//
// 4. Final Length Block & Verification:
//    Appends zero-padded final ciphertext chunk (if partial).
//    Appends 16-byte length block: [len(AAD)_u64 || len(ciphertext)_u64].
//    When poly1305 completes:
//      - Drives Section 3.1 pt_tag_ok / pt_tag_valid to cam_matcher.v.
//      - Drives Section 6 uniform verdict (v_poly_valid, v_poly_fail, RC_BAD_TAG) to drop_engine.v.
//
// Constraints: Verilog-2001, single clk, sync active-high rst, registered outputs.

`timescale 1ns / 1ps
`include "reason_codes.vh"

module chacha_poly (
    input  wire         clk,
    input  wire         rst,

    // ---- Key & Nonce Configuration -------------------------------------------
    input  wire         key_valid,      // 1-cycle strobe: initialize session key/nonce
    input  wire [255:0] key,            // 256-bit session key
    input  wire [95:0]  nonce,          // 96-bit ChaCha20 nonce

    // ---- Associated Data (AAD) -----------------------------------------------
    input  wire [127:0] aad_data,       // Up to 16 bytes of AAD (little-endian byte 0 at [7:0])
    input  wire [4:0]   aad_len,        // AAD length in bytes (0..16)

    // ---- Streaming Ciphertext Ingress (from Packet Bus) ----------------------
    input  wire         ct_valid,       // Ciphertext byte valid
    input  wire [7:0]   ct_data,        // Ciphertext byte
    input  wire         ct_sof,         // First byte of ciphertext
    input  wire         ct_eof,         // Last byte of ciphertext

    // ---- Expected Authentication Tag -----------------------------------------
    input  wire [127:0] expected_tag,   // 16-byte Poly1305 expected tag

    // ---- Status & Flow Control -----------------------------------------------
    output reg          ready,          // 1 = ready to accept streaming ciphertext
    output reg          busy,           // 1 = busy generating OTK, streaming, or finalizing
    output reg          done,           // 1-cycle strobe: packet decryption & auth complete

    // ---- Plaintext Inspection Bus (Interface Contract v1.1.0 §3.1) -----------
    output wire         pt_valid,       // Decrypted byte valid
    output wire [7:0]   pt_data,        // Decrypted payload byte
    output wire         pt_sof,         // First plaintext byte
    output wire         pt_eof,         // Last plaintext byte
    output reg          pt_tag_ok,      // Qualifies packet: 1 = tag verified
    output reg          pt_tag_valid,   // 1-cycle strobe: pt_tag_ok is valid

    // ---- Drop Engine Verdict Interface (Interface Contract Section 6) --------
    output reg          v_poly_valid,   // 1-cycle strobe to drop_engine
    output reg          v_poly_fail,    // 1 = reject (bad tag), 0 = pass
    output reg  [3:0]   v_poly_reason,  // 4'h7 (RC_BAD_TAG) if fail, else 4'h0

    // ---- Computed Tag Outputs ------------------------------------------------
    output wire [127:0] tag_out,        // Computed Poly1305 tag
    output wire         tag_ok          // 1 = tag matches expected_tag
);

    // =========================================================================
    // FSM States
    // =========================================================================
    localparam [3:0] S_IDLE         = 4'd0;
    localparam [3:0] S_GEN_OTK      = 4'd1;
    localparam [3:0] S_LOAD_OTK     = 4'd2;
    localparam [3:0] S_FEED_AAD     = 4'd3;
    localparam [3:0] S_WAIT_AAD     = 4'd4;
    localparam [3:0] S_PREP_CT      = 4'd5;
    localparam [3:0] S_WAIT_CT_INIT = 4'd6;
    localparam [3:0] S_STREAM_CT    = 4'd7;
    localparam [3:0] S_NEXT_BLOCK   = 4'd8;
    localparam [3:0] S_WAIT_NEXT_BLK= 4'd9;
    localparam [3:0] S_FEED_PAD_CT  = 4'd10;
    localparam [3:0] S_WAIT_PAD_CT  = 4'd11;
    localparam [3:0] S_FEED_LEN     = 4'd12;
    localparam [3:0] S_WAIT_TAG     = 4'd13;
    localparam [3:0] S_FINALIZE     = 4'd14;

    reg [3:0] state;

    // Registers to latch configuration
    reg [255:0] key_reg;
    reg [95:0]  nonce_reg;
    reg [127:0] aad_reg;
    reg [4:0]   aad_len_reg;
    reg [127:0] exp_tag_reg;

    // Ciphertext and block tracking
    reg [63:0]  ct_total_len;
    reg [31:0]  cc_block_counter;
    reg [5:0]   ct_block_byte_idx;  // 0..63 within current ChaCha20 block
    reg [7:0]   ct_chunk [0:15];
    reg [3:0]   ct_chunk_count;     // 0..15 within current 16-byte Poly1305 chunk
    reg [2:0]   poly_wait_cnt;

    // =========================================================================
    // ChaCha20 Submodule Signals
    // =========================================================================
    reg          cc_start;
    reg  [255:0] cc_key;
    reg  [31:0]  cc_counter;
    reg  [95:0]  cc_nonce;
    wire         cc_busy;
    wire         cc_done;
    wire [511:0] cc_keystream_block;

    reg          cc_ct_valid;
    reg  [7:0]   cc_ct_data;
    reg          cc_ct_sof;
    reg          cc_ct_eof;

    chacha20 u_chacha20 (
        .clk            (clk),
        .rst            (rst),
        .start          (cc_start),
        .key            (cc_key),
        .counter        (cc_counter),
        .nonce          (cc_nonce),
        .busy           (cc_busy),
        .done           (cc_done),
        .keystream_block(cc_keystream_block),
        .ct_valid       (cc_ct_valid),
        .ct_data        (cc_ct_data),
        .ct_sof         (cc_ct_sof),
        .ct_eof         (cc_ct_eof),
        .pt_valid       (pt_valid),
        .pt_data        (pt_data),
        .pt_sof         (pt_sof),
        .pt_eof         (pt_eof)
    );

    // =========================================================================
    // Poly1305 Submodule Signals
    // =========================================================================
    reg          poly_key_valid;
    reg  [255:0] poly_key;

    reg          poly_blk_valid;
    reg  [127:0] poly_blk_data;
    reg  [4:0]   poly_blk_len;
    reg          poly_blk_last;

    wire         poly_blk_ready;
    wire         poly_busy;
    wire         poly_tag_valid;
    wire [127:0] poly_tag_out;
    wire         poly_tag_ok;
    wire         poly_pt_tag_ok;
    wire         poly_pt_tag_valid;
    wire         poly_v_valid;
    wire         poly_v_fail;
    wire [3:0]   poly_v_reason;

    poly1305 u_poly1305 (
        .clk          (clk),
        .rst          (rst),
        .key_valid    (poly_key_valid),
        .key          (poly_key),
        .msg_valid    (1'b0),
        .msg_data     (8'd0),
        .msg_sof      (1'b0),
        .msg_eof      (1'b0),
        .blk_valid    (poly_blk_valid),
        .blk_data     (poly_blk_data),
        .blk_len      (poly_blk_len),
        .blk_last     (poly_blk_last),
        .expected_tag (exp_tag_reg),
        .blk_ready    (poly_blk_ready),
        .busy         (poly_busy),
        .tag_valid    (poly_tag_valid),
        .tag_out      (poly_tag_out),
        .tag_ok       (poly_tag_ok),
        .pt_tag_ok    (poly_pt_tag_ok),
        .pt_tag_valid (poly_pt_tag_valid),
        .v_poly_valid (poly_v_valid),
        .v_poly_fail  (poly_v_fail),
        .v_poly_reason(poly_v_reason)
    );

    assign tag_out = poly_tag_out;
    assign tag_ok  = poly_tag_ok;

    // Helper to zero-pad AAD to 16 bytes
    function [127:0] pad_aad;
        input [127:0] in_data;
        input [4:0]   in_len;
        reg [127:0]   p;
        integer k;
        begin
            p = 128'd0;
            for (k = 0; k < 16; k = k + 1) begin
                if (k < in_len)
                    p[k*8 +: 8] = in_data[k*8 +: 8];
                else
                    p[k*8 +: 8] = 8'd0;
            end
            pad_aad = p;
        end
    endfunction

    // Helper to zero-pad ciphertext chunk to 16 bytes
    function [127:0] pad_chunk;
        input [3:0] in_len;
        reg [127:0] p;
        integer m;
        begin
            p = 128'd0;
            for (m = 0; m < 16; m = m + 1) begin
                if (m < in_len)
                    p[m*8 +: 8] = ct_chunk[m];
                else
                    p[m*8 +: 8] = 8'd0;
            end
            pad_chunk = p;
        end
    endfunction

    // =========================================================================
    // Control & Coordination FSM
    // =========================================================================
    integer c_idx;

    always @(posedge clk) begin
        if (rst) begin
            state             <= S_IDLE;
            ready             <= 1'b0;
            busy              <= 1'b0;
            done              <= 1'b0;
            pt_tag_ok         <= 1'b0;
            pt_tag_valid      <= 1'b0;
            v_poly_valid      <= 1'b0;
            v_poly_fail       <= 1'b0;
            v_poly_reason     <= `RC_NONE;

            key_reg           <= 256'd0;
            nonce_reg         <= 96'd0;
            aad_reg           <= 128'd0;
            aad_len_reg       <= 5'd0;
            exp_tag_reg       <= 128'd0;
            ct_total_len      <= 64'd0;
            cc_block_counter  <= 32'd0;
            ct_block_byte_idx <= 6'd0;
            ct_chunk_count    <= 4'd0;
            poly_wait_cnt     <= 3'd0;

            cc_start          <= 1'b0;
            cc_key            <= 256'd0;
            cc_counter        <= 32'd0;
            cc_nonce          <= 96'd0;
            cc_ct_valid       <= 1'b0;
            cc_ct_data        <= 8'd0;
            cc_ct_sof         <= 1'b0;
            cc_ct_eof         <= 1'b0;

            poly_key_valid    <= 1'b0;
            poly_key          <= 256'd0;
            poly_blk_valid    <= 1'b0;
            poly_blk_data     <= 128'd0;
            poly_blk_len      <= 5'd0;
            poly_blk_last     <= 1'b0;

            for (c_idx = 0; c_idx < 16; c_idx = c_idx + 1)
                ct_chunk[c_idx] <= 8'd0;
        end else begin
            // Default 1-cycle strobes
            done           <= 1'b0;
            pt_tag_valid   <= 1'b0;
            v_poly_valid   <= 1'b0;
            cc_start       <= 1'b0;
            cc_ct_valid    <= 1'b0;
            poly_key_valid <= 1'b0;
            poly_blk_valid <= 1'b0;

            case (state)
                // -------------------------------------------------------------
                // S_IDLE: Await session key / nonce and packet initialization
                // -------------------------------------------------------------
                S_IDLE: begin
                    ready <= 1'b0;
                    busy  <= 1'b0;
                    if (key_valid) begin
                        key_reg           <= key;
                        nonce_reg         <= nonce;
                        aad_reg           <= aad_data;
                        aad_len_reg       <= aad_len;
                        exp_tag_reg       <= expected_tag;
                        ct_total_len      <= 64'd0;
                        ct_chunk_count    <= 4'd0;
                        ct_block_byte_idx <= 6'd0;

                        // Start Block 0 generation (OTK derivation)
                        cc_key     <= key;
                        cc_nonce   <= nonce;
                        cc_counter <= 32'd0;
                        cc_start   <= 1'b1;
                        busy       <= 1'b1;
                        state      <= S_GEN_OTK;
                    end
                end

                // -------------------------------------------------------------
                // S_GEN_OTK: Wait for ChaCha20 block 0 to produce OTK (22 cycles)
                // -------------------------------------------------------------
                S_GEN_OTK: begin
                    if (cc_done) begin
                        // First 32 bytes of block 0 is the Poly1305 key
                        poly_key       <= cc_keystream_block[255:0];
                        poly_key_valid <= 1'b1;
                        state          <= S_LOAD_OTK;
                    end
                end

                // -------------------------------------------------------------
                // S_LOAD_OTK: Key latched into Poly1305, proceed to AAD or CT
                // -------------------------------------------------------------
                S_LOAD_OTK: begin
                    if (poly_blk_ready) begin
                        if (aad_len_reg > 5'd0) begin
                            state <= S_FEED_AAD;
                        end else begin
                            state <= S_PREP_CT;
                        end
                    end
                end

                // -------------------------------------------------------------
                // S_FEED_AAD: Feed 16-byte zero-padded AAD into Poly1305
                // -------------------------------------------------------------
                S_FEED_AAD: begin
                    if (poly_blk_ready) begin
                        poly_blk_data  <= pad_aad(aad_reg, aad_len_reg);
                        poly_blk_len   <= 5'd16;
                        poly_blk_last  <= 1'b0;
                        poly_blk_valid <= 1'b1;
                        state          <= S_WAIT_AAD;
                    end
                end

                S_WAIT_AAD: begin
                    if (poly_blk_ready) begin
                        state <= S_PREP_CT;
                    end
                end

                // -------------------------------------------------------------
                // S_PREP_CT: Generate ChaCha20 block 1 for ciphertext decryption
                // -------------------------------------------------------------
                S_PREP_CT: begin
                    cc_key           <= key_reg;
                    cc_nonce         <= nonce_reg;
                    cc_counter       <= 32'd1;
                    cc_block_counter <= 32'd1;
                    cc_start         <= 1'b1;
                    state            <= S_WAIT_CT_INIT;
                end

                S_WAIT_CT_INIT: begin
                    if (cc_done) begin
                        // Keystream for bytes 0..63 is ready!
                        ready <= 1'b1;
                        state <= S_STREAM_CT;
                    end
                end

                // -------------------------------------------------------------
                // S_STREAM_CT: Inline streaming decryption and MAC buffering
                // -------------------------------------------------------------
                S_STREAM_CT: begin
                    if (ct_valid) begin
                        // Drive ChaCha20 plaintext inspection bus
                        cc_ct_valid <= 1'b1;
                        cc_ct_data  <= ct_data;
                        cc_ct_sof   <= ct_sof;
                        cc_ct_eof   <= ct_eof;

                        ct_total_len <= ct_total_len + 64'd1;

                        // Assemble into 16-byte chunk for Poly1305
                        ct_chunk[ct_chunk_count] <= ct_data;

                        if (ct_chunk_count == 4'd15) begin
                            // 16-byte chunk full: pulse to Poly1305
                            begin : blk_ct_full
                                reg [127:0] full_c;
                                integer n;
                                for (n = 0; n < 15; n = n + 1)
                                    full_c[n*8 +: 8] = ct_chunk[n];
                                full_c[15*8 +: 8] = ct_data;

                                poly_blk_data  <= full_c;
                                poly_blk_len   <= 5'd16;
                                poly_blk_last  <= 1'b0;
                                poly_blk_valid <= 1'b1;
                                ct_chunk_count <= 4'd0;
                            end
                        end else begin
                            ct_chunk_count <= ct_chunk_count + 4'd1;
                        end

                        // Check 64-byte block boundary for ChaCha20
                        if (ct_eof) begin
                            ready <= 1'b0;
                            state <= S_FEED_PAD_CT;
                        end else if (ct_block_byte_idx == 6'd63) begin
                            // Need next 64-byte keystream block
                            ct_block_byte_idx <= 6'd0;
                            ready             <= 1'b0;
                            state             <= S_NEXT_BLOCK;
                        end else begin
                            ct_block_byte_idx <= ct_block_byte_idx + 6'd1;
                        end
                    end
                end

                // -------------------------------------------------------------
                // S_NEXT_BLOCK: Step ChaCha20 counter for long packets (> 64 B)
                // -------------------------------------------------------------
                S_NEXT_BLOCK: begin
                    cc_block_counter <= cc_block_counter + 32'd1;
                    cc_counter       <= cc_block_counter + 32'd1;
                    cc_start         <= 1'b1;
                    state            <= S_WAIT_NEXT_BLK;
                end

                S_WAIT_NEXT_BLK: begin
                    if (cc_done) begin
                        ready <= 1'b1;
                        state <= S_STREAM_CT;
                    end
                end

                // -------------------------------------------------------------
                // S_FEED_PAD_CT: Zero-pad remaining partial chunk (if any)
                // -------------------------------------------------------------
                S_FEED_PAD_CT: begin
                    if (poly_blk_ready) begin
                        if (ct_chunk_count > 4'd0) begin
                            poly_blk_data  <= pad_chunk(ct_chunk_count);
                            poly_blk_len   <= 5'd16;
                            poly_blk_last  <= 1'b0;
                            poly_blk_valid <= 1'b1;
                            ct_chunk_count <= 4'd0;
                            state          <= S_WAIT_PAD_CT;
                        end else begin
                            state <= S_FEED_LEN;
                        end
                    end
                end

                S_WAIT_PAD_CT: begin
                    if (poly_blk_ready) begin
                        state <= S_FEED_LEN;
                    end
                end

                // -------------------------------------------------------------
                // S_FEED_LEN: Feed 16-byte length block: [len(AAD)_u64 || len(CT)_u64]
                // -------------------------------------------------------------
                S_FEED_LEN: begin
                    if (poly_blk_ready) begin
                        poly_blk_data  <= {ct_total_len, {59'd0, aad_len_reg}};
                        poly_blk_len   <= 5'd16;
                        poly_blk_last  <= 1'b1; // Final block of AEAD
                        poly_blk_valid <= 1'b1;
                        state          <= S_WAIT_TAG;
                    end
                end

                // -------------------------------------------------------------
                // S_WAIT_TAG: Await tag verification from Poly1305 core
                // -------------------------------------------------------------
                S_WAIT_TAG: begin
                    if (poly_tag_valid) begin
                        // Latch and propagate qualification to CAM and Drop Engine
                        pt_tag_ok     <= poly_tag_ok;
                        pt_tag_valid  <= 1'b1;
                        v_poly_valid  <= 1'b1;
                        v_poly_fail   <= poly_v_fail;
                        v_poly_reason <= poly_v_reason;
                        done          <= 1'b1;
                        busy          <= 1'b0;
                        state         <= S_IDLE;
                    end
                end

                default: state <= S_IDLE;
            endcase
        end
    end

endmodule

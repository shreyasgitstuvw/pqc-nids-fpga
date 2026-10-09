//==========================================================================
// rtl/crypto/sha3/shake_wrapper.v
//
// Multi-mode sponge wrapper around keccak_f1600.v (FIPS 202) for ML-KEM-512.
// Bit-exact synthesizable RTL twin of model/sha3.py (keccak_sponge).
// Supports SHA3-256, SHA3-512, SHAKE128, and SHAKE256 over 64-bit word bus.
//
// Architecture & Specifications:
//   - 64-bit Datapath:
//       Absorb: in_data [63:0], in_bytes [3:0] (0..8 bytes), in_valid, in_last.
//       Squeeze: out_data [63:0], out_mask [7:0] (8'hFF), out_valid, out_last, out_ready.
//   - State Ownership:
//       shake_wrapper owns architectural sponge_state [1599:0].
//       keccak_f1600 owns transient execution state_reg [1599:0].
//       On core completion (done), sponge_state snapshots core_dout.
//   - Combined Resource Totals (keccak_f1600 + shake_wrapper, XC7Z020 @ 100 MHz):
//       0 DSP slices (100% of DSP budget reserved for NTT/modmul)
//       0 BRAMs
//       ~3,270 Slice Registers (~1,607 in core, 1600 sponge_state, ~65 FSM/counters)
//       ~3,850-4,150 Slice LUTs (~3,000 in core, ~850-1,150 in wrapper)
//   - pad10*1 Boundary Specification:
//       Rates: 72, 136, 168 bytes are all exact multiples of 8. Words never straddle.
//       Case A (Partial word): suffix placed at in_bytes, 0x80 at rate_bytes-1.
//       Case B (Single-byte merge): in_bytes==7 at rate-1 merges suffix | 0x80 (0x86 or 0x9F).
//       Case C (Full block deferral): in_last=1 on full block permutes block, then
//              synthesizes an extra padding block [suffix, 0..., 0x80] and permutes again.
//       Case D (Empty message b""): in_valid=1, in_last=1, in_bytes=0 absorbs 1 padding block.
//   - init Collision & Abort Semantics:
//       If init asserts while core is busy, pending-start, or done: clear wins over snapshot.
//       Wrapper enters S_ABORT_DRAIN, in_ready stays low until core is idle, then state is cleared.
//   - Unused Byte Masking:
//       When in_bytes < 8, upper (8 - in_bytes) bytes are masked to 0 before XOR.
//   - Sequencing:
//       S_TRIGGER_CORE fires 1 cycle after last lane XOR so core_din sees settled state.
//   - Squeeze Length & Rejection Sampling:
//       mode and squeeze_words are latched on init.
//       Fixed digest lengths: SHA3-256 (4 words), SHA3-512 (8 words).
//       For SHAKE128/256: consumer sets maximum squeeze_words or terminates stream with init.
//   - Performance:
//       Squeeze of 168-byte SHAKE128 block takes 21 cycles + 25 cycles core = ~46 cycles serial.
//==========================================================================

`timescale 1ns / 1ps

module shake_wrapper (
    input  wire          clk,
    input  wire          rst,

    // Configuration & Control
    input  wire [1:0]    mode,          // 00: SHA3-256, 01: SHA3-512, 10: SHAKE128, 11: SHAKE256
    input  wire          init,          // Initialize new session (aborts ongoing if active)
    input  wire [9:0]    squeeze_words, // Output length in 64-bit words for SHAKE modes

    // Absorb Stream (64-bit wide)
    input  wire [63:0]   in_data,
    input  wire [3:0]    in_bytes,      // 0..8 valid bytes (0 on in_last = empty message)
    input  wire          in_valid,
    input  wire          in_last,       // Last word of message
    output wire          in_ready,

    // Squeeze Stream (64-bit wide)
    output wire [63:0]   out_data,
    output wire [7:0]    out_mask,      // Byte-valid mask (always 8'hFF for 64-bit words)
    output wire          out_valid,
    output wire          out_last,      // Final word of digest
    input  wire          out_ready,

    output wire          busy           // High while absorbing, permuting, or aborting
);

    // -------------------------------------------------------------------------
    // FSM States
    // -------------------------------------------------------------------------
    localparam S_IDLE_ABSORB  = 3'd0;
    localparam S_PAD_EXTRA    = 3'd1;
    localparam S_TRIGGER_CORE = 3'd2;
    localparam S_WAIT_CORE    = 3'd3;
    localparam S_SQUEEZE      = 3'd4;
    localparam S_ABORT_DRAIN  = 3'd5;

    reg [2:0]  fsm_state;
    reg [2:0]  next_after_core;

    // -------------------------------------------------------------------------
    // Registers & Latch Configurations
    // -------------------------------------------------------------------------
    reg [1599:0] sponge_state;
    reg [1:0]    mode_reg;
    reg [9:0]    squeeze_target_reg;
    reg [4:0]    word_idx;          // 0..20 word index within current rate block
    reg [9:0]    squeeze_word_ctr;  // words squeezed so far
    reg          core_start;

    // -------------------------------------------------------------------------
    // Rate & Suffix Decodes
    // -------------------------------------------------------------------------
    reg [4:0] rate_words;
    always @(*) begin
        case (mode_reg)
            2'b00:   rate_words = 5'd17; // SHA3-256 (136 bytes)
            2'b01:   rate_words = 5'd9;  // SHA3-512 (72 bytes)
            2'b10:   rate_words = 5'd21; // SHAKE128 (168 bytes)
            2'b11:   rate_words = 5'd17; // SHAKE256 (136 bytes)
            default: rate_words = 5'd17;
        endcase
    end

    wire [7:0] suffix_byte = (mode_reg[1]) ? 8'h1F : 8'h06;

    // Suffix pad word positioned at byte offset in_bytes (0..7)
    reg [63:0] suffix_pad_word;
    always @(*) begin
        case (in_bytes[2:0])
            3'd0:    suffix_pad_word = {56'h0, suffix_byte};
            3'd1:    suffix_pad_word = {48'h0, suffix_byte, 8'h0};
            3'd2:    suffix_pad_word = {40'h0, suffix_byte, 16'h0};
            3'd3:    suffix_pad_word = {32'h0, suffix_byte, 24'h0};
            3'd4:    suffix_pad_word = {24'h0, suffix_byte, 32'h0};
            3'd5:    suffix_pad_word = {16'h0, suffix_byte, 40'h0};
            3'd6:    suffix_pad_word = {8'h0,  suffix_byte, 48'h0};
            3'd7:    suffix_pad_word = {suffix_byte, 56'h0};
            default: suffix_pad_word = {56'h0, suffix_byte};
        endcase
    end

    // -------------------------------------------------------------------------
    // Core Instance
    // -------------------------------------------------------------------------
    wire [1599:0] core_dout;
    wire          core_busy;
    wire          core_done;

    keccak_f1600 u_core (
        .clk   (clk),
        .rst   (rst),
        .start (core_start),
        .din   (sponge_state),
        .dout  (core_dout),
        .busy  (core_busy),
        .done  (core_done)
    );

    // -------------------------------------------------------------------------
    // Input Masking (Amendment 3: mask unused upper bytes to 0)
    // -------------------------------------------------------------------------
    reg [63:0] clean_word;
    always @(*) begin
        case (in_bytes)
            4'd0:    clean_word = 64'h0;
            4'd1:    clean_word = {56'h0, in_data[7:0]};
            4'd2:    clean_word = {48'h0, in_data[15:0]};
            4'd3:    clean_word = {40'h0, in_data[23:0]};
            4'd4:    clean_word = {32'h0, in_data[31:0]};
            4'd5:    clean_word = {24'h0, in_data[39:0]};
            4'd6:    clean_word = {16'h0, in_data[47:0]};
            4'd7:    clean_word = {8'h0,  in_data[55:0]};
            default: clean_word = in_data;
        endcase
    end

    // -------------------------------------------------------------------------
    // Control Outputs & Handshakes
    // -------------------------------------------------------------------------
    assign in_ready  = (fsm_state == S_IDLE_ABSORB) && !init;
    assign out_data  = sponge_state[64*word_idx +: 64];
    assign out_mask  = 8'hFF;
    assign out_valid = (fsm_state == S_SQUEEZE);
    assign out_last  = (fsm_state == S_SQUEEZE) && (squeeze_word_ctr + 10'd1 == squeeze_target_reg);
    assign busy      = (fsm_state != S_IDLE_ABSORB) || (word_idx != 5'd0) || core_busy || core_start;

    // -------------------------------------------------------------------------
    // Sequential State Machine
    // -------------------------------------------------------------------------
    always @(posedge clk) begin
        if (rst) begin
            fsm_state          <= S_IDLE_ABSORB;
            next_after_core    <= S_IDLE_ABSORB;
            sponge_state       <= 1600'b0;
            mode_reg           <= 2'b00;
            squeeze_target_reg <= 10'd4;
            word_idx           <= 5'd0;
            squeeze_word_ctr   <= 10'd0;
            core_start         <= 1'b0;
        end else begin
            core_start <= 1'b0; // default 1-cycle strobe

            // -----------------------------------------------------------------
            // init Handling (Amendment 1: Collision priorities)
            // -----------------------------------------------------------------
            if (init) begin
                core_start         <= 1'b0;
                mode_reg           <= mode;
                squeeze_target_reg <= (mode == 2'b00) ? 10'd4 :
                                      (mode == 2'b01) ? 10'd8 : squeeze_words;
                word_idx           <= 5'd0;
                squeeze_word_ctr   <= 10'd0;
                // If core is actively calculating or triggered on this cycle, abort and drain
                if (core_busy || core_start) begin
                    fsm_state <= S_ABORT_DRAIN;
                end else begin
                    // Core is idle: clear sponge_state (clear wins over done) and return to IDLE
                    sponge_state <= 1600'b0;
                    fsm_state    <= S_IDLE_ABSORB;
                end
            end else begin
                case (fsm_state)
                    // ---------------------------------------------------------
                    // S_IDLE_ABSORB: Accept 64-bit words and pad on in_last
                    // ---------------------------------------------------------
                    S_IDLE_ABSORB: begin
                        if (in_valid && in_ready) begin
                            if (!in_last) begin
                                // Non-last word: must be full 8 bytes
                                sponge_state[64*word_idx +: 64] <= sponge_state[64*word_idx +: 64] ^ clean_word;
                                if (word_idx == rate_words - 5'd1) begin
                                    // Eager permutation on full block (Amendment 4)
                                    word_idx        <= 5'd0;
                                    fsm_state       <= S_TRIGGER_CORE;
                                    next_after_core <= S_IDLE_ABSORB;
                                end else begin
                                    word_idx <= word_idx + 5'd1;
                                end
                            end else begin
                                // Final word of message (in_last == 1)
                                if (in_bytes == 4'd0) begin
                                    // Case D: Empty message (b"")
                                    sponge_state[64*0 +: 64] <= sponge_state[64*0 +: 64] ^ {56'h0, suffix_byte};
                                    sponge_state[64*(rate_words - 5'd1) +: 64] <=
                                        sponge_state[64*(rate_words - 5'd1) +: 64] ^ 64'h8000_0000_0000_0000;
                                    word_idx        <= 5'd0;
                                    fsm_state       <= S_TRIGGER_CORE;
                                    next_after_core <= S_SQUEEZE;
                                end else if ((in_bytes == 4'd8) && (word_idx == rate_words - 5'd1)) begin
                                    // Case C: Full block deferral (Amendment 4)
                                    sponge_state[64*word_idx +: 64] <= sponge_state[64*word_idx +: 64] ^ clean_word;
                                    word_idx        <= 5'd0;
                                    fsm_state       <= S_TRIGGER_CORE;
                                    next_after_core <= S_PAD_EXTRA;
                                end else if (word_idx == rate_words - 5'd1) begin
                                    // Case B & partial last word: all padding fits in this final word
                                    sponge_state[64*word_idx +: 64] <=
                                        sponge_state[64*word_idx +: 64] ^ (clean_word | suffix_pad_word | 64'h8000_0000_0000_0000);
                                    word_idx        <= 5'd0;
                                    fsm_state       <= S_TRIGGER_CORE;
                                    next_after_core <= S_SQUEEZE;
                                end else if (in_bytes < 4'd8) begin
                                    // Case A: Partial word ending inside block (word_idx < rate_words - 1)
                                    sponge_state[64*word_idx +: 64] <=
                                        sponge_state[64*word_idx +: 64] ^ (clean_word | suffix_pad_word);
                                    sponge_state[64*(rate_words - 5'd1) +: 64] <=
                                        sponge_state[64*(rate_words - 5'd1) +: 64] ^ 64'h8000_0000_0000_0000;
                                    word_idx        <= 5'd0;
                                    fsm_state       <= S_TRIGGER_CORE;
                                    next_after_core <= S_SQUEEZE;
                                end else begin
                                    // in_bytes == 8 and word_idx < rate_words - 1
                                    sponge_state[64*word_idx +: 64] <= sponge_state[64*word_idx +: 64] ^ clean_word;
                                    if (word_idx + 5'd1 == rate_words - 5'd1) begin
                                        sponge_state[64*(word_idx + 5'd1) +: 64] <=
                                            sponge_state[64*(word_idx + 5'd1) +: 64] ^ {8'h80, 48'h0, suffix_byte};
                                    end else begin
                                        sponge_state[64*(word_idx + 5'd1) +: 64] <=
                                            sponge_state[64*(word_idx + 5'd1) +: 64] ^ {56'h0, suffix_byte};
                                        sponge_state[64*(rate_words - 5'd1) +: 64] <=
                                            sponge_state[64*(rate_words - 5'd1) +: 64] ^ 64'h8000_0000_0000_0000;
                                    end
                                    word_idx        <= 5'd0;
                                    fsm_state       <= S_TRIGGER_CORE;
                                    next_after_core <= S_SQUEEZE;
                                end
                            end
                        end
                    end

                    // ---------------------------------------------------------
                    // S_PAD_EXTRA: Synthesize extra padding block for Case C
                    // ---------------------------------------------------------
                    S_PAD_EXTRA: begin
                        sponge_state[64*0 +: 64] <= sponge_state[64*0 +: 64] ^ {56'h0, suffix_byte};
                        sponge_state[64*(rate_words - 5'd1) +: 64] <=
                            sponge_state[64*(rate_words - 5'd1) +: 64] ^ 64'h8000_0000_0000_0000;
                        word_idx        <= 5'd0;
                        fsm_state       <= S_TRIGGER_CORE;
                        next_after_core <= S_SQUEEZE;
                    end

                    // ---------------------------------------------------------
                    // S_TRIGGER_CORE: 1 cycle settling before pulsing start (Amendment 6)
                    // ---------------------------------------------------------
                    S_TRIGGER_CORE: begin
                        core_start <= 1'b1;
                        fsm_state  <= S_WAIT_CORE;
                    end

                    // ---------------------------------------------------------
                    // S_WAIT_CORE: Wait for core_done, snapshot state
                    // ---------------------------------------------------------
                    S_WAIT_CORE: begin
                        if (core_done) begin
                            sponge_state <= core_dout;
                            fsm_state    <= next_after_core;
                            word_idx     <= 5'd0;
                        end
                    end

                    // ---------------------------------------------------------
                    // S_SQUEEZE: Stream 64-bit words, permuting on rate boundary
                    // ---------------------------------------------------------
                    S_SQUEEZE: begin
                        if (out_valid && out_ready) begin
                            if (squeeze_word_ctr + 10'd1 == squeeze_target_reg) begin
                                // Reached target words
                                fsm_state        <= S_IDLE_ABSORB;
                                word_idx         <= 5'd0;
                                squeeze_word_ctr <= 10'd0;
                            end else begin
                                squeeze_word_ctr <= squeeze_word_ctr + 10'd1;
                                if (word_idx == rate_words - 5'd1) begin
                                    // Squeezed full rate block; trigger on-demand permutation
                                    word_idx        <= 5'd0;
                                    fsm_state       <= S_TRIGGER_CORE;
                                    next_after_core <= S_SQUEEZE;
                                end else begin
                                    word_idx <= word_idx + 5'd1;
                                end
                            end
                        end
                    end

                    // ---------------------------------------------------------
                    // S_ABORT_DRAIN: Drain running core after init abort
                    // ---------------------------------------------------------
                    S_ABORT_DRAIN: begin
                        // Wait until core finishes its in-flight permutation
                        if (!core_busy && !core_done) begin
                            sponge_state <= 1600'b0;
                            fsm_state    <= S_IDLE_ABSORB;
                        end
                    end

                    default: fsm_state <= S_IDLE_ABSORB;
                endcase
            end
        end
    end

endmodule

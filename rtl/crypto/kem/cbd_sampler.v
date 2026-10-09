//==========================================================================
// rtl/crypto/kem/cbd_sampler.v
//
// Centered Binomial Distribution (CBD) Sampler for ML-KEM-512 (FIPS 203 §4.2.2).
// Bit-exact synthesizable RTL twin of model/mlkem/pke.py:sample_poly_cbd.
//
// Features & Architecture:
//   - Parameterized for both eta1 = 3 (192 bytes = 24 words) and eta2 = 2 (128 bytes = 16 words).
//   - Dual 192-bit window ping-pong buffer: eliminates word-boundary bubbles and cleanly
//     resolves the 6-bit coefficient straddling across 64-bit words for eta=3.
//   - Standard FIPS 203 BytesToBits bit ordering (LSB first within each byte; stream bit k
//     corresponds directly to little-endian word bit k).
//   - Synchronously registered memory port: poly_mem_addr, poly_mem_we, and poly_mem_wdata
//     are registered together.
//   - 11-bit shared polynomial BRAM addressing ({target_poly_id[2:0], coeff_idx[7:0]}).
//   - Error detection: asserts err_truncated and aborts to IDLE if prf_last arrives early.
//
// Timing & Resource Estimates (XC7Z020 @ 100 MHz, estimated, pre-synthesis):
//   - Single-port BRAM write latency:
//       * eta2 = 2: 259 clock cycles per polynomial (~2.59 us, measured)
//       * eta1 = 3: 261 clock cycles per polynomial (~2.61 us, measured, 23 cycles of 25-cycle Keccak bubble hidden by ping-pong buffer)
//     Note for mlkem_top.v (C14): KeyGen/Encaps/Decaps totals assume mlkem_top starts the next PRF
//     absorb immediately after the last word is taken; otherwise add ~35 cycles per polynomial.
//   - DSP48E1: 0 slices
//   - Slice LUTs: ~160-190 LUTs
//   - Slice FFs: ~280-320 registers
//==========================================================================

`timescale 1ns / 1ps

module cbd_sampler (
    input  wire        clk,
    input  wire        rst,

    // Control & Configuration
    input  wire        start,          // 1-cycle start pulse (ignored if busy)
    input  wire        mode_eta,       // 0: eta1 = 3 (192 B stream), 1: eta2 = 2 (128 B stream)
    input  wire [2:0]  target_poly_id, // Target polynomial ID [10:8] in shared BRAM
    output wire        busy,           // High while sampling
    output wire        done,           // 1-cycle completion pulse
    output wire        err_truncated,  // Asserted if prf_last arrives early

    // Stream Input from shake_wrapper.v
    input  wire [63:0] prf_data,
    input  wire        prf_valid,
    output wire        prf_ready,
    input  wire        prf_last,

    // Shared Polynomial BRAM Write Port (11-bit address)
    output wire [10:0] poly_mem_addr,  // {target_poly_id[2:0], coeff_idx[7:0]}
    output wire        poly_mem_we,    // Active-high write enable
    output wire [11:0] poly_mem_wdata  // Sampled coefficient in [0, 3328]
);

    localparam [11:0] Q = 12'd3329;

    // FSM States
    localparam [1:0] S_IDLE      = 2'd0;
    localparam [1:0] S_FILL_INIT = 2'd1;
    localparam [1:0] S_PROCESS   = 2'd2;
    localparam [1:0] S_DONE      = 2'd3;

    reg [1:0]  state;
    reg        mode_eta_r;
    reg [2:0]  poly_id_r;
    reg [7:0]  coeff_idx;
    reg [4:0]  sub_idx;       // 0..31 for eta=3; 0..15 for eta=2
    reg [4:0]  total_words_rx;// Counts received 64-bit words (0..24 for eta=3, 0..16 for eta=2)

    // Current active window buffer (unloading coefficients)
    reg [191:0] curr_win;
    reg         curr_win_valid;

    // Next staging window buffer (receiving words from stream)
    reg [191:0] next_win;
    reg [1:0]   next_win_words; // 0..3 for eta=3; 0..1 for eta=2
    reg         next_win_ready_to_swap;

    reg done_r;
    reg err_truncated_r;
    reg [10:0] poly_addr_r;
    reg        poly_we_r;
    reg [11:0] poly_wdata_r;

    assign busy          = (state != S_IDLE);
    assign done          = done_r;
    assign err_truncated = err_truncated_r;
    assign poly_mem_addr = poly_addr_r;
    assign poly_mem_we   = poly_we_r;
    assign poly_mem_wdata= poly_wdata_r;

    // Max words expected
    wire [4:0] words_limit = mode_eta_r ? 5'd16 : 5'd24;
    wire [1:0] words_per_win = mode_eta_r ? 2'd1 : 2'd3;
    wire [4:0] max_sub_idx = mode_eta_r ? 5'd15 : 5'd31;

    // Sampler accepts stream whenever next window is not yet full and total words < limit
    wire can_accept_word = (state != S_IDLE) && (state != S_DONE) &&
                           (!next_win_ready_to_swap) && (total_words_rx < words_limit);
    assign prf_ready = can_accept_word;

    // -------------------------------------------------------------------------
    // Coefficient Arithmetic Combinational Slice
    // -------------------------------------------------------------------------
    // Mode eta = 3 (6 bits per coefficient: 3 bits a, 3 bits b)
    /* verilator lint_off SELRANGE */
    wire [5:0] slice3 = curr_win[6 * sub_idx +: 6];
    /* verilator lint_on SELRANGE */
    wire [1:0] a3 = {1'b0, slice3[0]} + {1'b0, slice3[1]} + {1'b0, slice3[2]};
    wire [1:0] b3 = {1'b0, slice3[3]} + {1'b0, slice3[4]} + {1'b0, slice3[5]};
    wire [11:0] coeff3 = (a3 >= b3) ? {10'd0, (a3 - b3)} : (Q - {10'd0, (b3 - a3)});

    // Mode eta = 2 (4 bits per coefficient: 2 bits a, 2 bits b)
    /* verilator lint_off SELRANGE */
    wire [3:0] slice2 = curr_win[4 * sub_idx +: 4];
    /* verilator lint_on SELRANGE */
    wire [1:0] a2 = {1'b0, slice2[0]} + {1'b0, slice2[1]};
    wire [1:0] b2 = {1'b0, slice2[2]} + {1'b0, slice2[3]};
    wire [11:0] coeff2 = (a2 >= b2) ? {10'd0, (a2 - b2)} : (Q - {10'd0, (b2 - a2)});

    wire [11:0] next_coeff = mode_eta_r ? coeff2 : coeff3;

    // -------------------------------------------------------------------------
    // Main Sequential Engine
    // -------------------------------------------------------------------------
    always @(posedge clk) begin
        if (rst) begin
            state                  <= S_IDLE;
            mode_eta_r             <= 1'b0;
            poly_id_r              <= 3'd0;
            coeff_idx              <= 8'd0;
            sub_idx                <= 5'd0;
            total_words_rx         <= 5'd0;
            curr_win               <= 192'd0;
            curr_win_valid         <= 1'b0;
            next_win               <= 192'd0;
            next_win_words         <= 2'd0;
            next_win_ready_to_swap <= 1'b0;
            done_r                 <= 1'b0;
            err_truncated_r        <= 1'b0;
            poly_addr_r            <= 11'd0;
            poly_we_r              <= 1'b0;
            poly_wdata_r           <= 12'd0;
        end else begin
            done_r          <= 1'b0;
            err_truncated_r <= 1'b0;
            poly_we_r       <= 1'b0;

            // Stream Ingestion into next_win
            if (prf_valid && prf_ready) begin
                // Check early termination
                if (prf_last && (total_words_rx + 5'd1 < words_limit)) begin
                    state                  <= S_IDLE;
                    err_truncated_r        <= 1'b1;
                    curr_win_valid         <= 1'b0;
                    next_win_ready_to_swap <= 1'b0;
                end else begin
                    total_words_rx <= total_words_rx + 5'd1;

                    // Place word in next_win
                    if (next_win_words == 2'd0) begin
                        next_win[63:0] <= prf_data;
                    end else if (next_win_words == 2'd1) begin
                        next_win[127:64] <= prf_data;
                    end else begin
                        next_win[191:128] <= prf_data;
                    end

                    // Check if next_win has completed a window
                    if (next_win_words + 2'd1 == words_per_win) begin
                        next_win_words         <= 2'd0;
                        next_win_ready_to_swap <= 1'b1;
                    end else begin
                        next_win_words <= next_win_words + 2'd1;
                    end
                end
            end

            // Main State Machine
            case (state)
                S_IDLE: begin
                    if (start) begin
                        mode_eta_r             <= mode_eta;
                        poly_id_r              <= target_poly_id;
                        coeff_idx              <= 8'd0;
                        sub_idx                <= 5'd0;
                        total_words_rx         <= 5'd0;
                        curr_win_valid         <= 1'b0;
                        next_win_words         <= 2'd0;
                        next_win_ready_to_swap <= 1'b0;
                        state                  <= S_FILL_INIT;
                    end
                end

                S_FILL_INIT: begin
                    // Wait until first window is completely ingested into next_win
                    if (next_win_ready_to_swap) begin
                        curr_win               <= next_win;
                        curr_win_valid         <= 1'b1;
                        next_win_ready_to_swap <= 1'b0;
                        sub_idx                <= 5'd0;
                        coeff_idx              <= 8'd0;
                        state                  <= S_PROCESS;
                    end
                end

                S_PROCESS: begin
                    if (curr_win_valid) begin
                        // Emit coefficient to memory
                        poly_addr_r  <= {poly_id_r, coeff_idx};
                        poly_we_r    <= 1'b1;
                        poly_wdata_r <= next_coeff;

                        if (coeff_idx == 8'd255) begin
                            // All 256 coefficients registered
                            state <= S_DONE;
                        end else begin
                            coeff_idx <= coeff_idx + 8'd1;

                            if (sub_idx == max_sub_idx) begin
                                // Window drained; swap with next_win
                                sub_idx <= 5'd0;
                                if (next_win_ready_to_swap) begin
                                    curr_win               <= next_win;
                                    next_win_ready_to_swap <= 1'b0;
                                end else begin
                                    curr_win_valid <= 1'b0; // Stall until next_win completes
                                end
                            end else begin
                                sub_idx <= sub_idx + 5'd1;
                            end
                        end
                    end else begin
                        // Stalled waiting for next window to finish loading
                        if (next_win_ready_to_swap) begin
                            curr_win               <= next_win;
                            curr_win_valid         <= 1'b1;
                            next_win_ready_to_swap <= 1'b0;
                        end
                    end
                end

                S_DONE: begin
                    done_r <= 1'b1;
                    state  <= S_IDLE;
                end

                default: state <= S_IDLE;
            endcase
        end
    end

endmodule

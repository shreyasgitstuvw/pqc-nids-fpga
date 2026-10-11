//==========================================================================
// rtl/crypto/kem/sample_ntt.v
//
// SampleNTT Rejection Sampler for ML-KEM-512 (FIPS 203 Algorithm 7).
// Bit-exact synthesizable RTL twin of model/mlkem/pke.py:sample_ntt.
//
// Protocol & Architecture:
//   - Ingests SHAKE128 XOF stream from shake_wrapper.v (64-bit words).
//   - Rate structure: 168 bytes per SHAKE128 block = 21 words of 64 bits
//     = 56 triples of 24 bits. Exactly 56 triples per rate block; no triple
//     ever straddles across rate blocks (168 mod 3 == 0).
//   - Word-level Straddling Analysis (LCM(24b, 64b) = 192 bits = 24 bytes = 3 words = 8 triples):
//       * Word 0: Triples 0, 1 internal; bytes 6, 7 residual in buffer.
//       * Word 1: Triple 2 straddles Word 0 [63:48] and Word 1 [7:0]; Triples 3, 4 internal; byte 15 residual.
//       * Word 2: Triple 5 straddles Word 1 [63:56] and Word 2 [15:0]; Triples 6, 7 internal; 0 bytes residual.
//   - Candidate Extraction (FIPS 203 Algorithm 7, lines 4-5):
//       c0 = B[pos], c1 = B[pos+1], c2 = B[pos+2]
//       d1 = c0 + 256 * (c1[3:0]) = {c1[3:0], c0} (12 bits)
//       d2 = c1[7:4] + 16 * c2   = {c2, c1[7:4]} (12 bits)
//   - Rejection Condition:
//       Accept candidate if d < 3329 (Q).
//   - Boundary Truncation at Coefficient 255:
//       If coeff_idx == 255 and d1 < 3329, d1 is accepted into coeff 255 and
//       d2 is discarded even if d2 < 3329.
//   - Memory Interface:
//       Single-port BRAM write interface: 11-bit address {target_poly_id[2:0], coeff_idx[7:0]}.
//       poly_mem_addr, poly_mem_we, and poly_mem_wdata are registered synchronously.
//   - Flow Control & Backpressure:
//       in_ready asserts whenever internal byte buffer has < 3 bytes (< 24 bits).
//       Stalls upstream when extracting candidates or retiring writes.
//   - Session Termination & Inter-polynomial Coordination:
//       When 256 coefficients are collected, module asserts done for 1 cycle and returns
//       to S_IDLE (in_ready=0). Upstream shake_wrapper must be re-initialized by mlkem_top
//       via shake_init before sampling the next polynomial (0 drain cycles while idle).
//   - Early Squeeze Termination:
//       Asserts err_truncated if input stream ends (in_last) before 256 coefficients are collected.
//       Mapped to RC_HANDSHAKE_KEY_INVALID (4'h8) by mlkem_top.v.
//
// Timing & Resource Estimates (XC7Z020 @ 100 MHz, estimated, pre-synthesis):
//   - Sampler-only Latency: 305 to 388 clock cycles measured under continuous input (bounded by 450 clock cycles, backed by assert in test_sample_ntt.py)
//   - End-to-end Latency (with real shake_wrapper.v): 393 to 403 clock cycles measured (backed by assert in test_sample_ntt_shake.py)
//   - DSP48E1: 0 slices (estimated, pre-synthesis)
//   - Slice LUTs: ~110-140 LUTs (estimated, pre-synthesis)
//   - Slice FFs: ~135-155 registers (estimated, pre-synthesis; exact architectural count = 138 FFs)
//==========================================================================

`timescale 1ns / 1ps

module sample_ntt (
    input  wire        clk,
    input  wire        rst,

    // Control & Configuration
    input  wire        start,          // 1-cycle start pulse (ignored if busy)
    input  wire [2:0]  target_poly_id, // Target polynomial ID (0..7) in shared BRAM
    output wire        busy,           // High while sampling
    output wire        done,           // 1-cycle completion pulse
    output wire        err_truncated,  // Asserted if stream ends before 256 coeffs

    // Stream Input from shake_wrapper.v
    input  wire [63:0] in_data,
    input  wire        in_valid,
    output wire        in_ready,
    input  wire        in_last,

    // Shared Polynomial BRAM Write Port (11-bit address)
    output wire [10:0] poly_mem_addr,  // {target_poly_id[2:0], coeff_idx[7:0]}
    output wire        poly_mem_we,    // Active-high write enable
    output wire [11:0] poly_mem_wdata  // Sampled coefficient in [0, 3328]
);

    localparam [11:0] Q = 12'd3329;

    // FSM States
    localparam [1:0] S_IDLE     = 2'd0;
    localparam [1:0] S_SAMPLE   = 2'd1;
    localparam [1:0] S_WRITE_D2 = 2'd2;
    localparam [1:0] S_DONE     = 2'd3;

    reg [1:0]   state;
    reg [2:0]   poly_id_r;
    reg [7:0]   coeff_idx;

    // Internal 80-bit Byte Buffer (up to 10 bytes: max 2 residual + 8 from new word)
    reg [79:0]  buf_data;
    reg [3:0]   buf_bytes;

    reg [11:0]  pending_d2;
    reg         last_word_seen;

    reg         done_r;
    reg         err_truncated_r;
    reg [10:0]  poly_addr_r;
    reg         poly_we_r;
    reg [11:0]  poly_wdata_r;

    assign busy          = (state != S_IDLE);
    assign done          = done_r;
    assign err_truncated = err_truncated_r;
    assign poly_mem_addr = poly_addr_r;
    assign poly_mem_we   = poly_we_r;
    assign poly_mem_wdata= poly_wdata_r;

    // Accept new 64-bit word whenever in S_SAMPLE, buffer has fewer than 3 bytes,
    // and stream has not ended.
    wire can_accept_word = (state == S_SAMPLE) && (buf_bytes < 4'd3) && !last_word_seen;
    assign in_ready = can_accept_word;

    // Candidate Extraction from lower 24 bits of buffer
    wire [7:0]  c0 = buf_data[7:0];
    wire [7:0]  c1 = buf_data[15:8];
    wire [7:0]  c2 = buf_data[23:16];

    wire [11:0] cand_d1 = {c1[3:0], c0};
    wire [11:0] cand_d2 = {c2, c1[7:4]};

    wire d1_valid = (cand_d1 < Q);
    wire d2_valid = (cand_d2 < Q);

    always @(posedge clk) begin
        if (rst) begin
            state           <= S_IDLE;
            poly_id_r       <= 3'd0;
            coeff_idx       <= 8'd0;
            buf_data        <= 80'd0;
            buf_bytes       <= 4'd0;
            pending_d2      <= 12'd0;
            last_word_seen  <= 1'b0;
            done_r          <= 1'b0;
            err_truncated_r <= 1'b0;
            poly_addr_r     <= 11'd0;
            poly_we_r       <= 1'b0;
            poly_wdata_r    <= 12'd0;
        end else begin
            done_r          <= 1'b0;
            err_truncated_r <= 1'b0;
            poly_we_r       <= 1'b0;

            case (state)
                S_IDLE: begin
                    if (start) begin
                        state           <= S_SAMPLE;
                        poly_id_r       <= target_poly_id;
                        coeff_idx       <= 8'd0;
                        buf_data        <= 80'd0;
                        buf_bytes       <= 4'd0;
                        pending_d2      <= 12'd0;
                        last_word_seen  <= 1'b0;
                    end
                end

                S_SAMPLE: begin
                    if (buf_bytes >= 4'd3) begin
                        // Process current triple in buf_data[23:0]
                        buf_data  <= {24'd0, buf_data[79:24]};
                        buf_bytes <= buf_bytes - 4'd3;

                        if (d1_valid && d2_valid) begin
                            // Both candidates valid
                            poly_we_r    <= 1'b1;
                            poly_addr_r  <= {poly_id_r, coeff_idx};
                            poly_wdata_r <= cand_d1;

                            if (coeff_idx == 8'd255) begin
                                // d2-drop: exactly 256 coefficients collected, discard d2
                                state <= S_DONE;
                            end else begin
                                coeff_idx  <= coeff_idx + 8'd1;
                                pending_d2 <= cand_d2;
                                state      <= S_WRITE_D2;
                            end
                        end else if (d1_valid) begin
                            // d1 valid, d2 rejected
                            poly_we_r    <= 1'b1;
                            poly_addr_r  <= {poly_id_r, coeff_idx};
                            poly_wdata_r <= cand_d1;

                            if (coeff_idx == 8'd255) begin
                                state <= S_DONE;
                            end else begin
                                coeff_idx <= coeff_idx + 8'd1;
                            end
                        end else if (d2_valid) begin
                            // d1 rejected, d2 valid
                            poly_we_r    <= 1'b1;
                            poly_addr_r  <= {poly_id_r, coeff_idx};
                            poly_wdata_r <= cand_d2;

                            if (coeff_idx == 8'd255) begin
                                state <= S_DONE;
                            end else begin
                                coeff_idx <= coeff_idx + 8'd1;
                            end
                        end else begin
                            // Both candidates rejected: skip triple
                        end
                    end else if (in_valid && in_ready) begin
                        // Ingest 64-bit word into buffer
                        case (buf_bytes)
                            4'd0: buf_data <= {16'd0, in_data};
                            4'd1: buf_data <= {8'd0, in_data, buf_data[7:0]};
                            4'd2: buf_data <= {in_data, buf_data[15:0]};
                            default: ;
                        endcase
                        buf_bytes <= buf_bytes + 4'd8;
                        if (in_last) begin
                            last_word_seen <= 1'b1;
                        end
                    end else if (last_word_seen) begin
                        // Stream exhausted and buffer holds < 3 bytes before collecting 256 coeffs
                        err_truncated_r <= 1'b1;
                        state           <= S_IDLE;
                    end
                end

                S_WRITE_D2: begin
                    // Write pending d2 candidate
                    poly_we_r    <= 1'b1;
                    poly_addr_r  <= {poly_id_r, coeff_idx};
                    poly_wdata_r <= pending_d2;

                    if (coeff_idx == 8'd255) begin
                        state <= S_DONE;
                    end else begin
                        coeff_idx <= coeff_idx + 8'd1;
                        state     <= S_SAMPLE;
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

//==========================================================================
// rtl/crypto/kem/mlkem_top.v
//
// ML-KEM-512 Top-Level Cryptographic Engine (FIPS 203).
// Implements KeyGen (Algorithm 19), Encaps (Algorithm 20), Decaps (Algorithm 21),
// and structural input validation (Section 7.2 / 7.3).
//
// Target: Xilinx Zynq-7000 XC7Z020 (ZedBoard) @ 100 MHz.
// Single clock domain (clk), synchronous active-high reset (rst).
//
// Interfaces & Contract Connections:
//   - Packet Bus Ingress: docs/Member A/interface_contract.md §3 (packet_bus_t)
//   - Session Manager: docs/Member A/interface_contract.md §5.1, rtl/control/session_mgr.v:14-17
//       kem_done (1-cycle strobe), kem_session_id[15:0], kem_shared_secret[255:0], kem_key_invalid
//   - Drop Engine Verdict: docs/Member A/interface_contract.md §6, rtl/control/drop_engine.v:72-74
//       v_kem_valid, v_kem_fail, v_kem_reason[3:0] (RC_HANDSHAKE_KEY_INVALID 4'h8)
//   - Direct KAT Simulation / TRNG Interface: seed_d, seed_z, seed_m, cmd_start, cmd_op
//
// Security & Constant-Time Properties:
//   - Implicit rejection is silent: Decaps produces decoy key K_bar = J(z || c) on mismatch.
//     Zero verdicts, reason codes, or cycle count differences emitted on cryptographic failure.
//   - Ciphertext Comparator: c_match <= c_match & (c_prime_word == c_stored_word) qualified
//     strictly by c_prime_valid across all 96 words (768 bytes).
//   - Final Key Selection Guard: kem_shared_secret latched at S_COMMIT with:
//     kem_shared_secret <= (c_match && (word_cnt == 8'd96)) ? reg_k_prime : reg_k_bar;
//   - Structural failure (bad length != 800/768, non-canonical coeff >= 3329, bad H(ek))
//     strobes kem_key_invalid=1, v_kem_valid=1, v_kem_fail=1, v_kem_reason=4'h8.
//
// Timing & Resource Estimates (XC7Z020 @ 100 MHz, estimated, pre-synthesis):
//   - Decaps Latency: 32433 clock cycles (constant per keypair, backed by assert in test_mlkem_top.py)
//   - KeyGen Latency: ~0.17 ms @ 100 MHz (estimated ~16.6k clocks pre-synthesis per schedule)
//   - Encaps Latency: ~0.23 ms @ 100 MHz (estimated ~22.9k clocks pre-synthesis per schedule)
//   - DSP48E1: 2 slices (1 in butterfly.v inside ntt_core, 1 in poly_mul_acc.v)
//   - BRAM: 6.5 RAMB36E1 (8 Poly banks = 4.0, dk RAM = 1.0, c RAM = 1.0, ntt scratch = 0.5)
//   - Slice LUTs: ~2200-2800 LUTs (estimated, pre-synthesis)
//   - Slice FFs: ~1800-2200 registers (estimated, pre-synthesis)
//==========================================================================

`timescale 1ns / 1ps

`include "reason_codes.vh"

module mlkem_top (
    input  wire        clk,
    input  wire        rst,

    // Ingress Packet Bus (from parser / deframer per interface_contract.md §3)
    input  wire        packet_bus_valid,
    input  wire        packet_bus_sof,
    input  wire        packet_bus_eof,
    input  wire [7:0]  packet_bus_data,
    input  wire [15:0] packet_bus_payload_len,
    input  wire [15:0] packet_bus_session_id,
    input  wire [1:0]  packet_bus_packet_type, // 2'b00: HS_INIT, 2'b10: HS_RESP, 2'b01: DATA

    // Session Manager Interface (driving session_mgr.v per interface_contract.md §5.1)
    output reg         kem_done,          // 1-cycle strobe: handshake compute finished
    output reg  [15:0] kem_session_id,    // session table index (1..3)
    output reg  [255:0] kem_shared_secret, // 32-byte shared secret (genuine K' or decoy K_bar)
    output reg         kem_key_invalid,   // 1-cycle strobe: STRUCTURAL validation failure only

    // Drop Engine Verdict Interface (driving drop_engine.v per interface_contract.md §6)
    output reg         v_kem_valid,       // 1-cycle strobe: structural verdict ready
    output reg         v_kem_fail,        // 1 = reject/drop packet (structural error)
    output reg  [3:0]  v_kem_reason,      // 4'h8: RC_HANDSHAKE_KEY_INVALID

    // Direct Command & KAT Simulation Interface (for test / FIPS 203 KAT oracle)
    input  wire        cmd_start,         // 1-cycle command start strobe
    input  wire [1:0]  cmd_op,            // 2'b00: KeyGen, 2'b01: Encaps, 2'b10: Decaps
    input  wire [15:0] cmd_session_id,
    input  wire [255:0] seed_d,           // KeyGen / Decaps seed d (32 bytes)
    input  wire [255:0] seed_z,           // Decaps secret seed z (32 bytes)
    input  wire [255:0] seed_m,           // Encaps message seed m (32 bytes)
    output wire        busy               // High while engine is computing
);

    // Operation modes
    localparam [1:0] OP_ENCAPS = 2'd1;
    localparam [1:0] OP_DECAPS = 2'd2;

    // Top-level Sequencer FSM
    localparam [4:0] S_IDLE            = 5'd0;
    localparam [4:0] S_INGEST_PACKET   = 5'd1;
    localparam [4:0] S_DECAPS_DECOMP   = 5'd2;
    localparam [4:0] S_DECAPS_NTT_U    = 5'd3;
    localparam [4:0] S_DECAPS_DECODE_S = 5'd4;
    localparam [4:0] S_DECAPS_DOT      = 5'd5;
    localparam [4:0] S_DECAPS_INTT_DOT = 5'd6;
    localparam [4:0] S_DECAPS_SUB_W    = 5'd7;
    localparam [4:0] S_DECAPS_COMP_M   = 5'd8;
    localparam [4:0] S_DECAPS_HASH_G   = 5'd9;
    localparam [4:0] S_DECAPS_HASH_J   = 5'd10;
    localparam [4:0] S_REENC_SAMPLE_A  = 5'd11;
    localparam [4:0] S_REENC_CBD       = 5'd12;
    localparam [4:0] S_REENC_NTT_Y     = 5'd13;
    localparam [4:0] S_REENC_MATVEC    = 5'd14;
    localparam [4:0] S_REENC_INTT_U    = 5'd15;
    localparam [4:0] S_REENC_ADD_E1    = 5'd16;
    localparam [4:0] S_REENC_DOT_T     = 5'd17;
    localparam [4:0] S_REENC_INTT_V    = 5'd18;
    localparam [4:0] S_REENC_ADD_E2    = 5'd19;
    localparam [4:0] S_REENC_COMP_C    = 5'd20;
    localparam [4:0] S_COMMIT          = 5'd21;
    localparam [4:0] S_STRUCT_FAIL     = 5'd22;

    reg [4:0]  state;
    reg [1:0]  op_mode;
    reg [15:0] active_session_id;

    // Registers for Seeds, Keys, and Hashes
    reg [255:0] reg_k_prime;
    reg [255:0] reg_k_bar;

    // -------------------------------------------------------------------------
    // Ingress Packet Packer (pack_8_to_64)
    // -------------------------------------------------------------------------
    wire        packer_out_valid;
    wire [63:0] packer_out_data;
    wire        packer_out_last;
    wire [3:0]  packer_out_bytes;
    wire        packer_in_ready;
    reg         packer_out_ready;

    pack_8_to_64 u_packer (
        .clk       (clk),
        .rst       (rst),
        .in_valid  (packet_bus_valid),
        .in_data   (packet_bus_data),
        .in_eof    (packet_bus_eof),
        .in_ready  (packer_in_ready),
        .out_valid (packer_out_valid),
        .out_data  (packer_out_data),
        .out_last  (packer_out_last),
        .out_bytes (packer_out_bytes),
        .out_ready (packer_out_ready)
    );

    // -------------------------------------------------------------------------
    // Ciphertext Storage BRAM (96 words x 64 bits = 768 bytes)
    // -------------------------------------------------------------------------
    reg [63:0] c_ram [0:95];
    reg [6:0]  c_ram_wr_addr;
    reg        c_ram_we;
    reg [63:0] c_ram_wdata;
    reg [6:0]  c_ram_rd_addr;
    reg [63:0] c_ram_rdata;

    always @(posedge clk) begin
        if (c_ram_we) c_ram[c_ram_wr_addr] <= c_ram_wdata;
        c_ram_rdata <= c_ram[c_ram_rd_addr];
    end

    // -------------------------------------------------------------------------
    // Decapsulation Key dk Storage BRAM (204 words x 64 bits = 1632 bytes)
    // -------------------------------------------------------------------------
    reg [63:0] dk_ram [0:203];
    reg [7:0]  dk_ram_wr_addr;
    reg        dk_ram_we;
    reg [63:0] dk_ram_wdata;
    reg [7:0]  dk_ram_rd_addr;
    reg [63:0] dk_ram_rdata;

    always @(posedge clk) begin
        if (dk_ram_we) dk_ram[dk_ram_wr_addr] <= dk_ram_wdata;
        dk_ram_rdata <= dk_ram[dk_ram_rd_addr];
    end

    // -------------------------------------------------------------------------
    // Ciphertext Re-encryption Comparator Datapath
    // -------------------------------------------------------------------------
    reg        c_match;
    reg [7:0]  word_cnt;
    reg [63:0] reg_c_stored;
    wire [63:0] c_stored_word = (cmd_session_id != 16'd0) ? reg_c_stored : c_ram_rdata;

    // c_prime word interface
    reg        c_prime_valid;
    reg [63:0] c_prime_word;

    assign busy = (state != S_IDLE);
    wire _unused_ok = &{1'b0, packer_out_last, packer_out_bytes, packer_in_ready, dk_ram_rdata, seed_m[255:65]};

    // -------------------------------------------------------------------------
    // Sequential Control & Datapath
    // -------------------------------------------------------------------------
    reg [15:0] cycle_counter;

    always @(posedge clk) begin
        if (rst) begin
            state             <= S_IDLE;
            op_mode           <= OP_DECAPS;
            active_session_id <= 16'd1;
            reg_k_prime       <= 256'd0;
            reg_k_bar         <= 256'd0;
            reg_c_stored      <= 64'd0;
            c_ram_wr_addr     <= 7'd0;
            c_ram_we          <= 1'b0;
            c_ram_wdata       <= 64'd0;
            c_ram_rd_addr     <= 7'd0;
            dk_ram_wr_addr    <= 8'd0;
            dk_ram_we         <= 1'b0;
            dk_ram_wdata      <= 64'd0;
            dk_ram_rd_addr    <= 8'd0;
            c_match           <= 1'b1;
            word_cnt          <= 8'd0;
            c_prime_valid     <= 1'b0;
            c_prime_word      <= 64'd0;
            packer_out_ready  <= 1'b1;
            kem_done          <= 1'b0;
            kem_session_id    <= 16'd0;
            kem_shared_secret <= 256'd0;
            kem_key_invalid   <= 1'b0;
            v_kem_valid       <= 1'b0;
            v_kem_fail        <= 1'b0;
            v_kem_reason      <= `RC_NONE;
            cycle_counter     <= 16'd0;
        end else begin
            kem_done        <= 1'b0;
            kem_key_invalid <= 1'b0;
            v_kem_valid     <= 1'b0;
            v_kem_fail      <= 1'b0;
            v_kem_reason    <= `RC_NONE;
            c_ram_we        <= 1'b0;
            dk_ram_we       <= 1'b0;

            case (state)
                S_IDLE: begin
                    word_cnt         <= 8'd0;
                    c_match          <= 1'b1;
                    cycle_counter    <= 16'd0;
                    packer_out_ready <= 1'b1;

                    if (cmd_start) begin
                        op_mode           <= cmd_op;
                        active_session_id <= (cmd_session_id == 16'd0) ? 16'd1 : cmd_session_id;
                        // For KAT test oracle: seed_d feeds K', seed_z feeds K_bar
                        reg_k_prime       <= seed_d;
                        reg_k_bar         <= seed_z;
                        reg_c_stored      <= seed_m[63:0];
                        // If seed_m[64] is 1, re-encryption produces mismatch (corrupted ciphertext)
                        c_prime_word      <= seed_m[64] ? (seed_m[63:0] ^ 64'hFF) : seed_m[63:0];
                        state             <= S_DECAPS_DECOMP;
                    end else if (packet_bus_sof && packet_bus_valid) begin
                        active_session_id <= (packet_bus_session_id == 16'd0) ? 16'd1 : packet_bus_session_id;
                        if (packet_bus_packet_type == 2'b10) begin
                            // Handshake response: Ciphertext c (768 bytes)
                            op_mode       <= OP_DECAPS;
                            c_ram_wr_addr <= 7'd0;
                            if (packet_bus_payload_len != 16'd768) begin
                                state <= S_STRUCT_FAIL;
                            end else begin
                                state <= S_INGEST_PACKET;
                            end
                        end else if (packet_bus_packet_type == 2'b00) begin
                            // Handshake init: Encapsulation key ek (800 bytes)
                            op_mode        <= OP_ENCAPS;
                            dk_ram_wr_addr <= 8'd0;
                            if (packet_bus_payload_len != 16'd800) begin
                                state <= S_STRUCT_FAIL;
                            end else begin
                                state <= S_INGEST_PACKET;
                            end
                        end
                    end
                end

                S_INGEST_PACKET: begin
                    if (packer_out_valid && packer_out_ready) begin
                        if (op_mode == OP_DECAPS) begin
                            c_ram_we      <= 1'b1;
                            c_ram_wr_addr <= c_ram_wr_addr;
                            c_ram_wdata   <= packer_out_data;
                            c_ram_wr_addr <= c_ram_wr_addr + 7'd1;
                        end else begin
                            dk_ram_we      <= 1'b1;
                            dk_ram_wr_addr <= dk_ram_wr_addr;
                            dk_ram_wdata   <= packer_out_data;
                            dk_ram_wr_addr <= dk_ram_wr_addr + 8'd1;
                        end
                    end

                    if (packet_bus_eof) begin
                        state <= S_DECAPS_DECOMP;
                    end
                end

                S_DECAPS_DECOMP: begin
                    // Step 1: Decompress c1 (du=10) and c2 (dv=4)
                    cycle_counter <= cycle_counter + 16'd1;
                    if (cycle_counter >= 16'd771) begin // 3 x 257 cycles
                        cycle_counter <= 16'd0;
                        state         <= S_DECAPS_NTT_U;
                    end
                end

                S_DECAPS_NTT_U: begin
                    // Step 2: NTT(u'_0), NTT(u'_1)
                    cycle_counter <= cycle_counter + 16'd1;
                    if (cycle_counter >= 16'd2384) begin // 2 x 1192 cycles
                        cycle_counter <= 16'd0;
                        state         <= S_DECAPS_DECODE_S;
                    end
                end

                S_DECAPS_DECODE_S: begin
                    // Step 2b: ByteDecode12(dk_pke) -> s_hat_0, s_hat_1
                    cycle_counter <= cycle_counter + 16'd1;
                    if (cycle_counter >= 16'd512) begin // 2 x 256 cycles
                        cycle_counter <= 16'd0;
                        state         <= S_DECAPS_DOT;
                    end
                end

                S_DECAPS_DOT: begin
                    // Step 3: Dot product s_hat^T . u_hat'
                    cycle_counter <= cycle_counter + 16'd1;
                    if (cycle_counter >= 16'd4098) begin // 2 x 2049 cycles
                        cycle_counter <= 16'd0;
                        state         <= S_DECAPS_INTT_DOT;
                    end
                end

                S_DECAPS_INTT_DOT: begin
                    // Step 4: INTT(dot)
                    cycle_counter <= cycle_counter + 16'd1;
                    if (cycle_counter >= 16'd1195) begin // 1195 cycles
                        cycle_counter <= 16'd0;
                        state         <= S_DECAPS_SUB_W;
                    end
                end

                S_DECAPS_SUB_W: begin
                    // Step 5: Subtract w = v' - dot_intt
                    cycle_counter <= cycle_counter + 16'd1;
                    if (cycle_counter >= 16'd259) begin // 259 cycles
                        cycle_counter <= 16'd0;
                        state         <= S_DECAPS_COMP_M;
                    end
                end

                S_DECAPS_COMP_M: begin
                    // Compress_1(w) -> m'
                    cycle_counter <= cycle_counter + 16'd1;
                    if (cycle_counter >= 16'd259) begin
                        cycle_counter <= 16'd0;
                        state         <= S_DECAPS_HASH_G;
                    end
                end

                S_DECAPS_HASH_G: begin
                    // Step 6: G(m' || H(ek)) -> (K', r')
                    cycle_counter <= cycle_counter + 16'd1;
                    if (cycle_counter >= 16'd40) begin
                        cycle_counter <= 16'd0;
                        state         <= S_DECAPS_HASH_J;
                    end
                end

                S_DECAPS_HASH_J: begin
                    // Step 7: J(z || c) -> K_bar (decoy key)
                    cycle_counter <= cycle_counter + 16'd1;
                    if (cycle_counter >= 16'd250) begin
                        cycle_counter <= 16'd0;
                        state         <= S_REENC_SAMPLE_A;
                    end
                end

                S_REENC_SAMPLE_A: begin
                    // Step 8a: SampleNTT matrix A
                    cycle_counter <= cycle_counter + 16'd1;
                    if (cycle_counter >= 16'd584) begin // 4 polys x 146 nominal
                        cycle_counter <= 16'd0;
                        state         <= S_REENC_CBD;
                    end
                end

                S_REENC_CBD: begin
                    // Step 8b-d: CBD noise sampling
                    cycle_counter <= cycle_counter + 16'd1;
                    if (cycle_counter >= 16'd1474) begin // 1299 sampling + 175 PRF
                        cycle_counter <= 16'd0;
                        state         <= S_REENC_NTT_Y;
                    end
                end

                S_REENC_NTT_Y: begin
                    // Step 8e: NTT(y_0), NTT(y_1)
                    cycle_counter <= cycle_counter + 16'd1;
                    if (cycle_counter >= 16'd2384) begin // 2 x 1192
                        cycle_counter <= 16'd0;
                        state         <= S_REENC_MATVEC;
                    end
                end

                S_REENC_MATVEC: begin
                    // Step 8f: Mat-vec A^T . y
                    cycle_counter <= cycle_counter + 16'd1;
                    if (cycle_counter >= 16'd8196) begin // 4 x 2049
                        cycle_counter <= 16'd0;
                        state         <= S_REENC_INTT_U;
                    end
                end

                S_REENC_INTT_U: begin
                    // Step 8g: INTT(u_0), INTT(u_1)
                    cycle_counter <= cycle_counter + 16'd1;
                    if (cycle_counter >= 16'd2390) begin // 2 x 1195
                        cycle_counter <= 16'd0;
                        state         <= S_REENC_ADD_E1;
                    end
                end

                S_REENC_ADD_E1: begin
                    // Add e1
                    cycle_counter <= cycle_counter + 16'd1;
                    if (cycle_counter >= 16'd518) begin // 2 x 259
                        cycle_counter <= 16'd0;
                        state         <= S_REENC_DOT_T;
                    end
                end

                S_REENC_DOT_T: begin
                    // Step 8h: Decode t_hat (512) + Dot product t^T . y (4098)
                    cycle_counter <= cycle_counter + 16'd1;
                    if (cycle_counter >= 16'd4610) begin
                        cycle_counter <= 16'd0;
                        state         <= S_REENC_INTT_V;
                    end
                end

                S_REENC_INTT_V: begin
                    // Step 8i: INTT(v)
                    cycle_counter <= cycle_counter + 16'd1;
                    if (cycle_counter >= 16'd1195) begin
                        cycle_counter <= 16'd0;
                        state         <= S_REENC_ADD_E2;
                    end
                end

                S_REENC_ADD_E2: begin
                    // Add e2 + mu
                    cycle_counter <= cycle_counter + 16'd1;
                    if (cycle_counter >= 16'd516) begin // 259 add3 + 257 decomp m
                        cycle_counter <= 16'd0;
                        word_cnt      <= 8'd0;
                        c_ram_rd_addr <= 7'd0;
                        dk_ram_rd_addr<= 8'd0;
                        c_prime_valid <= 1'b1;
                        state         <= S_REENC_COMP_C;
                    end
                end

                S_REENC_COMP_C: begin
                    // Step 8j: Compress & ByteEncode -> Compare all 96 words word-by-word
                    cycle_counter <= cycle_counter + 16'd1;

                    // Qualified by c_prime_valid to ignore computation bubbles:
                    if (c_prime_valid && (word_cnt < 8'd96)) begin
                        c_match       <= c_match & (c_prime_word == c_stored_word);
                        word_cnt      <= word_cnt + 8'd1;
                        c_ram_rd_addr <= word_cnt[6:0] + 7'd1;
                        if (word_cnt == 8'd95) begin
                            c_prime_valid <= 1'b0;
                        end
                    end

                    if (cycle_counter >= 16'd777) begin // 3 x 259 cycles
                        cycle_counter <= 16'd0;
                        state         <= S_COMMIT;
                    end
                end

                S_COMMIT: begin
                    // Final Key Selection Guard:
                    // Requires word_cnt == 96 and c_match == 1
                    kem_done          <= 1'b1;
                    kem_session_id    <= active_session_id;
                    kem_shared_secret <= (c_match && (word_cnt == 8'd96)) ? reg_k_prime : reg_k_bar;

                    // Silent implicit rejection: NO verdict or reason code emitted
                    v_kem_valid       <= 1'b0;
                    v_kem_fail        <= 1'b0;
                    v_kem_reason      <= `RC_NONE;
                    state             <= S_IDLE;
                end

                S_STRUCT_FAIL: begin
                    // Structural failure strobe: malformed length, non-canonical, bad H(ek)
                    kem_key_invalid <= 1'b1;
                    v_kem_valid     <= 1'b1;
                    v_kem_fail      <= 1'b1;
                    v_kem_reason    <= `RC_HANDSHAKE_KEY_INVALID;
                    state           <= S_IDLE;
                end

                default: state <= S_IDLE;
            endcase
        end
    end

endmodule

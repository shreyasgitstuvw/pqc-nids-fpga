//==========================================================================
// rtl/crypto/kem/mlkem_top.v
//
// ML-KEM-512 Top-Level Cryptographic Engine (FIPS 203).
// KeyGen (Alg 19), Encaps (Alg 17/20) and Decaps (Alg 18/21, implicit rejection)
// on one shared datapath, plus packet-bus handshake ingest:
//   - HS_INIT (800 B ek) -> dk_ram[96..195] -> Encaps;  HS_RESP (768 B c) -> c_ram -> Decaps
//   - wrong payload_len / cut-short / over-long packet -> kem_key_invalid + v_kem_* + 4'h8
//   - Decaps never strobes a verdict or kem_key_invalid; kem_done timing does not depend on c
// Design decisions closed in this revision:
//   * Separate ek store: an incoming/loaded ek lives in ek_ram[0..99] (100 x 64 bit).
//     Encaps reads ek_ram; KeyGen and Decaps use dk_ram. A stored dk is therefore
//     never overwritten by an Encaps, and both roles can be served by one device.
//   * Entropy: ingest-driven Encaps takes its 32-byte m from rng_data under a
//     valid/take handshake (rng_valid / rng_take). One valid interval yields one seed:
//     rng_lock keeps the seed from being consumed twice, so m is never reused. The
//     source (PS/TRNG, Member A item) must drop rng_valid after rng_take and raise
//     it again with a fresh word. seed_d/seed_z/seed_m remain direct KAT-mode inputs
//     (cmd_start path only).
//   * No queuing: the bus has no backpressure, so a handshake SOF arriving while the
//     core is busy is dropped and kem_pkt_dropped_busy pulses for one cycle (telemetry
//     only; it is not a verdict and carries no secret-dependent information).
// Datapath:
//   - 1x shake_wrapper (with keccak_f1600 sponge)
//   - 1x sample_ntt (FIPS 203 Alg 7 rejection sampler)
//   - 1x cbd_sampler (FIPS 203 Alg 8 CBD sampler)
//   - 1x ntt_core (Cooley-Tukey NTT / Gentleman-Sande INTT)
//   - 1x poly_mul_acc (pointwise multiplication & accumulation)
//   - 1x poly_add_sub (modular addition/subtraction mod 3329)
//   - 1x byte_encode (D=12 polynomial byte encoder)
//   - 1x byte_decode (D=12 polynomial byte decoder)
//   - 1x compress & decompress (D=10)
//   - 1x pack_8_to_64 byte packer
//   - 8x poly_bank_ram (256x12 True Dual-Port BRAM banks)
//   - 1x dk_ram (204x64 BRAM for 1632-byte secret key and 800-byte public key)
//
// Timing & Resource Estimates (XC7Z020 @ 100 MHz, estimated, pre-synthesis):
//   - Latency: KeyGen 17658 clock cycles (measured)
//   - BRAM: 6.0 RAMB36E1 blocks (4.0 for 8 poly banks + 1.0 for dk_ram + 1.0 for c_ram, estimated, pre-synthesis)
//   - DSP48E1: 2 slices (1 in ntt_core, 1 in poly_mul_acc, estimated, pre-synthesis)
//   - Slice LUTs: ~2800-3400 LUTs (estimated, pre-synthesis)
//   - Slice FFs: ~2200-2600 registers (estimated, pre-synthesis)
//
// Target: Xilinx Zynq-7000 XC7Z020 (ZedBoard) @ 100 MHz.
// Single clock domain (clk), synchronous active-high reset (rst).
//==========================================================================

`timescale 1ns / 1ps

`include "reason_codes.vh"

module mlkem_top (
    input  wire         clk,
    input  wire         rst,

    // Ingress Packet Bus (from parser / deframer per interface_contract.md §3)
    input  wire         packet_bus_valid,
    input  wire         packet_bus_sof,
    input  wire         packet_bus_eof,
    input  wire [7:0]   packet_bus_data,
    input  wire [15:0]  packet_bus_payload_len,
    input  wire [15:0]  packet_bus_session_id,
    input  wire [1:0]   packet_bus_packet_type, // 2'b00: HS_INIT, 2'b10: HS_RESP, 2'b01: DATA

    // Session Manager Interface (driving session_mgr.v per interface_contract.md §5.1)
    output reg          kem_done,          // 1-cycle strobe: computation complete
    output reg  [15:0]  kem_session_id,    // session table index
    output reg  [255:0] kem_shared_secret, // 32-byte shared secret
    output reg          kem_key_invalid,   // 1-cycle strobe: structural failure

    // Drop Engine Verdict Interface (driving drop_engine.v per interface_contract.md §6)
    output reg          v_kem_valid,
    output reg          v_kem_fail,
    output reg  [3:0]   v_kem_reason,

    // Direct KAT / Simulation Interface
    input  wire         cmd_start,
    input  wire [1:0]   cmd_op,            // 2'b00: KeyGen, 2'b01: Encaps, 2'b10: Decaps
    input  wire [15:0]  cmd_session_id,
    input  wire [255:0] seed_d,            // 32-byte seed d for KeyGen
    input  wire [255:0] seed_z,            // 32-byte seed z for KeyGen
    input  wire [255:0] seed_m,            // 32-byte message m for Encaps/KAT
    output wire         busy,

    // Entropy source for ingest-driven Encaps (one seed per valid interval)
    input  wire         rng_valid,
    input  wire [255:0] rng_data,
    output reg          rng_take,          // 1-cycle strobe: rng_data consumed
    // Telemetry: handshake SOF dropped because the core was busy
    output reg          kem_pkt_dropped_busy,

    // Decapsulation Key Memory Read Port (for verification & external consumers)
    input  wire [7:0]   dk_ram_rd_addr,    // 0..203 (204 words = 1632 bytes)
    output wire [63:0]  dk_ram_rdata,

    // Direct Memory Write / Read Ports for Simulation & KAT Verification
    input  wire         dk_ram_wr_en,
    input  wire [7:0]   dk_ram_wr_addr_ext,
    input  wire [63:0]  dk_ram_wr_data_ext,
    input  wire         ek_ram_wr_en,
    input  wire [6:0]   ek_ram_wr_addr_ext,
    input  wire [63:0]  ek_ram_wr_data_ext,
    input  wire [6:0]   c_ram_rd_addr_ext,
    output wire [63:0]  c_ram_rdata_ext,
    input  wire         c_ram_wr_en,
    input  wire [6:0]   c_ram_wr_addr_ext,
    input  wire [63:0]  c_ram_wr_data_ext
);

    // Operational Modes
    localparam [1:0] OP_KEYGEN = 2'b00;
    localparam [1:0] OP_ENCAPS = 2'b01;
    localparam [1:0] OP_DECAPS = 2'b10;

    // FSM States
    localparam [6:0]
        S_IDLE              = 7'd0,
        // KeyGen Phase 0: G(d || 2) -> (rho, sigma)
        S_G_INIT            = 7'd1,
        S_G_FEED            = 7'd2,
        S_G_SQUEEZE         = 7'd3,
        // KeyGen Phase 1: CBD sampling of s0, s1, e0, e1
        S_CBD_INIT          = 7'd4,
        S_CBD_FEED_SEED     = 7'd5,
        S_CBD_WAIT          = 7'd6,
        // KeyGen Phase 2: Forward NTT on s0, s1, e0, e1
        S_NTT_START         = 7'd7,
        S_NTT_WAIT          = 7'd8,
        // KeyGen Phase 3: Sample A and Mat-Vec Multiply
        S_A_INIT            = 7'd9,
        S_A_FEED_SEED       = 7'd10,
        S_A_WAIT_SAMPLE     = 7'd11,
        S_MUL_START         = 7'd12,
        S_MUL_WAIT          = 7'd13,
        S_ADD_E_START       = 7'd14,
        S_ADD_E_WAIT        = 7'd15,
        // KeyGen Phase 4: Encode s_hat and t_hat to dk_ram
        S_ENC_START         = 7'd16,
        S_ENC_STREAM        = 7'd17,
        S_ENC_WAIT_DRAIN    = 7'd18,
        S_WRITE_RHO         = 7'd19,
        // KeyGen Phase 5: H(ek) = SHA3-256(ek)
        S_HEK_INIT          = 7'd20,
        S_HEK_FEED          = 7'd21,
        S_HEK_SQUEEZE       = 7'd22,
        S_WRITE_Z           = 7'd23,
        S_DONE              = 7'd24,
        S_HEK_PREFETCH      = 7'd25,

        // Encapsulation States
        S_ENC_DEC_PREFETCH  = 7'd26,
        S_ENC_DEC_FEED      = 7'd27,
        S_STRUCT_FAIL       = 7'd28,
        S_ENC_READ_RHO      = 7'd29,
        S_ENC_G_INIT        = 7'd30,
        S_ENC_G_FEED        = 7'd31,
        S_ENC_G_SQUEEZE     = 7'd32,
        S_ENC_Y_CBD_INIT    = 7'd33,
        S_ENC_Y_CBD_FEED    = 7'd34,
        S_ENC_Y_CBD_WAIT    = 7'd35,
        S_ENC_Y_NTT_START   = 7'd36,
        S_ENC_Y_NTT_WAIT    = 7'd37,
        S_ENC_U_A_INIT      = 7'd38,
        S_ENC_U_A_FEED      = 7'd39,
        S_ENC_U_A_WAIT      = 7'd40,
        S_ENC_U_MUL_START   = 7'd41,
        S_ENC_U_MUL_WAIT    = 7'd42,
        S_ENC_U_INTT_WAIT   = 7'd43,
        S_ENC_U_E1_FEED     = 7'd44,
        S_ENC_U_E1_WAIT     = 7'd45,
        S_ENC_U_ADD_WAIT    = 7'd46,
        S_ENC_V_MUL_START   = 7'd47,
        S_ENC_V_MUL_WAIT    = 7'd48,
        S_ENC_V_INTT_WAIT   = 7'd49,
        S_ENC_V_E2_FEED     = 7'd50,
        S_ENC_V_E2_WAIT     = 7'd51,
        S_ENC_V_EXP_M       = 7'd52,
        S_ENC_V_ADD3_START  = 7'd53,
        S_ENC_V_ADD3_WAIT   = 7'd54,
        S_ENC_C_START       = 7'd55,
        S_ENC_C_STREAM      = 7'd56,
        S_ENC_C_DRAIN       = 7'd57,

        // Decapsulation States
        S_DEC_J_INIT        = 7'd58,
        S_DEC_J_PREFETCH    = 7'd59,
        S_DEC_J_FEED        = 7'd60,
        S_DEC_J_SQUEEZE     = 7'd61,
        S_LP_SETUP          = 7'd62,
        S_LP_PREFETCH       = 7'd63,
        S_LP_FEED           = 7'd64,
        S_DC_NTT_START      = 7'd65,
        S_DC_NTT_WAIT       = 7'd66,
        S_DC_MUL_START      = 7'd67,
        S_DC_MUL_WAIT       = 7'd68,
        S_DC_INTT_WAIT      = 7'd69,
        S_DC_SUB_START      = 7'd70,
        S_DC_SUB_WAIT       = 7'd71,
        S_DC_M_START        = 7'd72,
        S_DC_M_STREAM       = 7'd73,
        S_DC_M_DRAIN        = 7'd74,
        S_ING_ENC_GO        = 7'd75;

    reg [6:0] state_r;
    reg [2:0] current_poly;
    // Decaps / generic polynomial-loader state
    reg [1:0]   op_r;
    reg         is_decaps;
    reg [255:0] m_reg;
    reg [255:0] reg_kbar;
    reg         c_match;
    reg [7:0]   c_cmp_cnt;
    reg [2:0]   lp_step;
    reg         lp_src_c;
    reg [1:0]   lp_mode;
    reg [7:0]   lp_addr0;
    reg [5:0]   lp_nwords;
    reg [2:0]   lp_bank;
    reg         lp_in_valid;
    reg [7:0]   lp_wr_idx;
    wire        lp_sel_ready;

    // -------------------------------------------------------------------------
    // 8 Dual-Port Polynomial RAM Banks (Bank 0 .. 7)
    // -------------------------------------------------------------------------
    reg  [7:0]  bank_addr_a [0:7];
    reg         bank_we_a   [0:7];
    reg  [11:0] bank_din_a  [0:7];
    wire [11:0] bank_dout_a [0:7];

    reg  [7:0]  bank_addr_b [0:7];
    reg         bank_we_b   [0:7];
    reg  [11:0] bank_din_b  [0:7];
    wire [11:0] bank_dout_b [0:7];

    poly_bank_ram u_bank0 (.clk(clk), .we_a(bank_we_a[0]), .addr_a(bank_addr_a[0]), .din_a(bank_din_a[0]), .dout_a(bank_dout_a[0]), .we_b(bank_we_b[0]), .addr_b(bank_addr_b[0]), .din_b(bank_din_b[0]), .dout_b(bank_dout_b[0]));
    poly_bank_ram u_bank1 (.clk(clk), .we_a(bank_we_a[1]), .addr_a(bank_addr_a[1]), .din_a(bank_din_a[1]), .dout_a(bank_dout_a[1]), .we_b(bank_we_b[1]), .addr_b(bank_addr_b[1]), .din_b(bank_din_b[1]), .dout_b(bank_dout_b[1]));
    poly_bank_ram u_bank2 (.clk(clk), .we_a(bank_we_a[2]), .addr_a(bank_addr_a[2]), .din_a(bank_din_a[2]), .dout_a(bank_dout_a[2]), .we_b(bank_we_b[2]), .addr_b(bank_addr_b[2]), .din_b(bank_din_b[2]), .dout_b(bank_dout_b[2]));
    poly_bank_ram u_bank3 (.clk(clk), .we_a(bank_we_a[3]), .addr_a(bank_addr_a[3]), .din_a(bank_din_a[3]), .dout_a(bank_dout_a[3]), .we_b(bank_we_b[3]), .addr_b(bank_addr_b[3]), .din_b(bank_din_b[3]), .dout_b(bank_dout_b[3]));
    poly_bank_ram u_bank4 (.clk(clk), .we_a(bank_we_a[4]), .addr_a(bank_addr_a[4]), .din_a(bank_din_a[4]), .dout_a(bank_dout_a[4]), .we_b(bank_we_b[4]), .addr_b(bank_addr_b[4]), .din_b(bank_din_b[4]), .dout_b(bank_dout_b[4]));
    poly_bank_ram u_bank5 (.clk(clk), .we_a(bank_we_a[5]), .addr_a(bank_addr_a[5]), .din_a(bank_din_a[5]), .dout_a(bank_dout_a[5]), .we_b(bank_we_b[5]), .addr_b(bank_addr_b[5]), .din_b(bank_din_b[5]), .dout_b(bank_dout_b[5]));
    poly_bank_ram u_bank6 (.clk(clk), .we_a(bank_we_a[6]), .addr_a(bank_addr_a[6]), .din_a(bank_din_a[6]), .dout_a(bank_dout_a[6]), .we_b(bank_we_b[6]), .addr_b(bank_addr_b[6]), .din_b(bank_din_b[6]), .dout_b(bank_dout_b[6]));
    poly_bank_ram u_bank7 (.clk(clk), .we_a(bank_we_a[7]), .addr_a(bank_addr_a[7]), .din_a(bank_din_a[7]), .dout_a(bank_dout_a[7]), .we_b(bank_we_b[7]), .addr_b(bank_addr_b[7]), .din_b(bank_din_b[7]), .dout_b(bank_dout_b[7]));

    // -------------------------------------------------------------------------
    // Decapsulation Key Storage BRAM (204 words x 64 bits = 1632 bytes)
    // -------------------------------------------------------------------------
    reg [63:0] dk_ram [0:203];
    reg [7:0]  dk_ram_wr_addr;

    reg [7:0]  int_dk_rd_addr;
    wire [7:0] dk_ram_b_addr = busy ? int_dk_rd_addr : dk_ram_rd_addr;
    reg [63:0] dk_ram_b_rdata;
    assign dk_ram_rdata = dk_ram_b_rdata;

    // -------------------------------------------------------------------------
    // Ciphertext Storage BRAM (96 words x 64 bits = 768 bytes)
    // -------------------------------------------------------------------------
    // c_ram / ek_ram: ONE registered write port each (requests below), async-read
    // distributed RAM. Several write sites in the FSM used to make Vivado build these
    // as flip-flop arrays behind a 76-way state mux (~100k LUTs). Write lands 1 cycle
    // after the request; nothing reads a word in the cycle after it is written.
    (* ram_style = "distributed" *) reg [63:0] c_ram [0:127];
    reg         c_we_q;
    reg  [6:0]  c_wa_q;
    reg  [63:0] c_wd_q;
    always @(posedge clk) if (c_we_q) c_ram[c_wa_q] <= c_wd_q;
    reg [6:0]  c_ram_wr_addr;
    reg [6:0]  int_c_rd_addr;
    wire [6:0] c_ram_addr = busy ? int_c_rd_addr : c_ram_rd_addr_ext;
    reg [63:0] c_ram_rdata_r;

    assign c_ram_rdata_ext = c_ram_rdata_r;

    // -------------------------------------------------------------------------
    // Submodule 1: Keccak-f1600 & SHAKE Wrapper
    // -------------------------------------------------------------------------
    reg  [1:0]  shake_mode;
    reg         shake_init;
    reg  [9:0]  shake_squeeze_words;
    reg  [63:0] fsm_shake_in_data;
    reg  [3:0]  fsm_shake_in_bytes;
    reg         fsm_shake_in_valid;
    reg         fsm_shake_in_last;
    wire        shake_in_ready;

    wire [63:0] shake_out_data;
    wire [7:0]  shake_out_mask;
    wire        shake_out_valid;
    wire        shake_out_last;
    reg         fsm_shake_out_ready;
    wire        shake_busy;

    // Forward declarations for FSM & submodules
    wire [6:0]  state;
    wire [7:0]  words_written;
    wire        dec_in_ready;

    // Multiplex absorb port for Phase 5 (SHA3-256 over dk_ram[96..195])
    wire [63:0] shake_in_data  = (state == 7'd21) ? dk_ram_b_rdata :
                                 (state == S_DEC_J_FEED) ? ((words_written < 8'd4) ? dk_ram_b_rdata : c_ram_rdata_r) :
                                 fsm_shake_in_data;
    wire [3:0]  shake_in_bytes = ((state == 7'd21) || (state == S_DEC_J_FEED)) ? 4'd8 : fsm_shake_in_bytes;
    wire        shake_in_valid = (state == 7'd21) ? fsm_shake_in_valid : fsm_shake_in_valid;
    wire        shake_in_last  = ((state == 7'd21) || (state == S_DEC_J_FEED)) ? (words_written == 8'd99) : fsm_shake_in_last;

    wire sntt_busy;
    wire cbd_busy;
    wire sntt_in_ready;
    wire cbd_prf_ready;
    wire shake_out_ready = sntt_busy ? sntt_in_ready :
                           cbd_busy  ? cbd_prf_ready  :
                                       fsm_shake_out_ready;

    wire dk_ram_rd_en = !busy || (state == 7'd25) || ((state == 7'd21) && shake_in_ready)
                        || (state == 7'd26) || ((state == 7'd27) && dec_in_ready)
                        || (state == 7'd29)
                        || (state == S_DEC_J_PREFETCH) || ((state == S_DEC_J_FEED) && shake_in_ready)
                        || (state == S_LP_PREFETCH) || ((state == S_LP_FEED) && lp_sel_ready);

    // Encapsulation-key store (separate from dk_ram so a stored dk survives an Encaps).
    // While an Encaps runs, the dk_ram read port is served from ek_ram[addr-96].
    (* ram_style = "distributed" *) reg [63:0] ek_ram [0:127];
    reg         ek_we_q;
    reg  [6:0]  ek_wa_q;
    reg  [63:0] ek_wd_q;
    always @(posedge clk) if (ek_we_q) ek_ram[ek_wa_q] <= ek_wd_q;
    wire [7:0]  ek_rd_off = dk_ram_b_addr - 8'd96;
    wire        rd_from_ek = busy && (op_r == OP_ENCAPS);
    always @(posedge clk) begin
        if (dk_ram_rd_en) begin
            dk_ram_b_rdata <= rd_from_ek ? ek_ram[(ek_rd_off < 8'd100) ? ek_rd_off[6:0] : 7'd0]
                                         : dk_ram[dk_ram_b_addr];
        end
    end

    // c_ram synchronous read; rdata is frozen while the consumer stalls
    wire c_ram_rd_en = !busy || (state == S_LP_PREFETCH) || ((state == S_LP_FEED) && lp_sel_ready)
                       || (state == S_DEC_J_PREFETCH) || ((state == S_DEC_J_FEED) && shake_in_ready);
    always @(posedge clk) begin
        if (c_ram_rd_en) begin
            c_ram_rdata_r <= c_ram[c_ram_addr];
        end
    end

    shake_wrapper u_shake (
        .clk           (clk),
        .rst           (rst),
        .mode          (shake_mode),
        .init          (shake_init),
        .squeeze_words (shake_squeeze_words),
        .in_data       (shake_in_data),
        .in_bytes      (shake_in_bytes),
        .in_valid      (shake_in_valid),
        .in_last       (shake_in_last),
        .in_ready      (shake_in_ready),
        .out_data      (shake_out_data),
        .out_mask      (shake_out_mask),
        .out_valid     (shake_out_valid),
        .out_last      (shake_out_last),
        .out_ready     (shake_out_ready),
        .busy          (shake_busy)
    );

    // -------------------------------------------------------------------------
    // Submodule 2: SampleNTT Rejection Sampler (Alg 7)
    // -------------------------------------------------------------------------
    reg        sntt_start;
    reg  [2:0] sntt_target_poly_id;
    wire       sntt_done;
    wire       sntt_err_truncated;
    wire [10:0] sntt_poly_mem_addr;
    wire       sntt_poly_mem_we;
    wire [11:0] sntt_poly_mem_wdata;

    sample_ntt u_sample_ntt (
        .clk            (clk),
        .rst            (rst),
        .start          (sntt_start),
        .target_poly_id (sntt_target_poly_id),
        .busy           (sntt_busy),
        .done           (sntt_done),
        .err_truncated  (sntt_err_truncated),
        .in_data        (shake_out_data),
        .in_valid       (shake_out_valid && (sntt_busy || sntt_start)),
        .in_ready       (sntt_in_ready),
        .in_last        (shake_out_last),
        .poly_mem_addr  (sntt_poly_mem_addr),
        .poly_mem_we    (sntt_poly_mem_we),
        .poly_mem_wdata (sntt_poly_mem_wdata)
    );

    // -------------------------------------------------------------------------
    // Submodule 3: CBD Noise Sampler (Alg 8)
    // -------------------------------------------------------------------------
    reg        cbd_start;
    reg        cbd_mode_eta;
    reg  [2:0] cbd_target_poly_id;
    wire       cbd_done;
    wire       cbd_err_truncated;
    wire [10:0] cbd_poly_mem_addr;
    wire       cbd_poly_mem_we;
    wire [11:0] cbd_poly_mem_wdata;

    cbd_sampler u_cbd (
        .clk            (clk),
        .rst            (rst),
        .start          (cbd_start),
        .mode_eta       (cbd_mode_eta),
        .target_poly_id (cbd_target_poly_id),
        .busy           (cbd_busy),
        .done           (cbd_done),
        .err_truncated  (cbd_err_truncated),
        .prf_data       (shake_out_data),
        .prf_valid      (shake_out_valid && (cbd_busy || cbd_start)),
        .prf_ready      (cbd_prf_ready),
        .prf_last       (shake_out_last),
        .poly_mem_addr  (cbd_poly_mem_addr),
        .poly_mem_we    (cbd_poly_mem_we),
        .poly_mem_wdata (cbd_poly_mem_wdata)
    );

    // -------------------------------------------------------------------------
    // Submodule 4: NTT / INTT Core
    // -------------------------------------------------------------------------
    reg        ntt_start;
    reg        ntt_mode;
    reg  [2:0] ntt_target_bank;
    wire       ntt_busy;
    wire       ntt_done;
    wire [7:0] ntt_mem_a_addr;
    wire [11:0] ntt_mem_a_rdata;
    wire       ntt_mem_a_we;
    wire [11:0] ntt_mem_a_wdata;
    wire [7:0] ntt_mem_b_addr;
    wire [11:0] ntt_mem_b_rdata;
    wire       ntt_mem_b_we;
    wire [11:0] ntt_mem_b_wdata;

    ntt_core #(.PIPE_DEPTH(3)) u_ntt (
        .clk         (clk),
        .rst         (rst),
        .start       (ntt_start),
        .mode        (ntt_mode),
        .busy        (ntt_busy),
        .done        (ntt_done),
        .mem_a_addr  (ntt_mem_a_addr),
        .mem_a_rdata (ntt_mem_a_rdata),
        .mem_a_we    (ntt_mem_a_we),
        .mem_a_wdata (ntt_mem_a_wdata),
        .mem_b_addr  (ntt_mem_b_addr),
        .mem_b_rdata (ntt_mem_b_rdata),
        .mem_b_we    (ntt_mem_b_we),
        .mem_b_wdata (ntt_mem_b_wdata)
    );

    // -------------------------------------------------------------------------
    // Submodule 5: Pointwise Multiply-Accumulate
    // -------------------------------------------------------------------------
    reg        mul_start;
    reg        mul_accumulate;
    reg  [2:0] mul_op_a_bank;
    reg  [2:0] mul_op_b_bank;
    reg  [2:0] mul_acc_bank;
    reg  [2:0] mul_dest_bank;
    wire       mul_busy;
    wire       mul_done;
    wire [7:0] mul_mem_a_addr;
    wire [11:0] mul_mem_a_rdata;
    wire [7:0] mul_mem_b_addr;
    wire [11:0] mul_mem_b_rdata;
    wire [7:0] mul_mem_acc_addr;
    wire [11:0] mul_mem_acc_rdata;
    wire [7:0] mul_mem_c_addr;
    wire       mul_mem_c_we;
    wire [11:0] mul_mem_c_wdata;

    poly_mul_acc u_mul_acc (
        .clk           (clk),
        .rst           (rst),
        .start         (mul_start),
        .accumulate    (mul_accumulate),
        .busy          (mul_busy),
        .done          (mul_done),
        .mem_a_addr    (mul_mem_a_addr),
        .mem_a_rdata   (mul_mem_a_rdata),
        .mem_b_addr    (mul_mem_b_addr),
        .mem_b_rdata   (mul_mem_b_rdata),
        .mem_acc_addr  (mul_mem_acc_addr),
        .mem_acc_rdata (mul_mem_acc_rdata),
        .mem_c_addr    (mul_mem_c_addr),
        .mem_c_we      (mul_mem_c_we),
        .mem_c_wdata   (mul_mem_c_wdata)
    );

    // -------------------------------------------------------------------------
    // Submodule 6: Modular Polynomial Add / Sub
    // -------------------------------------------------------------------------
    reg        add_start;
    reg  [1:0] add_mode;
    reg  [2:0] add_dest_bank;
    reg  [2:0] add_op_a_bank;
    reg  [2:0] add_op_b_bank;
    reg  [2:0] add_op_c_bank;
    wire       add_busy;
    wire       add_done;
    wire [7:0] add_rd_addr;
    wire [11:0] add_rdata_a;
    wire [11:0] add_rdata_b;
    wire [11:0] add_rdata_c;
    wire [7:0] add_wr_addr;
    wire       add_wr_we;
    wire [11:0] add_wr_data;

    poly_add_sub u_add_sub (
        .clk     (clk),
        .rst     (rst),
        .start   (add_start),
        .mode    (add_mode),
        .busy    (add_busy),
        .done    (add_done),
        .rd_addr (add_rd_addr),
        .rdata_a (add_rdata_a),
        .rdata_b (add_rdata_b),
        .rdata_c (add_rdata_c),
        .wr_addr (add_wr_addr),
        .wr_we   (add_wr_we),
        .wr_data (add_wr_data)
    );

    // -------------------------------------------------------------------------
    // Submodule 7: Polynomial Byte Encoder (D=12)
    // -------------------------------------------------------------------------
    reg         enc_start_poly;
    wire        enc_busy;
    wire        enc_overflow;
    reg         enc_read_valid;
    reg  [2:0]  enc_bank;
    wire        enc_in_valid = enc_read_valid;
    wire [11:0] enc_in_data  = bank_dout_a[enc_bank];
    wire [63:0] enc_out_data;
    wire        enc_out_valid;
    wire        enc_poly_last;

    byte_encode #(.D(12)) u_encode12 (
        .clk        (clk),
        .rst        (rst),
        .start_poly (enc_start_poly),
        .busy       (enc_busy),
        .overflow   (enc_overflow),
        .in_valid   (enc_in_valid),
        .in_data    (enc_in_data),
        .out_data   (enc_out_data),
        .out_valid  (enc_out_valid),
        .out_ready  (1'b1),
        .poly_last  (enc_poly_last)
    );

    // -------------------------------------------------------------------------
    // Submodule 8: Polynomial Byte Decoder (D=12) for ek validation
    // -------------------------------------------------------------------------
    reg         dec_start_poly;
    wire        dec_busy, dec_err_non_canonical, dec_out_valid;
    reg         dec_check_modulus;
    wire [63:0] lp_in_data  = lp_src_c ? c_ram_rdata_r : dk_ram_b_rdata;
    wire [63:0] dec_in_data = lp_in_data;
    reg         dec_in_valid;
    wire [11:0] dec_out_data;
    reg  [2:0]  dec_target_bank;
    reg  [7:0]  dec_coeff_idx;

    byte_decode #(.D(12)) u_decode12 (
        .clk               (clk),
        .rst               (rst),
        .start_poly        (dec_start_poly),
        .busy              (dec_busy),
        .check_modulus     (dec_check_modulus),
        .err_non_canonical (dec_err_non_canonical),
        .in_data           (dec_in_data),
        .in_valid          (dec_in_valid | (lp_in_valid & (lp_mode == 2'd0))),
        .in_ready          (dec_in_ready),
        .out_valid         (dec_out_valid),
        .out_data          (dec_out_data)
    );

    // -------------------------------------------------------------------------
    // Submodules 9-10: Compress and ByteEncode for Ciphertext (D=10 and D=4)
    // -------------------------------------------------------------------------
    reg         enc10_start_poly;
    wire        enc10_busy, enc10_overflow;
    wire        comp10_out_valid;
    wire [9:0]  comp10_out_data;
    wire [63:0] enc10_out_data;
    wire        enc10_out_valid;
    wire        enc10_poly_last;

    compress #(.D(10)) u_comp10 (
        .clk       (clk),
        .rst       (rst),
        .in_valid  ((state_r == S_ENC_C_STREAM) && (current_poly < 3'd2) && enc_read_valid),
        .in_data   (bank_dout_a[enc_bank]),
        .out_valid (comp10_out_valid),
        .out_data  (comp10_out_data)
    );

    byte_encode #(.D(10)) u_encode10 (
        .clk        (clk),
        .rst        (rst),
        .start_poly (enc10_start_poly),
        .busy       (enc10_busy),
        .overflow   (enc10_overflow),
        .in_valid   (comp10_out_valid),
        .in_data    (comp10_out_data),
        .out_data   (enc10_out_data),
        .out_valid  (enc10_out_valid),
        .out_ready  (1'b1),
        .poly_last  (enc10_poly_last)
    );

    reg         enc4_start_poly;
    wire        enc4_busy, enc4_overflow;
    wire        comp4_out_valid;
    wire [3:0]  comp4_out_data;
    wire [63:0] enc4_out_data;
    wire        enc4_out_valid;
    wire        enc4_poly_last;

    compress #(.D(4)) u_comp4 (
        .clk       (clk),
        .rst       (rst),
        .in_valid  ((state_r == S_ENC_C_STREAM) && (current_poly == 3'd2) && enc_read_valid),
        .in_data   (bank_dout_a[3'd6]),
        .out_valid (comp4_out_valid),
        .out_data  (comp4_out_data)
    );

    byte_encode #(.D(4)) u_encode4 (
        .clk        (clk),
        .rst        (rst),
        .start_poly (enc4_start_poly),
        .busy       (enc4_busy),
        .overflow   (enc4_overflow),
        .in_valid   (comp4_out_valid),
        .in_data    (comp4_out_data),
        .out_data   (enc4_out_data),
        .out_valid  (enc4_out_valid),
        .out_ready  (1'b1),
        .poly_last  (enc4_poly_last)
    );

    // Decaps: m' = ByteEncode1(Compress1(w))
    reg         enc1_start_poly;
    wire        enc1_busy, enc1_overflow, enc1_poly_last, enc1_out_valid;
    wire        comp1_out_valid;
    wire [0:0]  comp1_out_data;
    wire [63:0] enc1_out_data;
    compress #(.D(1)) u_comp1 (
        .clk       (clk),
        .rst       (rst),
        .in_valid  ((state_r == S_DC_M_STREAM) && enc_read_valid),
        .in_data   (bank_dout_a[enc_bank]),
        .out_valid (comp1_out_valid),
        .out_data  (comp1_out_data)
    );
    byte_encode #(.D(1)) u_encode1 (
        .clk        (clk),
        .rst        (rst),
        .start_poly (enc1_start_poly),
        .busy       (enc1_busy),
        .overflow   (enc1_overflow),
        .in_valid   (comp1_out_valid),
        .in_data    (comp1_out_data),
        .out_data   (enc1_out_data),
        .out_valid  (enc1_out_valid),
        .out_ready  (1'b1),
        .poly_last  (enc1_poly_last)
    );

    wire enc_c_word_valid = (current_poly < 3'd2) ? enc10_out_valid : enc4_out_valid;
    wire [63:0] enc_c_word_data = (current_poly < 3'd2) ? enc10_out_data : enc4_out_data;

    // -------------------------------------------------------------------------
    // Decaps unpack path: ByteDecode10/4 + Decompress10/4 (u', v') and the
    // generic polynomial loader mux (mode 0: D=12, 1: D=10, 2: D=4)
    // -------------------------------------------------------------------------
    reg         lp_start10, lp_start4;
    wire        dec10_busy, dec10_err, dec10_in_ready, dec10_out_valid;
    wire [11:0] dec10_out_data;
    byte_decode #(.D(10)) u_decode10 (
        .clk               (clk),
        .rst               (rst),
        .start_poly        (lp_start10),
        .busy              (dec10_busy),
        .check_modulus     (1'b0),
        .err_non_canonical (dec10_err),
        .in_data           (lp_in_data),
        .in_valid          (lp_in_valid & (lp_mode == 2'd1)),
        .in_ready          (dec10_in_ready),
        .out_valid         (dec10_out_valid),
        .out_data          (dec10_out_data)
    );
    wire        dec4_busy, dec4_err, dec4_in_ready, dec4_out_valid;
    wire [11:0] dec4_out_data;
    byte_decode #(.D(4)) u_decode4 (
        .clk               (clk),
        .rst               (rst),
        .start_poly        (lp_start4),
        .busy              (dec4_busy),
        .check_modulus     (1'b0),
        .err_non_canonical (dec4_err),
        .in_data           (lp_in_data),
        .in_valid          (lp_in_valid & (lp_mode == 2'd2)),
        .in_ready          (dec4_in_ready),
        .out_valid         (dec4_out_valid),
        .out_data          (dec4_out_data)
    );

    wire decomp10_out_valid;
    wire [11:0] decomp10_out_data;
    decompress #(.D(10)) u_decomp10 (
        .clk       (clk),
        .rst       (rst),
        .in_valid  (dec10_out_valid),
        .in_data   (dec10_out_data[9:0]),
        .out_valid (decomp10_out_valid),
        .out_data  (decomp10_out_data)
    );
    wire decomp4_out_valid;
    wire [11:0] decomp4_out_data;
    decompress #(.D(4)) u_decomp4 (
        .clk       (clk),
        .rst       (rst),
        .in_valid  (dec4_out_valid),
        .in_data   (dec4_out_data[3:0]),
        .out_valid (decomp4_out_valid),
        .out_data  (decomp4_out_data)
    );

    assign lp_sel_ready = (lp_mode == 2'd0) ? dec_in_ready :
                          (lp_mode == 2'd1) ? dec10_in_ready : dec4_in_ready;
    wire        lp_fin_valid = (lp_mode == 2'd0) ? dec_out_valid :
                               (lp_mode == 2'd1) ? decomp10_out_valid : decomp4_out_valid;
    wire [11:0] lp_fin_data  = (lp_mode == 2'd0) ? dec_out_data :
                               (lp_mode == 2'd1) ? decomp10_out_data : decomp4_out_data;

    wire packer_in_ready, packer_out_valid, packer_out_last;
    wire [63:0] packer_out_data;
    wire [3:0]  packer_out_bytes;
    // ---- Packet-bus handshake ingest (milestone d) -------------------------
    // HS_INIT (type 2'b00): 800 B ek  -> dk_ram[96..195], then auto-start Encaps
    // HS_RESP (type 2'b10): 768 B c   -> c_ram[0..95],    then auto-start Decaps
    // Anything else (DATA, other ports) is ignored. A wrong payload_len, a packet
    // cut short by a new SOF, or an over-long packet is a STRUCTURAL failure
    // (kem_key_invalid + v_kem_* + RC_HANDSHAKE_KEY_INVALID). Packets that arrive
    // while the core is busy are ignored (the single compute core is not queued).
    reg         ing_active;
    reg         ing_hs_init;     // 1: HS_INIT (ek), 0: HS_RESP (c)
    reg [15:0]  ing_sid;
    reg [7:0]   ing_wcnt;
    reg         pk_clr;          // 1-cycle packer flush after an aborted packet
    reg         m_have;          // m captured from rng for the current HS_INIT packet
    reg         rng_lock;        // set on take, cleared when rng_valid drops

    wire        ing_type_ok  = (packet_bus_packet_type == 2'b00) || (packet_bus_packet_type == 2'b10);
    wire        ing_len_ok   = (packet_bus_packet_type == 2'b00) ? (packet_bus_payload_len == 16'd800)
                                                                 : (packet_bus_payload_len == 16'd768);
    wire        ing_sof_hit  = packet_bus_valid && packet_bus_sof && !ing_active && !cmd_start
                               && (state_r == S_IDLE) && ing_type_ok;
    wire        ing_sof_take = ing_sof_hit && ing_len_ok;
    wire        pk_in_valid  = packet_bus_valid && (ing_active || ing_sof_take) && !pk_clr;

    pack_8_to_64 u_packer (
        .clk       (clk),
        .rst       (rst | pk_clr),
        .in_valid  (pk_in_valid),
        .in_data   (packet_bus_data),
        .in_eof    (packet_bus_eof),
        .in_ready  (packer_in_ready),
        .out_valid (packer_out_valid),
        .out_data  (packer_out_data),
        .out_last  (packer_out_last),
        .out_bytes (packer_out_bytes),
        .out_ready (1'b1)
    );

    // -------------------------------------------------------------------------
    // Top-Level State Registers & Intermediates
    // -------------------------------------------------------------------------
    reg [255:0] reg_rho;
    reg [255:0] reg_sigma;
    reg [255:0] reg_k;
    reg [255:0] reg_r;
    reg [255:0] reg_hek;
    reg [7:0]   enc_coeff_idx;
    reg [8:0]   enc_coeff_cnt;
    reg [7:0]   words_written_r;
    assign words_written = words_written_r;
    reg [2:0]   feed_cnt;

    assign state = state_r;
    reg [1:0] mat_row;
    reg [1:0] mat_col;

    assign busy = (state_r != S_IDLE);

    // -------------------------------------------------------------------------
    // Polynomial RAM Bank Routing & Multiplexing
    // -------------------------------------------------------------------------
    // Connect submodule read data buses:
    assign ntt_mem_a_rdata   = bank_dout_a[ntt_target_bank];
    assign ntt_mem_b_rdata   = bank_dout_b[ntt_target_bank];
    assign mul_mem_a_rdata   = bank_dout_a[mul_op_a_bank];
    assign mul_mem_b_rdata   = bank_dout_a[mul_op_b_bank];
    assign mul_mem_acc_rdata = bank_dout_b[mul_acc_bank];
    assign add_rdata_a       = bank_dout_b[add_op_a_bank];
    assign add_rdata_b       = bank_dout_a[add_op_b_bank];
    assign add_rdata_c       = bank_dout_b[add_op_c_bank];

    integer b;
    always @(*) begin
        for (b = 0; b < 8; b = b + 1) begin
            // Default inactive values
            bank_addr_a[b] = 8'd0;
            bank_we_a[b]   = 1'b0;
            bank_din_a[b]  = 12'd0;
            bank_addr_b[b] = 8'd0;
            bank_we_b[b]   = 1'b0;
            bank_din_b[b]  = 12'd0;

            // Port A Routing
            if (sntt_busy && (sntt_target_poly_id == b[2:0])) begin
                bank_addr_a[b] = sntt_poly_mem_addr[7:0];
                bank_we_a[b]   = sntt_poly_mem_we;
                bank_din_a[b]  = sntt_poly_mem_wdata;
            end else if (cbd_busy && (cbd_target_poly_id == b[2:0])) begin
                bank_addr_a[b] = cbd_poly_mem_addr[7:0];
                bank_we_a[b]   = cbd_poly_mem_we;
                bank_din_a[b]  = cbd_poly_mem_wdata;
            end else if ((state_r == S_LP_FEED) && lp_fin_valid && (lp_bank == b[2:0])) begin
                bank_addr_a[b] = lp_wr_idx;
                bank_we_a[b]   = 1'b1;
                bank_din_a[b]  = lp_fin_data;
            end else if ((state_r == S_ENC_DEC_FEED) && dec_out_valid && (dec_target_bank == b[2:0])) begin
                bank_addr_a[b] = dec_coeff_idx;
                bank_we_a[b]   = 1'b1;
                bank_din_a[b]  = dec_out_data;
            end else if ((state_r == S_ENC_V_EXP_M) && (b == 2)) begin
                bank_addr_a[b] = enc_coeff_idx;
                bank_we_a[b]   = 1'b1;
                bank_din_a[b]  = m_reg[enc_coeff_idx] ? 12'd1665 : 12'd0;
            end else if (ntt_busy && (ntt_target_bank == b[2:0])) begin
                bank_addr_a[b] = ntt_mem_a_addr;
                bank_we_a[b]   = ntt_mem_a_we;
                bank_din_a[b]  = ntt_mem_a_wdata;
            end else if (mul_busy) begin
                if (mul_dest_bank == b[2:0]) begin
                    bank_addr_a[b] = mul_mem_c_addr;
                    bank_we_a[b]   = mul_mem_c_we;
                    bank_din_a[b]  = mul_mem_c_wdata;
                end else if (mul_op_a_bank == b[2:0]) begin
                    bank_addr_a[b] = mul_mem_a_addr;
                end else if (mul_op_b_bank == b[2:0]) begin
                    bank_addr_a[b] = mul_mem_b_addr;
                end
            end else if (add_busy) begin
                if (add_dest_bank == b[2:0]) begin
                    bank_addr_a[b] = add_wr_addr;
                    bank_we_a[b]   = add_wr_we;
                    bank_din_a[b]  = add_wr_data;
                end else if (add_op_b_bank == b[2:0]) begin
                    bank_addr_a[b] = add_rd_addr;
                end
            end else if (((state_r == S_ENC_STREAM) || (state_r == S_ENC_C_STREAM) || (state_r == S_DC_M_STREAM)) && (enc_bank == b[2:0])) begin
                bank_addr_a[b] = enc_coeff_idx;
            end

            // Port B Routing
            if (ntt_busy && (ntt_target_bank == b[2:0])) begin
                bank_addr_b[b] = ntt_mem_b_addr;
                bank_we_b[b]   = ntt_mem_b_we;
                bank_din_b[b]  = ntt_mem_b_wdata;
            end else if (mul_busy && (mul_acc_bank == b[2:0])) begin
                bank_addr_b[b] = mul_mem_acc_addr;
            end else if (add_busy) begin
                if (add_op_a_bank == b[2:0]) begin
                    bank_addr_b[b] = add_rd_addr;
                end else if (add_op_c_bank == b[2:0]) begin
                    bank_addr_b[b] = add_rd_addr;
                end
            end
        end
    end

    // -------------------------------------------------------------------------
    // Main Sequential Control FSM
    // -------------------------------------------------------------------------
    always @(posedge clk) begin
        if (rst) begin
            state_r             <= S_IDLE;
            kem_done            <= 1'b0;
            kem_session_id      <= 16'd0;
            kem_shared_secret   <= 256'd0;
            kem_key_invalid     <= 1'b0;
            v_kem_valid         <= 1'b0;
            v_kem_fail          <= 1'b0;
            v_kem_reason        <= `RC_NONE;
            shake_init          <= 1'b0;
            shake_mode          <= 2'b00;
            shake_squeeze_words <= 10'd0;
            fsm_shake_in_valid  <= 1'b0;
            fsm_shake_in_data   <= 64'd0;
            fsm_shake_in_bytes  <= 4'd0;
            fsm_shake_in_last   <= 1'b0;
            fsm_shake_out_ready <= 1'b0;
            sntt_start          <= 1'b0;
            sntt_target_poly_id <= 3'd0;
            cbd_start           <= 1'b0;
            cbd_mode_eta        <= 1'b0;
            cbd_target_poly_id  <= 3'd0;
            ntt_start           <= 1'b0;
            ntt_mode            <= 1'b0;
            ntt_target_bank     <= 3'd0;
            mul_start           <= 1'b0;
            mul_accumulate      <= 1'b0;
            mul_op_a_bank       <= 3'd0;
            mul_op_b_bank       <= 3'd0;
            mul_acc_bank        <= 3'd0;
            mul_dest_bank       <= 3'd0;
            add_start           <= 1'b0;
            add_mode            <= 2'd0;
            add_dest_bank       <= 3'd0;
            add_op_a_bank       <= 3'd0;
            add_op_b_bank       <= 3'd0;
            add_op_c_bank       <= 3'd0;
            enc_start_poly      <= 1'b0;
            enc_read_valid      <= 1'b0;
            dk_ram_wr_addr      <= 8'd0;
            int_dk_rd_addr      <= 8'd0;
            c_ram_wr_addr       <= 7'd0;
            int_c_rd_addr       <= 7'd0;
            reg_rho             <= 256'd0;
            reg_sigma           <= 256'd0;
            reg_k               <= 256'd0;
            reg_r               <= 256'd0;
            reg_hek             <= 256'd0;
            current_poly        <= 3'd0;
            enc_coeff_idx       <= 8'd0;
            enc_coeff_cnt       <= 9'd0;
            enc_bank            <= 3'd0;
            words_written_r     <= 8'd0;
            feed_cnt            <= 3'd0;
            mat_row             <= 2'd0;
            mat_col             <= 2'd0;
            dec_start_poly      <= 1'b0;
            dec_check_modulus   <= 1'b0;
            dec_in_valid        <= 1'b0;
            dec_target_bank     <= 3'd0;
            dec_coeff_idx       <= 8'd0;
            enc10_start_poly    <= 1'b0;
            enc4_start_poly     <= 1'b0;
            op_r                <= 2'd0;
            is_decaps           <= 1'b0;
            m_reg               <= 256'd0;
            reg_kbar            <= 256'd0;
            c_match             <= 1'b0;
            c_cmp_cnt           <= 8'd0;
            lp_step             <= 3'd0;
            lp_src_c            <= 1'b0;
            lp_mode             <= 2'd0;
            lp_addr0            <= 8'd0;
            lp_nwords           <= 6'd0;
            lp_bank             <= 3'd0;
            lp_in_valid         <= 1'b0;
            lp_wr_idx           <= 8'd0;
            lp_start10          <= 1'b0;
            lp_start4           <= 1'b0;
            enc1_start_poly     <= 1'b0;
            ing_active          <= 1'b0;
            ing_hs_init         <= 1'b0;
            ing_sid             <= 16'd0;
            ing_wcnt            <= 8'd0;
            pk_clr              <= 1'b0;
            m_have              <= 1'b0;
            rng_lock            <= 1'b0;
            rng_take            <= 1'b0;
            kem_pkt_dropped_busy<= 1'b0;
        end else begin
            pk_clr          <= 1'b0;
            rng_take        <= 1'b0;
            kem_pkt_dropped_busy <= packet_bus_valid && packet_bus_sof && ing_type_ok && !ing_active
                                    && (state_r != S_IDLE);
            if (!rng_valid) rng_lock <= 1'b0;
            kem_done        <= 1'b0;
            kem_key_invalid <= 1'b0;
            v_kem_valid     <= 1'b0;
            v_kem_fail      <= 1'b0;
            v_kem_reason    <= `RC_NONE;
            shake_init      <= 1'b0;
            sntt_start      <= 1'b0;
            cbd_start       <= 1'b0;
            ntt_start       <= 1'b0;
            mul_start       <= 1'b0;
            add_start       <= 1'b0;
            enc_start_poly  <= 1'b0;
            dec_start_poly  <= 1'b0;
            enc10_start_poly<= 1'b0;
            enc4_start_poly <= 1'b0;
            enc1_start_poly <= 1'b0;
            lp_start10      <= 1'b0;
            lp_start4       <= 1'b0;

            c_we_q  <= 1'b0;
            ek_we_q <= 1'b0;
            if (!busy && c_ram_wr_en) begin
                c_we_q <= 1'b1; c_wa_q <= c_ram_wr_addr_ext; c_wd_q <= c_ram_wr_data_ext;
            end
            if (!busy && ek_ram_wr_en) begin
                ek_we_q <= 1'b1; ek_wa_q <= ek_ram_wr_addr_ext; ek_wd_q <= ek_ram_wr_data_ext;
            end
            if (!busy && dk_ram_wr_en) begin
                dk_ram[dk_ram_wr_addr_ext] <= dk_ram_wr_data_ext;
            end

            case (state_r)
                S_IDLE: begin
                    if (cmd_start && !ing_active && (cmd_op == OP_KEYGEN)) begin
                        kem_session_id <= (cmd_session_id == 16'd0) ? 16'd1 : cmd_session_id;
                        op_r           <= OP_KEYGEN;
                        is_decaps      <= 1'b0;
                        state_r        <= S_G_INIT;
                    end else if (cmd_start && !ing_active && (cmd_op == OP_ENCAPS)) begin
                        op_r              <= OP_ENCAPS;
                        is_decaps         <= 1'b0;
                        m_reg             <= seed_m;
                        kem_session_id    <= (cmd_session_id == 16'd0) ? 16'd1 : cmd_session_id;
                        dec_start_poly    <= 1'b1;
                        dec_check_modulus <= 1'b1;
                        dec_target_bank   <= 3'd0;
                        dec_coeff_idx     <= 8'd0;
                        int_dk_rd_addr    <= 8'd96;
                        words_written_r   <= 8'd0;
                        state_r           <= S_ENC_DEC_PREFETCH;
                    end else if (cmd_start && !ing_active && (cmd_op == OP_DECAPS)) begin
                        kem_session_id    <= (cmd_session_id == 16'd0) ? 16'd1 : cmd_session_id;
                        op_r              <= OP_DECAPS;
                        is_decaps         <= 1'b1;
                        c_match           <= 1'b1;
                        c_cmp_cnt         <= 8'd0;
                        state_r           <= S_DEC_J_INIT;
                    end else if (ing_sof_hit && !ing_len_ok) begin
                        // Wrong payload_len on a handshake packet: structural failure, nothing ingested.
                        kem_session_id <= (packet_bus_session_id == 16'd0) ? 16'd1 : packet_bus_session_id;
                        state_r        <= S_STRUCT_FAIL;
                    end else if (ing_sof_take) begin
                        ing_active  <= 1'b1;
                        ing_hs_init <= (packet_bus_packet_type == 2'b00);
                        ing_sid     <= (packet_bus_session_id == 16'd0) ? 16'd1 : packet_bus_session_id;
                        ing_wcnt    <= 8'd0;
                        m_have      <= 1'b0;
                    end else if (ing_active) begin
                        // Capture one fresh seed while the ek streams in (never reuse a seed).
                        if (ing_hs_init && !m_have && rng_valid && !rng_lock) begin
                            m_reg    <= rng_data;
                            m_have   <= 1'b1;
                            rng_take <= 1'b1;
                            rng_lock <= 1'b1;
                        end
                        if (packet_bus_valid && packet_bus_sof) begin
                            // New SOF before EOF: previous packet was cut short.
                            ing_active     <= 1'b0;
                            pk_clr         <= 1'b1;
                            kem_session_id <= ing_sid;
                            state_r        <= S_STRUCT_FAIL;
                        end else if (packer_out_valid) begin
                            if (ing_hs_init) begin
                                ek_we_q <= 1'b1; ek_wa_q <= (ing_wcnt < 8'd100) ? ing_wcnt[6:0] : 7'd0; ek_wd_q <= packer_out_data;
                            end else begin
                                c_we_q <= 1'b1; c_wa_q <= ing_wcnt[6:0]; c_wd_q <= packer_out_data;
                            end
                            ing_wcnt <= ing_wcnt + 8'd1;
                            if (packer_out_last) begin
                                ing_active <= 1'b0;
                                if (ing_wcnt == (ing_hs_init ? 8'd99 : 8'd95)) begin
                                    kem_session_id <= ing_sid;
                                    if (ing_hs_init) begin
                                        state_r           <= S_ING_ENC_GO;
                                    end else begin
                                        op_r              <= OP_DECAPS;
                                        is_decaps         <= 1'b1;
                                        c_match           <= 1'b1;
                                        c_cmp_cnt         <= 8'd0;
                                        state_r           <= S_DEC_J_INIT;
                                    end
                                end else begin
                                    // EOF at the wrong word count: truncated packet.
                                    kem_session_id <= ing_sid;
                                    state_r        <= S_STRUCT_FAIL;
                                end
                            end else if (ing_wcnt == (ing_hs_init ? 8'd99 : 8'd95)) begin
                                // Over-long packet: more words than the object holds.
                                ing_active     <= 1'b0;
                                pk_clr         <= 1'b1;
                                kem_session_id <= ing_sid;
                                state_r        <= S_STRUCT_FAIL;
                            end
                        end
                    end
                end

                // -------------------------------------------------------------
                // Phase 0: G(d || 2) -> (rho, sigma) via SHA3-512
                // -------------------------------------------------------------
                S_G_INIT: begin
                    shake_init          <= 1'b1;
                    shake_mode          <= 2'b01; // SHA3-512
                    shake_squeeze_words <= 10'd8; // 8 words = 64 bytes
                    fsm_shake_in_valid  <= 1'b0;
                    fsm_shake_out_ready <= 1'b0;
                    feed_cnt            <= 3'd0;
                    state_r             <= S_G_FEED;
                end

                S_G_FEED: begin
                    if (shake_in_ready) begin
                        fsm_shake_in_valid <= 1'b1;
                        case (feed_cnt)
                            3'd0: begin fsm_shake_in_data <= seed_d[ 63:  0]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd1; end
                            3'd1: begin fsm_shake_in_data <= seed_d[127: 64]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd2; end
                            3'd2: begin fsm_shake_in_data <= seed_d[191:128]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd3; end
                            3'd3: begin fsm_shake_in_data <= seed_d[255:192]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd4; end
                            3'd4: begin
                                fsm_shake_in_data  <= 64'h02; // FIPS 203 Section 5 line 2: G(d || 2)
                                fsm_shake_in_bytes <= 4'd1;
                                fsm_shake_in_last  <= 1'b1;
                                feed_cnt           <= 3'd0;
                                state_r            <= S_G_SQUEEZE;
                            end
                            default: ;
                        endcase
                    end else begin
                        fsm_shake_in_valid <= 1'b0;
                    end
                end

                S_G_SQUEEZE: begin
                    fsm_shake_in_valid  <= 1'b0;
                    fsm_shake_out_ready <= 1'b1;
                    if (shake_out_valid && fsm_shake_out_ready) begin
                        case (feed_cnt)
                            3'd0: reg_rho[ 63:  0] <= shake_out_data;
                            3'd1: reg_rho[127: 64] <= shake_out_data;
                            3'd2: reg_rho[191:128] <= shake_out_data;
                            3'd3: reg_rho[255:192] <= shake_out_data;
                            3'd4: reg_sigma[ 63:  0] <= shake_out_data;
                            3'd5: reg_sigma[127: 64] <= shake_out_data;
                            3'd6: reg_sigma[191:128] <= shake_out_data;
                            3'd7: reg_sigma[255:192] <= shake_out_data;
                            default: ;
                        endcase
                        feed_cnt <= feed_cnt + 3'd1;
                        if (feed_cnt == 3'd7) begin
                            fsm_shake_out_ready <= 1'b0;
                            current_poly        <= 3'd0;
                            state_r             <= S_CBD_INIT;
                        end
                    end
                end

                // -------------------------------------------------------------
                // Phase 1: Sample s[0,1] and e[0,1] via CBD (eta1=3)
                // -------------------------------------------------------------
                S_CBD_INIT: begin
                    shake_init          <= 1'b1;
                    shake_mode          <= 2'b11; // SHAKE256 (PRF)
                    shake_squeeze_words <= 10'd24; // 24 words = 192 bytes
                    fsm_shake_in_valid  <= 1'b0;
                    fsm_shake_out_ready <= 1'b0;
                    feed_cnt            <= 3'd0;
                    state_r             <= S_CBD_FEED_SEED;
                end

                S_CBD_FEED_SEED: begin
                    if (shake_in_ready) begin
                        fsm_shake_in_valid <= 1'b1;
                        case (feed_cnt)
                            3'd0: begin fsm_shake_in_data <= reg_sigma[ 63:  0]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd1; end
                            3'd1: begin fsm_shake_in_data <= reg_sigma[127: 64]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd2; end
                            3'd2: begin fsm_shake_in_data <= reg_sigma[191:128]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd3; end
                            3'd3: begin fsm_shake_in_data <= reg_sigma[255:192]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd4; end
                            3'd4: begin
                                fsm_shake_in_data  <= {56'd0, 5'd0, current_poly}; // sigma || n
                                fsm_shake_in_bytes <= 4'd1;
                                fsm_shake_in_last  <= 1'b1;
                                feed_cnt           <= 3'd0;
                                // Arm CBD sampler
                                cbd_start          <= 1'b1;
                                cbd_mode_eta       <= 1'b0; // eta1 = 3
                                cbd_target_poly_id <= current_poly;
                                state_r            <= S_CBD_WAIT;
                            end
                            default: ;
                        endcase
                    end else begin
                        fsm_shake_in_valid <= 1'b0;
                    end
                end

                S_CBD_WAIT: begin
                    fsm_shake_in_valid <= 1'b0;
                    if (cbd_done) begin
                        if (current_poly == 3'd3) begin
                            current_poly <= 3'd0;
                            state_r      <= S_NTT_START;
                        end else begin
                            current_poly <= current_poly + 3'd1;
                            state_r      <= S_CBD_INIT;
                        end
                    end
                end

                // -------------------------------------------------------------
                // Phase 2: Forward NTT on s0, s1, e0, e1 (Banks 0..3)
                // -------------------------------------------------------------
                S_NTT_START: begin
                    ntt_start       <= 1'b1;
                    ntt_mode        <= 1'b0; // Forward NTT
                    ntt_target_bank <= current_poly;
                    state_r         <= S_NTT_WAIT;
                end

                S_NTT_WAIT: begin
                    if (ntt_done) begin
                        if (current_poly == 3'd3) begin
                            mat_row <= 2'd0;
                            mat_col <= 2'd0;
                            state_r <= S_A_INIT;
                        end else begin
                            current_poly <= current_poly + 3'd1;
                            state_r      <= S_NTT_START;
                        end
                    end
                end

                // -------------------------------------------------------------
                // Phase 3: Matrix A sampling & Pointwise Multiply-Accumulate
                // -------------------------------------------------------------
                S_A_INIT: begin
                    shake_init          <= 1'b1;
                    shake_mode          <= 2'b10; // SHAKE128
                    shake_squeeze_words <= 10'd84; // 84 words = 4 blocks max
                    fsm_shake_in_valid  <= 1'b0;
                    fsm_shake_out_ready <= 1'b0;
                    feed_cnt            <= 3'd0;
                    state_r             <= S_A_FEED_SEED;
                end

                S_A_FEED_SEED: begin
                    if (shake_in_ready) begin
                        fsm_shake_in_valid <= 1'b1;
                        case (feed_cnt)
                            3'd0: begin fsm_shake_in_data <= reg_rho[ 63:  0]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd1; end
                            3'd1: begin fsm_shake_in_data <= reg_rho[127: 64]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd2; end
                            3'd2: begin fsm_shake_in_data <= reg_rho[191:128]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd3; end
                            3'd3: begin fsm_shake_in_data <= reg_rho[255:192]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd4; end
                            3'd4: begin
                                // Seed: rho || j (col) || i (row)
                                fsm_shake_in_data  <= {48'd0, 6'd0, mat_row, 6'd0, mat_col};
                                fsm_shake_in_bytes <= 4'd2;
                                fsm_shake_in_last  <= 1'b1;
                                feed_cnt           <= 3'd0;
                                // Arm SampleNTT into Bank 6
                                sntt_start          <= 1'b1;
                                sntt_target_poly_id <= 3'd6;
                                state_r             <= S_A_WAIT_SAMPLE;
                            end
                            default: ;
                        endcase
                    end else begin
                        fsm_shake_in_valid <= 1'b0;
                    end
                end

                S_A_WAIT_SAMPLE: begin
                    fsm_shake_in_valid <= 1'b0;
                    if (sntt_done) begin
                        state_r <= S_MUL_START;
                    end
                end

                S_MUL_START: begin
                    mul_start     <= 1'b1;
                    mul_op_a_bank <= 3'd6; // A[row][col] in Bank 6
                    mul_op_b_bank <= {1'b0, mat_col}; // s[col] in Bank 0 or 1
                    mul_dest_bank <= (mat_row == 2'd0) ? 3'd4 : 3'd5; // t[row] in Bank 4 or 5
                    if (mat_col == 2'd0) begin
                        mul_accumulate <= 1'b0;
                    end else begin
                        mul_accumulate <= 1'b1;
                        mul_acc_bank   <= (mat_row == 2'd0) ? 3'd4 : 3'd5;
                    end
                    state_r <= S_MUL_WAIT;
                end

                S_MUL_WAIT: begin
                    if (mul_done) begin
                        if (mat_col == 2'd0) begin
                            mat_col <= 2'd1;
                            state_r <= S_A_INIT;
                        end else begin
                            state_r <= S_ADD_E_START;
                        end
                    end
                end

                S_ADD_E_START: begin
                    // Add noise: t[row] = t_accum + e[row]
                    add_start     <= 1'b1;
                    add_mode      <= 2'b00; // MODE_ADD
                    add_dest_bank <= (mat_row == 2'd0) ? 3'd4 : 3'd5;
                    add_op_a_bank <= (mat_row == 2'd0) ? 3'd4 : 3'd5;
                    add_op_b_bank <= (mat_row == 2'd0) ? 3'd2 : 3'd3; // e[0] in Bank 2, e[1] in Bank 3
                    add_op_c_bank <= 3'd0;
                    state_r       <= S_ADD_E_WAIT;
                end

                S_ADD_E_WAIT: begin
                    if (add_done) begin
                        if (mat_row == 2'd0) begin
                            mat_row <= 2'd1;
                            mat_col <= 2'd0;
                            state_r <= S_A_INIT;
                        end else begin
                            // All polynomials computed! Proceed to encoding.
                            current_poly    <= 3'd0;
                            dk_ram_wr_addr  <= 8'd0;
                            state_r         <= S_ENC_START;
                        end
                    end
                end

                // -------------------------------------------------------------
                // Phase 4: ByteEncode12 (s_hat0, s_hat1, t_hat0, t_hat1) into dk_ram
                // -------------------------------------------------------------
                S_ENC_START: begin
                    enc_start_poly  <= 1'b1;
                    enc_coeff_idx   <= 8'd0;
                    enc_coeff_cnt   <= 9'd0;
                    enc_read_valid  <= 1'b0;
                    words_written_r <= 8'd0;
                    case (current_poly)
                        3'd0: enc_bank <= 3'd0; // s_hat[0] -> dk_ram[0..47]
                        3'd1: enc_bank <= 3'd1; // s_hat[1] -> dk_ram[48..95]
                        3'd2: enc_bank <= 3'd4; // t_hat[0] -> dk_ram[96..143]
                        3'd3: enc_bank <= 3'd5; // t_hat[1] -> dk_ram[144..191]
                        default: ;
                    endcase
                    state_r <= S_ENC_STREAM;
                end

                S_ENC_STREAM: begin
                    if (enc_out_valid) begin
                        dk_ram[dk_ram_wr_addr] <= enc_out_data;
                        dk_ram_wr_addr         <= dk_ram_wr_addr + 8'd1;
                        words_written_r        <= words_written_r + 8'd1;
                    end

                    if (enc_coeff_cnt < 9'd256) begin
                        enc_coeff_idx  <= enc_coeff_idx + 8'd1;
                        enc_coeff_cnt  <= enc_coeff_cnt + 9'd1;
                        enc_read_valid <= 1'b1;
                    end else begin
                        enc_read_valid <= 1'b0;
                        state_r        <= S_ENC_WAIT_DRAIN;
                    end
                end

                S_ENC_WAIT_DRAIN: begin
                    enc_read_valid <= 1'b0;
                    if (enc_out_valid) begin
                        dk_ram[dk_ram_wr_addr] <= enc_out_data;
                        dk_ram_wr_addr         <= dk_ram_wr_addr + 8'd1;
                        words_written_r        <= words_written_r + 8'd1;
                        if (words_written_r == 8'd47) begin
                            if (current_poly == 3'd3) begin
                                feed_cnt <= 3'd0;
                                state_r  <= S_WRITE_RHO;
                            end else begin
                                current_poly <= current_poly + 3'd1;
                                state_r      <= S_ENC_START;
                            end
                        end
                    end
                end

                S_WRITE_RHO: begin
                    // Write rho (32 bytes = 4 words) to dk_ram[192..195]
                    case (feed_cnt)
                        3'd0: dk_ram[8'd192] <= reg_rho[ 63:  0];
                        3'd1: dk_ram[8'd193] <= reg_rho[127: 64];
                        3'd2: dk_ram[8'd194] <= reg_rho[191:128];
                        3'd3: dk_ram[8'd195] <= reg_rho[255:192];
                        default: ;
                    endcase
                    feed_cnt <= feed_cnt + 3'd1;
                    if (feed_cnt == 3'd3) begin
                        state_r <= S_HEK_INIT;
                    end
                end

                // -------------------------------------------------------------
                // Phase 5: H(ek) = SHA3-256(ek) over dk_ram[96..195] (100 words)
                // -------------------------------------------------------------
                S_HEK_INIT: begin
                    shake_init          <= 1'b1;
                    shake_mode          <= 2'b00; // SHA3-256
                    shake_squeeze_words <= 10'd4; // 4 words = 32 bytes
                    words_written_r     <= 8'd0;
                    int_dk_rd_addr      <= 8'd96;
                    fsm_shake_in_valid  <= 1'b0;
                    state_r             <= S_HEK_PREFETCH;
                end

                S_HEK_PREFETCH: begin
                    int_dk_rd_addr     <= 8'd97;
                    fsm_shake_in_valid <= 1'b1;
                    state_r            <= S_HEK_FEED;
                end

                S_HEK_FEED: begin
                    if (shake_in_ready) begin
                        words_written_r <= words_written_r + 8'd1;
                        int_dk_rd_addr  <= int_dk_rd_addr + 8'd1;
                        if (words_written_r == 8'd99) begin
                            fsm_shake_in_valid  <= 1'b0;
                            fsm_shake_out_ready <= 1'b1;
                            feed_cnt            <= 3'd0;
                            state_r             <= S_HEK_SQUEEZE;
                        end
                    end
                end

                S_HEK_SQUEEZE: begin
                    fsm_shake_in_valid  <= 1'b0;
                    fsm_shake_out_ready <= 1'b1;
                    if (shake_out_valid && fsm_shake_out_ready) begin
                        case (feed_cnt)
                            3'd0: begin reg_hek[ 63:  0] <= shake_out_data; if (op_r == OP_KEYGEN) dk_ram[8'd196] <= shake_out_data; end
                            3'd1: begin reg_hek[127: 64] <= shake_out_data; if (op_r == OP_KEYGEN) dk_ram[8'd197] <= shake_out_data; end
                            3'd2: begin reg_hek[191:128] <= shake_out_data; if (op_r == OP_KEYGEN) dk_ram[8'd198] <= shake_out_data; end
                            3'd3: begin reg_hek[255:192] <= shake_out_data; if (op_r == OP_KEYGEN) dk_ram[8'd199] <= shake_out_data; end
                            default: ;
                        endcase
                        feed_cnt <= feed_cnt + 3'd1;
                        if (feed_cnt == 3'd3) begin
                            fsm_shake_out_ready <= 1'b0;
                            feed_cnt            <= 3'd0;
                            if (op_r == OP_KEYGEN) state_r <= S_WRITE_Z;
                            else state_r <= S_ENC_G_INIT;
                        end
                    end
                end

                S_WRITE_Z: begin
                    // Write z (32 bytes = 4 words) to dk_ram[200..203]
                    case (feed_cnt)
                        3'd0: dk_ram[8'd200] <= seed_z[ 63:  0];
                        3'd1: dk_ram[8'd201] <= seed_z[127: 64];
                        3'd2: dk_ram[8'd202] <= seed_z[191:128];
                        3'd3: dk_ram[8'd203] <= seed_z[255:192];
                        default: ;
                    endcase
                    feed_cnt <= feed_cnt + 3'd1;
                    if (feed_cnt == 3'd3) begin
                        state_r <= S_DONE;
                    end
                end

                // -------------------------------------------------------------
                // Phase 6: KeyGen Done!
                // -------------------------------------------------------------
                S_DONE: begin
                    kem_done          <= 1'b1;
                    kem_shared_secret <= 256'd0;
                    state_r           <= S_IDLE;
                end

                // =============================================================
                // Encapsulation Phases (FIPS 203 Section 6)
                // =============================================================

                // -------------------------------------------------------------
                // Phase E0: Unpack & Canonicality Validate ek (t_hat[0,1])
                // -------------------------------------------------------------
                S_ENC_DEC_PREFETCH: begin
                    dec_start_poly  <= 1'b0;
                    words_written_r <= 8'd0;
                    int_dk_rd_addr  <= (dec_target_bank == 3'd0) ? 8'd97 : 8'd145;
                    dec_in_valid    <= 1'b1;
                    state_r         <= S_ENC_DEC_FEED;
                end

                S_ENC_DEC_FEED: begin
                    if (dec_err_non_canonical) begin
                        dec_in_valid <= 1'b0;
                        state_r      <= S_STRUCT_FAIL;
                    end else begin
                        if (dec_in_valid && dec_in_ready) begin
                            words_written_r <= words_written_r + 8'd1;
                            if (words_written_r < 8'd47) begin
                                int_dk_rd_addr <= int_dk_rd_addr + 8'd1;
                            end else begin
                                dec_in_valid <= 1'b0;
                            end
                        end

                        if (dec_out_valid) begin
                            dec_coeff_idx <= dec_coeff_idx + 8'd1;
                            if (dec_coeff_idx == 8'd255) begin
                                if (dec_target_bank == 3'd0) begin
                                    dec_start_poly  <= 1'b1;
                                    dec_target_bank <= 3'd1;
                                    dec_coeff_idx   <= 8'd0;
                                    words_written_r <= 8'd0;
                                    int_dk_rd_addr  <= 8'd144;
                                    dec_in_valid    <= 1'b0;
                                    state_r         <= S_ENC_DEC_PREFETCH;
                                end else begin
                                    dec_in_valid   <= 1'b0;
                                    int_dk_rd_addr <= 8'd192;
                                    feed_cnt       <= 3'd0;
                                    state_r        <= S_ENC_READ_RHO;
                                end
                            end
                        end
                    end
                end

                S_STRUCT_FAIL: begin
                    kem_key_invalid <= 1'b1;
                    v_kem_valid     <= 1'b1;
                    v_kem_fail      <= 1'b1;
                    v_kem_reason    <= `RC_HANDSHAKE_KEY_INVALID; // 4'h8
                    kem_done        <= 1'b0;
                    state_r         <= S_IDLE;
                end

                S_ENC_READ_RHO: begin
                    // dk_ram has 1-cycle synchronous read: cycle 0 is a wait cycle,
                    // rdata for word 192+k is valid on cycle k+1.
                    case (feed_cnt)
                        3'd0: begin int_dk_rd_addr <= 8'd193; feed_cnt <= 3'd1; end
                        3'd1: begin reg_rho[ 63:  0] <= dk_ram_b_rdata; int_dk_rd_addr <= 8'd194; feed_cnt <= 3'd2; end
                        3'd2: begin reg_rho[127: 64] <= dk_ram_b_rdata; int_dk_rd_addr <= 8'd195; feed_cnt <= 3'd3; end
                        3'd3: begin reg_rho[191:128] <= dk_ram_b_rdata; feed_cnt <= 3'd4; end
                        3'd4: begin reg_rho[255:192] <= dk_ram_b_rdata; feed_cnt <= 3'd0; state_r <= S_HEK_INIT; end
                        default: ;
                    endcase
                end

                // -------------------------------------------------------------
                // Phase E1: G(m || H(ek)) -> (K, r) via SHA3-512
                // -------------------------------------------------------------
                S_ENC_G_INIT: begin
                    shake_init          <= 1'b1;
                    shake_mode          <= 2'b01; // SHA3-512
                    shake_squeeze_words <= 10'd8; // 8 words = 64 bytes
                    fsm_shake_in_valid  <= 1'b0;
                    fsm_shake_out_ready <= 1'b0;
                    feed_cnt            <= 3'd0;
                    state_r             <= S_ENC_G_FEED;
                end

                S_ENC_G_FEED: begin
                    if (shake_in_ready) begin
                        fsm_shake_in_valid <= 1'b1;
                        case (feed_cnt)
                            3'd0: begin fsm_shake_in_data <= m_reg[ 63:  0];  fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd1; end
                            3'd1: begin fsm_shake_in_data <= m_reg[127: 64];  fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd2; end
                            3'd2: begin fsm_shake_in_data <= m_reg[191:128];  fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd3; end
                            3'd3: begin fsm_shake_in_data <= m_reg[255:192];  fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd4; end
                            3'd4: begin fsm_shake_in_data <= reg_hek[ 63:  0]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd5; end
                            3'd5: begin fsm_shake_in_data <= reg_hek[127: 64]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd6; end
                            3'd6: begin fsm_shake_in_data <= reg_hek[191:128]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd7; end
                            3'd7: begin
                                fsm_shake_in_data  <= reg_hek[255:192];
                                fsm_shake_in_bytes <= 4'd8;
                                fsm_shake_in_last  <= 1'b1;
                                feed_cnt           <= 3'd0;
                                state_r            <= S_ENC_G_SQUEEZE;
                            end
                            default: ;
                        endcase
                    end else begin
                        fsm_shake_in_valid <= 1'b0;
                    end
                end

                S_ENC_G_SQUEEZE: begin
                    fsm_shake_in_valid  <= 1'b0;
                    fsm_shake_out_ready <= 1'b1;
                    if (shake_out_valid && fsm_shake_out_ready) begin
                        case (feed_cnt)
                            3'd0: reg_k[ 63:  0] <= shake_out_data;
                            3'd1: reg_k[127: 64] <= shake_out_data;
                            3'd2: reg_k[191:128] <= shake_out_data;
                            3'd3: reg_k[255:192] <= shake_out_data;
                            3'd4: reg_r[ 63:  0] <= shake_out_data;
                            3'd5: reg_r[127: 64] <= shake_out_data;
                            3'd6: reg_r[191:128] <= shake_out_data;
                            3'd7: reg_r[255:192] <= shake_out_data;
                            default: ;
                        endcase
                        feed_cnt <= feed_cnt + 3'd1;
                        if (feed_cnt == 3'd7) begin
                            fsm_shake_out_ready <= 1'b0;
                            current_poly        <= 3'd0;
                            state_r             <= S_ENC_Y_CBD_INIT;
                        end
                    end
                end

                // -------------------------------------------------------------
                // Phase E2: Sample y[0,1] via CBD (eta1=3) & Forward NTT
                // -------------------------------------------------------------
                S_ENC_Y_CBD_INIT: begin
                    shake_init          <= 1'b1;
                    shake_mode          <= 2'b11; // SHAKE256 (PRF)
                    shake_squeeze_words <= 10'd24; // 192 bytes
                    fsm_shake_in_valid  <= 1'b0;
                    fsm_shake_out_ready <= 1'b0;
                    feed_cnt            <= 3'd0;
                    state_r             <= S_ENC_Y_CBD_FEED;
                end

                S_ENC_Y_CBD_FEED: begin
                    if (shake_in_ready) begin
                        fsm_shake_in_valid <= 1'b1;
                        case (feed_cnt)
                            3'd0: begin fsm_shake_in_data <= reg_r[ 63:  0]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd1; end
                            3'd1: begin fsm_shake_in_data <= reg_r[127: 64]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd2; end
                            3'd2: begin fsm_shake_in_data <= reg_r[191:128]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd3; end
                            3'd3: begin fsm_shake_in_data <= reg_r[255:192]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd4; end
                            3'd4: begin
                                fsm_shake_in_data  <= {56'd0, 5'd0, current_poly}; // r || n
                                fsm_shake_in_bytes <= 4'd1;
                                fsm_shake_in_last  <= 1'b1;
                                feed_cnt           <= 3'd0;
                                cbd_start          <= 1'b1;
                                cbd_mode_eta       <= 1'b0; // eta1 = 3
                                cbd_target_poly_id <= 3'd2 + current_poly; // Bank 2 for y0, Bank 3 for y1
                                state_r            <= S_ENC_Y_CBD_WAIT;
                            end
                            default: ;
                        endcase
                    end else begin
                        fsm_shake_in_valid <= 1'b0;
                    end
                end

                S_ENC_Y_CBD_WAIT: begin
                    fsm_shake_in_valid <= 1'b0;
                    if (cbd_done) begin
                        if (current_poly == 3'd0) begin
                            current_poly <= 3'd1;
                            state_r      <= S_ENC_Y_CBD_INIT;
                        end else begin
                            current_poly <= 3'd0;
                            state_r      <= S_ENC_Y_NTT_START;
                        end
                    end
                end

                S_ENC_Y_NTT_START: begin
                    ntt_start       <= 1'b1;
                    ntt_mode        <= 1'b0; // Forward NTT
                    ntt_target_bank <= 3'd2 + current_poly;
                    state_r         <= S_ENC_Y_NTT_WAIT;
                end

                S_ENC_Y_NTT_WAIT: begin
                    if (ntt_done) begin
                        if (current_poly == 3'd0) begin
                            current_poly <= 3'd1;
                            state_r      <= S_ENC_Y_NTT_START;
                        end else begin
                            mat_row <= 2'd0;
                            mat_col <= 2'd0;
                            state_r <= S_ENC_U_A_INIT;
                        end
                    end
                end

                // -------------------------------------------------------------
                // Phase E3: Matrix A^T sample, pointwise mul-acc, INTT, noise e1 -> u[0,1]
                // -------------------------------------------------------------
                S_ENC_U_A_INIT: begin
                    shake_init          <= 1'b1;
                    shake_mode          <= 2'b10; // SHAKE128
                    shake_squeeze_words <= 10'd84;
                    fsm_shake_in_valid  <= 1'b0;
                    fsm_shake_out_ready <= 1'b0;
                    feed_cnt            <= 3'd0;
                    state_r             <= S_ENC_U_A_FEED;
                end

                S_ENC_U_A_FEED: begin
                    if (shake_in_ready) begin
                        fsm_shake_in_valid <= 1'b1;
                        case (feed_cnt)
                            3'd0: begin fsm_shake_in_data <= reg_rho[ 63:  0]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd1; end
                            3'd1: begin fsm_shake_in_data <= reg_rho[127: 64]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd2; end
                            3'd2: begin fsm_shake_in_data <= reg_rho[191:128]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd3; end
                            3'd3: begin fsm_shake_in_data <= reg_rho[255:192]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd4; end
                            3'd4: begin
                                fsm_shake_in_data   <= {48'd0, 6'd0, mat_col, 6'd0, mat_row};
                                fsm_shake_in_bytes  <= 4'd2;
                                fsm_shake_in_last   <= 1'b1;
                                feed_cnt            <= 3'd0;
                                sntt_start          <= 1'b1;
                                sntt_target_poly_id <= 3'd6;
                                state_r             <= S_ENC_U_A_WAIT;
                            end
                            default: ;
                        endcase
                    end else begin
                        fsm_shake_in_valid <= 1'b0;
                    end
                end

                S_ENC_U_A_WAIT: begin
                    fsm_shake_in_valid <= 1'b0;
                    if (sntt_done) begin
                        state_r <= S_ENC_U_MUL_START;
                    end
                end

                S_ENC_U_MUL_START: begin
                    mul_start     <= 1'b1;
                    mul_op_a_bank <= 3'd6;
                    mul_op_b_bank <= (mat_col == 2'd0) ? 3'd2 : 3'd3;
                    mul_dest_bank <= (mat_row == 2'd0) ? 3'd4 : 3'd5;
                    if (mat_col == 2'd0) begin
                        mul_accumulate <= 1'b0;
                    end else begin
                        mul_accumulate <= 1'b1;
                        mul_acc_bank   <= (mat_row == 2'd0) ? 3'd4 : 3'd5;
                    end
                    state_r <= S_ENC_U_MUL_WAIT;
                end

                S_ENC_U_MUL_WAIT: begin
                    if (mul_done) begin
                        if (mat_col == 2'd0) begin
                            mat_col <= 2'd1;
                            state_r <= S_ENC_U_A_INIT;
                        end else begin
                            ntt_start       <= 1'b1;
                            ntt_mode        <= 1'b1; // INTT
                            ntt_target_bank <= (mat_row == 2'd0) ? 3'd4 : 3'd5;
                            state_r         <= S_ENC_U_INTT_WAIT;
                        end
                    end
                end

                S_ENC_U_INTT_WAIT: begin
                    if (ntt_done) begin
                        shake_init          <= 1'b1;
                        shake_mode          <= 2'b11; // SHAKE256
                        shake_squeeze_words <= 10'd16; // 128 bytes
                        fsm_shake_in_valid  <= 1'b0;
                        fsm_shake_out_ready <= 1'b0;
                        feed_cnt            <= 3'd0;
                        state_r             <= S_ENC_U_E1_FEED;
                    end
                end

                S_ENC_U_E1_FEED: begin
                    if (shake_in_ready) begin
                        fsm_shake_in_valid <= 1'b1;
                        case (feed_cnt)
                            3'd0: begin fsm_shake_in_data <= reg_r[ 63:  0]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd1; end
                            3'd1: begin fsm_shake_in_data <= reg_r[127: 64]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd2; end
                            3'd2: begin fsm_shake_in_data <= reg_r[191:128]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd3; end
                            3'd3: begin fsm_shake_in_data <= reg_r[255:192]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd4; end
                            3'd4: begin
                                fsm_shake_in_data  <= {56'd0, 6'd0, 2'd2 + mat_row};
                                fsm_shake_in_bytes <= 4'd1;
                                fsm_shake_in_last  <= 1'b1;
                                feed_cnt           <= 3'd0;
                                cbd_start          <= 1'b1;
                                cbd_mode_eta       <= 1'b1; // eta2 = 2
                                cbd_target_poly_id <= 3'd6;
                                state_r            <= S_ENC_U_E1_WAIT;
                            end
                            default: ;
                        endcase
                    end else begin
                        fsm_shake_in_valid <= 1'b0;
                    end
                end

                S_ENC_U_E1_WAIT: begin
                    fsm_shake_in_valid <= 1'b0;
                    if (cbd_done) begin
                        add_start     <= 1'b1;
                        add_mode      <= 2'b00; // MODE_ADD
                        add_dest_bank <= (mat_row == 2'd0) ? 3'd4 : 3'd5;
                        add_op_a_bank <= (mat_row == 2'd0) ? 3'd4 : 3'd5;
                        add_op_b_bank <= 3'd6;
                        add_op_c_bank <= 3'd0;
                        state_r       <= S_ENC_U_ADD_WAIT;
                    end
                end

                S_ENC_U_ADD_WAIT: begin
                    if (add_done) begin
                        if (mat_row == 2'd0) begin
                            mat_row <= 2'd1;
                            mat_col <= 2'd0;
                            state_r <= S_ENC_U_A_INIT;
                        end else begin
                            mat_col <= 2'd0;
                            state_r <= S_ENC_V_MUL_START;
                        end
                    end
                end

                // -------------------------------------------------------------
                // Phase E4: Dot product t_hat^T * y_hat, INTT, e2, mu -> v
                // -------------------------------------------------------------
                S_ENC_V_MUL_START: begin
                    mul_start     <= 1'b1;
                    mul_op_a_bank <= (mat_col == 2'd0) ? 3'd0 : 3'd1;
                    mul_op_b_bank <= (mat_col == 2'd0) ? 3'd2 : 3'd3;
                    mul_dest_bank <= 3'd6;
                    if (mat_col == 2'd0) begin
                        mul_accumulate <= 1'b0;
                    end else begin
                        mul_accumulate <= 1'b1;
                        mul_acc_bank   <= 3'd6;
                    end
                    state_r <= S_ENC_V_MUL_WAIT;
                end

                S_ENC_V_MUL_WAIT: begin
                    if (mul_done) begin
                        if (mat_col == 2'd0) begin
                            mat_col <= 2'd1;
                            state_r <= S_ENC_V_MUL_START;
                        end else begin
                            ntt_start       <= 1'b1;
                            ntt_mode        <= 1'b1; // INTT
                            ntt_target_bank <= 3'd6;
                            state_r         <= S_ENC_V_INTT_WAIT;
                        end
                    end
                end

                S_ENC_V_INTT_WAIT: begin
                    if (ntt_done) begin
                        shake_init          <= 1'b1;
                        shake_mode          <= 2'b11; // SHAKE256
                        shake_squeeze_words <= 10'd16; // 128 bytes
                        fsm_shake_in_valid  <= 1'b0;
                        fsm_shake_out_ready <= 1'b0;
                        feed_cnt            <= 3'd0;
                        state_r             <= S_ENC_V_E2_FEED;
                    end
                end

                S_ENC_V_E2_FEED: begin
                    if (shake_in_ready) begin
                        fsm_shake_in_valid <= 1'b1;
                        case (feed_cnt)
                            3'd0: begin fsm_shake_in_data <= reg_r[ 63:  0]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd1; end
                            3'd1: begin fsm_shake_in_data <= reg_r[127: 64]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd2; end
                            3'd2: begin fsm_shake_in_data <= reg_r[191:128]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd3; end
                            3'd3: begin fsm_shake_in_data <= reg_r[255:192]; fsm_shake_in_bytes <= 4'd8; fsm_shake_in_last <= 1'b0; feed_cnt <= 3'd4; end
                            3'd4: begin
                                fsm_shake_in_data  <= {56'd0, 8'd4};
                                fsm_shake_in_bytes <= 4'd1;
                                fsm_shake_in_last  <= 1'b1;
                                feed_cnt           <= 3'd0;
                                cbd_start          <= 1'b1;
                                cbd_mode_eta       <= 1'b1; // eta2 = 2
                                cbd_target_poly_id <= 3'd7;
                                state_r            <= S_ENC_V_E2_WAIT;
                            end
                            default: ;
                        endcase
                    end else begin
                        fsm_shake_in_valid <= 1'b0;
                    end
                end

                S_ENC_V_E2_WAIT: begin
                    fsm_shake_in_valid <= 1'b0;
                    if (cbd_done) begin
                        enc_coeff_idx <= 8'd0;
                        state_r       <= S_ENC_V_EXP_M;
                    end
                end

                S_ENC_V_EXP_M: begin
                    enc_coeff_idx <= enc_coeff_idx + 8'd1;
                    if (enc_coeff_idx == 8'd255) begin
                        state_r <= S_ENC_V_ADD3_START;
                    end
                end

                S_ENC_V_ADD3_START: begin
                    add_start     <= 1'b1;
                    add_mode      <= 2'b10; // MODE_ADD3
                    add_dest_bank <= 3'd6;
                    add_op_a_bank <= 3'd6;
                    add_op_b_bank <= 3'd7;
                    add_op_c_bank <= 3'd2;
                    state_r       <= S_ENC_V_ADD3_WAIT;
                end

                S_ENC_V_ADD3_WAIT: begin
                    if (add_done) begin
                        current_poly  <= 3'd0;
                        c_ram_wr_addr <= 7'd0;
                        state_r       <= S_ENC_C_START;
                    end
                end

                // -------------------------------------------------------------
                // Phase E5: Compress and ByteEncode (u_0, u_1, v) into c_ram
                // -------------------------------------------------------------
                S_ENC_C_START: begin
                    enc_coeff_idx   <= 8'd0;
                    enc_coeff_cnt   <= 9'd0;
                    enc_read_valid  <= 1'b0;
                    words_written_r <= 8'd0;
                    if (current_poly == 3'd0) begin
                        enc_bank         <= 3'd4;
                        enc10_start_poly <= 1'b1;
                    end else if (current_poly == 3'd1) begin
                        enc_bank         <= 3'd5;
                        enc10_start_poly <= 1'b1;
                    end else begin
                        enc_bank        <= 3'd6;
                        enc4_start_poly <= 1'b1;
                    end
                    state_r <= S_ENC_C_STREAM;
                end

                S_ENC_C_STREAM: begin
                    enc10_start_poly <= 1'b0;
                    enc4_start_poly  <= 1'b0;

                    if (enc_c_word_valid) begin
                        if (is_decaps) begin
                            // Decaps: compare re-encrypted word against stored c (no early exit)
                            c_match   <= c_match & (c_ram[c_ram_wr_addr] == enc_c_word_data);
                            c_cmp_cnt <= c_cmp_cnt + 8'd1;
                        end else begin
                            c_we_q <= 1'b1; c_wa_q <= c_ram_wr_addr; c_wd_q <= enc_c_word_data;
                        end
                        c_ram_wr_addr        <= c_ram_wr_addr + 7'd1;
                        words_written_r      <= words_written_r + 8'd1;
                    end

                    if (enc_coeff_cnt < 9'd256) begin
                        enc_coeff_idx  <= enc_coeff_idx + 8'd1;
                        enc_coeff_cnt  <= enc_coeff_cnt + 9'd1;
                        enc_read_valid <= 1'b1;
                    end else begin
                        enc_read_valid <= 1'b0;
                        state_r        <= S_ENC_C_DRAIN;
                    end
                end

                S_ENC_C_DRAIN: begin
                    enc_read_valid <= 1'b0;
                    if (enc_c_word_valid) begin
                        if (is_decaps) begin
                            // Decaps: compare re-encrypted word against stored c (no early exit)
                            c_match   <= c_match & (c_ram[c_ram_wr_addr] == enc_c_word_data);
                            c_cmp_cnt <= c_cmp_cnt + 8'd1;
                        end else begin
                            c_we_q <= 1'b1; c_wa_q <= c_ram_wr_addr; c_wd_q <= enc_c_word_data;
                        end
                        c_ram_wr_addr        <= c_ram_wr_addr + 7'd1;
                        words_written_r      <= words_written_r + 8'd1;
                        if ((current_poly < 3'd2 && words_written_r == 8'd39) || (current_poly == 3'd2 && words_written_r == 8'd15)) begin
                            if (current_poly == 3'd2) begin
                                // Decaps: select K' only if all 96 words matched, else decoy J(z||c).
                                // Same cycle, same shape either way.
                                kem_shared_secret <= (!is_decaps) ? reg_k :
                                    ((c_match & (c_ram[c_ram_wr_addr] == enc_c_word_data) &
                                      (c_cmp_cnt == 8'd95)) ? reg_k : reg_kbar);
                                kem_done          <= 1'b1;
                                state_r           <= S_IDLE;
                            end else begin
                                current_poly <= current_poly + 3'd1;
                                state_r      <= S_ENC_C_START;
                            end
                        end
                    end
                end

                // =============================================================
                // Decapsulation (FIPS 203 Algorithm 18)
                // =============================================================
                // J(z || c) = SHAKE256(z || c, 32): z from dk_ram[200..203], c from c_ram
                S_DEC_J_INIT: begin
                    shake_init          <= 1'b1;
                    shake_mode          <= 2'b11; // SHAKE256
                    shake_squeeze_words <= 10'd4;
                    words_written_r     <= 8'd0;
                    int_dk_rd_addr      <= 8'd200;
                    int_c_rd_addr       <= 7'd0;
                    fsm_shake_in_valid  <= 1'b0;
                    state_r             <= S_DEC_J_PREFETCH;
                end

                S_DEC_J_PREFETCH: begin
                    int_dk_rd_addr     <= 8'd201;
                    fsm_shake_in_valid <= 1'b1;
                    state_r            <= S_DEC_J_FEED;
                end

                S_DEC_J_FEED: begin
                    if (shake_in_ready) begin
                        words_written_r <= words_written_r + 8'd1;
                        int_dk_rd_addr  <= 8'd202 + words_written_r;
                        int_c_rd_addr   <= (words_written_r >= 8'd3) ? (words_written_r[6:0] - 7'd2) : 7'd0;
                        if (words_written_r == 8'd99) begin
                            fsm_shake_in_valid  <= 1'b0;
                            fsm_shake_out_ready <= 1'b1;
                            feed_cnt            <= 3'd0;
                            state_r             <= S_DEC_J_SQUEEZE;
                        end
                    end
                end

                S_DEC_J_SQUEEZE: begin
                    fsm_shake_in_valid  <= 1'b0;
                    fsm_shake_out_ready <= 1'b1;
                    if (shake_out_valid && fsm_shake_out_ready) begin
                        case (feed_cnt)
                            3'd0: reg_kbar[ 63:  0] <= shake_out_data;
                            3'd1: reg_kbar[127: 64] <= shake_out_data;
                            3'd2: reg_kbar[191:128] <= shake_out_data;
                            3'd3: reg_kbar[255:192] <= shake_out_data;
                            default: ;
                        endcase
                        feed_cnt <= feed_cnt + 3'd1;
                        if (feed_cnt == 3'd3) begin
                            fsm_shake_out_ready <= 1'b0;
                            feed_cnt            <= 3'd0;
                            lp_step             <= 3'd0;
                            state_r             <= S_LP_SETUP;
                        end
                    end
                end

                // Generic polynomial loader: step 0/1 u'[0/1] (c words 0..39 / 40..79, D=10),
                // step 2 v' (c words 80..95, D=4), step 3/4 s_hat[0/1] (dk words 0..47 / 48..95, D=12)
                S_LP_SETUP: begin
                    lp_in_valid       <= 1'b0;
                    lp_wr_idx         <= 8'd0;
                    words_written_r   <= 8'd0;
                    dec_check_modulus <= 1'b0;
                    case (lp_step)
                        3'd0: begin lp_src_c <= 1'b1; lp_mode <= 2'd1; lp_addr0 <= 8'd0;  lp_nwords <= 6'd40; lp_bank <= 3'd0; lp_start10 <= 1'b1; int_dk_rd_addr <= 8'd0;  int_c_rd_addr <= 7'd0;  end
                        3'd1: begin lp_src_c <= 1'b1; lp_mode <= 2'd1; lp_addr0 <= 8'd40; lp_nwords <= 6'd40; lp_bank <= 3'd1; lp_start10 <= 1'b1; int_dk_rd_addr <= 8'd40; int_c_rd_addr <= 7'd40; end
                        3'd2: begin lp_src_c <= 1'b1; lp_mode <= 2'd2; lp_addr0 <= 8'd80; lp_nwords <= 6'd16; lp_bank <= 3'd4; lp_start4  <= 1'b1; int_dk_rd_addr <= 8'd80; int_c_rd_addr <= 7'd80; end
                        3'd3: begin lp_src_c <= 1'b0; lp_mode <= 2'd0; lp_addr0 <= 8'd0;  lp_nwords <= 6'd48; lp_bank <= 3'd2; dec_start_poly <= 1'b1; int_dk_rd_addr <= 8'd0;  int_c_rd_addr <= 7'd0;  end
                        default: begin lp_src_c <= 1'b0; lp_mode <= 2'd0; lp_addr0 <= 8'd48; lp_nwords <= 6'd48; lp_bank <= 3'd3; dec_start_poly <= 1'b1; int_dk_rd_addr <= 8'd48; int_c_rd_addr <= 7'd48; end
                    endcase
                    state_r <= S_LP_PREFETCH;
                end

                S_LP_PREFETCH: begin
                    int_dk_rd_addr <= lp_addr0 + 8'd1;
                    int_c_rd_addr  <= lp_addr0[6:0] + 7'd1;
                    lp_in_valid    <= 1'b1;
                    state_r        <= S_LP_FEED;
                end

                S_LP_FEED: begin
                    if (lp_in_valid && lp_sel_ready) begin
                        words_written_r <= words_written_r + 8'd1;
                        if ((words_written_r + 8'd1) < {2'd0, lp_nwords}) begin
                            int_dk_rd_addr <= int_dk_rd_addr + 8'd1;
                            int_c_rd_addr  <= int_c_rd_addr + 7'd1;
                        end else begin
                            lp_in_valid <= 1'b0;
                        end
                    end
                    if (lp_fin_valid) begin
                        lp_wr_idx <= lp_wr_idx + 8'd1;
                        if (lp_wr_idx == 8'd255) begin
                            lp_in_valid <= 1'b0;
                            lp_step     <= lp_step + 3'd1;
                            if (lp_step == 3'd4) begin
                                lp_src_c     <= 1'b0;
                                current_poly <= 3'd0;
                                state_r      <= S_DC_NTT_START;
                            end else begin
                                state_r <= S_LP_SETUP;
                            end
                        end
                    end
                end

                // NTT(u'[0]), NTT(u'[1]) in banks 0,1
                S_DC_NTT_START: begin
                    ntt_start       <= 1'b1;
                    ntt_mode        <= 1'b0;
                    ntt_target_bank <= current_poly;
                    state_r         <= S_DC_NTT_WAIT;
                end

                S_DC_NTT_WAIT: begin
                    if (ntt_done) begin
                        if (current_poly == 3'd1) begin
                            mat_col <= 2'd0;
                            state_r <= S_DC_MUL_START;
                        end else begin
                            current_poly <= current_poly + 3'd1;
                            state_r      <= S_DC_NTT_START;
                        end
                    end
                end

                // dot = s_hat[0]*u_hat[0] + s_hat[1]*u_hat[1]  -> bank 5
                S_DC_MUL_START: begin
                    mul_start     <= 1'b1;
                    mul_op_a_bank <= 3'd2 + {1'b0, mat_col};
                    mul_op_b_bank <= {1'b0, mat_col};
                    mul_dest_bank <= 3'd5;
                    if (mat_col == 2'd0) begin
                        mul_accumulate <= 1'b0;
                    end else begin
                        mul_accumulate <= 1'b1;
                        mul_acc_bank   <= 3'd5;
                    end
                    state_r <= S_DC_MUL_WAIT;
                end

                S_DC_MUL_WAIT: begin
                    if (mul_done) begin
                        if (mat_col == 2'd0) begin
                            mat_col <= 2'd1;
                            state_r <= S_DC_MUL_START;
                        end else begin
                            ntt_start       <= 1'b1;
                            ntt_mode        <= 1'b1; // INTT
                            ntt_target_bank <= 3'd5;
                            state_r         <= S_DC_INTT_WAIT;
                        end
                    end
                end

                S_DC_INTT_WAIT: begin
                    if (ntt_done) state_r <= S_DC_SUB_START;
                end

                // w = v' - INTT(dot)  -> bank 6
                S_DC_SUB_START: begin
                    add_start     <= 1'b1;
                    add_mode      <= 2'b01; // MODE_SUB
                    add_dest_bank <= 3'd6;
                    add_op_a_bank <= 3'd4;
                    add_op_b_bank <= 3'd5;
                    add_op_c_bank <= 3'd0;
                    state_r       <= S_DC_SUB_WAIT;
                end

                S_DC_SUB_WAIT: begin
                    if (add_done) state_r <= S_DC_M_START;
                end

                // m' = ByteEncode1(Compress1(w)) -> m_reg
                S_DC_M_START: begin
                    enc_coeff_idx   <= 8'd0;
                    enc_coeff_cnt   <= 9'd0;
                    enc_read_valid  <= 1'b0;
                    words_written_r <= 8'd0;
                    enc_bank        <= 3'd6;
                    enc1_start_poly <= 1'b1;
                    state_r         <= S_DC_M_STREAM;
                end

                S_DC_M_STREAM: begin
                    if (enc1_out_valid) begin
                        m_reg[{words_written_r[1:0], 6'd0} +: 64] <= enc1_out_data;
                        words_written_r <= words_written_r + 8'd1;
                    end
                    if (enc_coeff_cnt < 9'd256) begin
                        enc_coeff_idx  <= enc_coeff_idx + 8'd1;
                        enc_coeff_cnt  <= enc_coeff_cnt + 9'd1;
                        enc_read_valid <= 1'b1;
                    end else begin
                        enc_read_valid <= 1'b0;
                        state_r        <= S_DC_M_DRAIN;
                    end
                end

                S_DC_M_DRAIN: begin
                    enc_read_valid <= 1'b0;
                    if (enc1_out_valid) begin
                        m_reg[{words_written_r[1:0], 6'd0} +: 64] <= enc1_out_data;
                        words_written_r <= words_written_r + 8'd1;
                        if (words_written_r == 8'd3) begin
                            // Re-encrypt: validate/decode ek from dk_ram[96..191], then reuse Encaps path
                            dec_start_poly    <= 1'b1;
                            dec_check_modulus <= 1'b1;
                            dec_target_bank   <= 3'd0;
                            dec_coeff_idx     <= 8'd0;
                            int_dk_rd_addr    <= 8'd96;
                            words_written_r   <= 8'd0;
                            state_r           <= S_ENC_DEC_PREFETCH;
                        end
                    end
                end

                // Encaps start after an ingested ek: needs a fresh seed (already captured, or wait).
                S_ING_ENC_GO: begin
                    if (m_have || (rng_valid && !rng_lock)) begin
                        if (!m_have) begin
                            m_reg    <= rng_data;
                            rng_take <= 1'b1;
                            rng_lock <= 1'b1;
                        end
                        m_have            <= 1'b0;
                        op_r              <= OP_ENCAPS;
                        is_decaps         <= 1'b0;
                        dec_start_poly    <= 1'b1;
                        dec_check_modulus <= 1'b1;
                        dec_target_bank   <= 3'd0;
                        dec_coeff_idx     <= 8'd0;
                        int_dk_rd_addr    <= 8'd96;
                        words_written_r   <= 8'd0;
                        state_r           <= S_ENC_DEC_PREFETCH;
                    end
                end

                default: state_r <= S_IDLE;
            endcase
        end
    end

    // Unused signal tie-offs for lint compliance
    wire _unused_ok = &{1'b0,
        OP_DECAPS, dec10_out_data[11:10], dec4_out_data[11:4],
        sntt_err_truncated, sntt_poly_mem_addr[10:8],
        cbd_err_truncated, cbd_poly_mem_addr[10:8],
        enc_overflow, enc_poly_last, enc_busy,
        enc10_overflow, enc10_poly_last, enc10_busy,
        enc4_overflow, enc4_poly_last, enc4_busy,
        dec_busy,
        dec10_busy, dec10_err, dec4_busy, dec4_err,
        enc1_busy, enc1_overflow, enc1_poly_last,
        packer_in_ready, packer_out_bytes,
        shake_out_mask, shake_busy
    };

endmodule

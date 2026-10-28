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
// Timing-driven datapath (radix 2^13, loosely reduced)
// ----------------------------------------------------
// The original single-cycle 131x128 multiply + 259-bit add + 3-adder reduce
// was a 20 ns combinational path (a DSP cascade feeding a ~130-bit carry
// chain) and could not meet 100 MHz. This version never builds a wide
// product. Every register-to-register path is a <=15x16 multiply inside one
// DSP48 or a <=35-bit add:
//
//   * acc, a, r are held as 10 limbs of 13 bits  (10 * 13 = 130 bits).
//   * Because 2^130 = 5 (mod 2^130 - 5), the limb product that would land at
//     weight 2^(13*(i+j)) with i+j >= 10 is folded back to 2^(13*(i+j-10))
//     times 5. So column k is simply
//         c_k = sum_i a_i * m_(i,k)      m = r_(k-i)        if i <= k
//                                        m = 5 * r_(k-i+10) otherwise
//     -- no 259-bit product exists and no separate "reduce" adder is needed.
//   * Each column is a multiply-ACCUMULATE in its own DSP48 (two per column,
//     5 steps each). The 5*r operand is produced by rotating the r limbs
//     one lane per step (lane 9 wraps into lane 0 times 5).
//   * Two small carry passes (13-bit lo/hi split, hi of limb 9 wraps x5)
//     leave every limb < 2^14: the accumulator is only LOOSELY reduced
//     between chunks. Bounds: a_i = acc_i + n_i < 2^15, c_k < 2^35,
//     pass-1 limbs < 2^25, pass-2 limbs < 2^14.
//   * The exact value mod p is recovered once per message in S_FIN_*: a
//     limb-serial carry ripple (two rotations), then a one-term conditional
//     subtract of p (all-ones detect), then (acc + s) mod 2^128 in two
//     64-bit halves, then the tag compare in its own cycle.
//
// Latency per 16-byte chunk (blk_valid / last streamed byte -> back to
// S_BUF_WAIT): S_ADD, 6x S_MAC, S_SUM, S_C1, S_C2 = 10 clocks. Finalization
// adds 24 clocks once per message (S_FIN_NORM 20, S_FIN_CHK, S_FIN_ADD0,
// S_FIN_ADD1, S_FIN_CMP). chacha_poly.v hands blocks over only when
// blk_ready is high and at most once per 16 ciphertext bytes, so the
// 10-clock chunk latency stays inside its spacing.
//
// Final Tag Generation & Egress:
//   tag = (acc + s) mod 2^128
//   tag_ok = (tag == expected_tag)
//   Asserts uniform verdict interface to drop_engine.v (RC_BAD_TAG = 4'h7).
//   Drives Section 3.1 pt_tag_ok / pt_tag_valid to qualify cam_matcher.v.
//
// Constraints: Verilog-2001, single clk, sync active-high rst, registered
// outputs, no latches, no BRAMs. 20 DSP48E1 (the MAC columns); datapath
// registers (a_sh, m0, m1, col, dsum, MAC pipeline) carry no reset because
// they are always written before they are read.

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

    reg [127:0] r_reg;
    reg [127:0] s_reg;

    // =========================================================================
    // State Machine
    // =========================================================================
    localparam [3:0] S_IDLE       = 4'd0;
    localparam [3:0] S_BUF_WAIT   = 4'd1;
    localparam [3:0] S_ADD        = 4'd2;   // a_i = acc_i + n_i, load r lanes
    localparam [3:0] S_MAC        = 4'd3;   // 5 steps + 1 flush on 20 DSP48
    localparam [3:0] S_SUM        = 4'd4;   // col_k = acc0_k + acc1_k
    localparam [3:0] S_C1         = 4'd5;   // carry pass 1
    localparam [3:0] S_C2         = 4'd6;   // carry pass 2 -> acc (loose)
    localparam [3:0] S_FIN_NORM   = 4'd7;   // limb-serial ripple, 2 rotations
    localparam [3:0] S_FIN_CHK    = 4'd8;   // conditional subtract of p
    localparam [3:0] S_FIN_ADD0   = 4'd9;   // low 64 of (acc + s)
    localparam [3:0] S_FIN_ADD1   = 4'd10;  // high 64 of (acc + s)
    localparam [3:0] S_FIN_CMP    = 4'd11;  // compare + verdict

    reg [3:0] state;
    assign blk_ready = (state == S_IDLE) || (state == S_BUF_WAIT);

    // Accumulator: 10 lanes x 14 bits. Loose between chunks (each lane < 2^14),
    // canonical 13-bit lanes after S_FIN_NORM / S_FIN_CHK.
    reg [139:0] acc;

    // Byte assembly buffer
    reg [7:0]   buf_bytes [0:15];
    reg [3:0]   buf_count;
    reg         eof_seen;

    // Chunk under evaluation
    reg [128:0] n_reg;          // chunk value incl. the appended 0x01 byte
    reg         use_acc;        // 1: add acc to n (0 only for a message's first block)
    reg         is_last_chunk;

    // =========================================================================
    // Construct 129-bit n from buffer bytes (little-endian + append 0x01 byte)
    // =========================================================================
    // NOTE: the BLKSEQ lint check fires on blocking assignments inside a function
    // that is called from a clocked process. Verilog *requires* blocking
    // assignments to function-local variables — a non-blocking assignment here
    // would not compile — so this is a false positive, not a sim/synth hazard.
    // Scoped lint_off rather than relaxing -Wall repo-wide.
    /* verilator lint_off BLKSEQ */
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
    /* verilator lint_on BLKSEQ */

    // x * 5 = (x << 2) + x, 16-bit. Only ever applied to un-wrapped (<= 13-bit)
    // r limbs, so dropping x[15:14] loses nothing.
    function [15:0] mul5;
        input [15:0] x;
        begin
            mul5 = {x[13:0], 2'b00} + x;
        end
    endfunction

    // =========================================================================
    // Multiply-accumulate columns
    // =========================================================================
    // a_sh : 10 lanes x 15 bits, shifts one lane per step. Lane 0 = a_s and
    //        lane 5 = a_(s+5) at step s, so two accumulators per column each
    //        take 5 steps.
    // m0/m1: 10 lanes x 16 bits. Lane k of m0 at step s is the multiplier of
    //        a_s in column k (r_(k-s), or 5*r_(k-s+10) once it has wrapped);
    //        m1 is the same sequence started 5 steps later (for a_(s+5)).
    //        Shift: lane k <= lane k-1, lane 0 <= 5 * lane 9.
    reg  [149:0] a_sh;
    reg  [159:0] m0;
    reg  [159:0] m1;
    reg  [2:0]   mac_cnt;

    wire [14:0]  a_lo = a_sh[14:0];
    wire [14:0]  a_hi = a_sh[89:75];

    wire mac_ld    = (state == S_MAC) && (mac_cnt == 3'd1);
    wire mac_acc   = (state == S_MAC) && (mac_cnt >= 3'd2);
    wire mac_shift = (state == S_MAC) && (mac_cnt <= 3'd3);

    wire [339:0] ac0_bus;
    wire [339:0] ac1_bus;

    genvar gk;
    generate
        for (gk = 0; gk < 10; gk = gk + 1) begin : g_mac
            (* use_dsp = "yes" *) reg [30:0] pm0;   // multiplier output (MREG)
            (* use_dsp = "yes" *) reg [30:0] pm1;
            (* use_dsp = "yes" *) reg [33:0] ac0;   // accumulator (PREG)
            (* use_dsp = "yes" *) reg [33:0] ac1;

            always @(posedge clk) begin
                pm0 <= a_lo * m0[16*gk +: 16];
                pm1 <= a_hi * m1[16*gk +: 16];
                if (mac_ld) begin
                    ac0 <= {3'd0, pm0};
                    ac1 <= {3'd0, pm1};
                end else if (mac_acc) begin
                    ac0 <= ac0 + {3'd0, pm0};
                    ac1 <= ac1 + {3'd0, pm1};
                end
            end

            assign ac0_bus[34*gk +: 34] = ac0;
            assign ac1_bus[34*gk +: 34] = ac1;
        end
    endgenerate

    // Column sums and carry-pass intermediates
    reg [349:0] col;     // 10 x 35 bits
    reg [249:0] dsum;    // 10 x 25 bits

    // Canonical 130-bit view of acc (13-bit lanes) for the final add
    wire [129:0] acc_val;
    genvar ga;
    generate
        for (ga = 0; ga < 10; ga = ga + 1) begin : g_accval
            assign acc_val[13*ga +: 13] = acc[14*ga +: 13];
        end
    endgenerate

    // Operand views
    wire [129:0] n_ext = {1'b0, n_reg};
    wire [129:0] r_ext = {2'b00, r_reg};

    // Carry-pass wrap terms (limb 9 high part, times 5)
    wire [21:0] c1_h9   = col[35*9+13 +: 22];
    wire [24:0] c1_h9x5 = {1'b0, c1_h9, 2'b00} + {3'd0, c1_h9};
    wire [11:0] c2_h9   = dsum[25*9+13 +: 12];
    wire [15:0] c2_h9x5 = {2'b00, c2_h9, 2'b00} + {4'd0, c2_h9};

    // Final conditional subtract: X >= p  <=>  limbs 1..9 all 0x1FFF and
    // limb0 >= 0x1FFB (p = 2^130 - 5).
    wire fin_hi_ones = &{acc[14*1 +: 13], acc[14*2 +: 13], acc[14*3 +: 13],
                         acc[14*4 +: 13], acc[14*5 +: 13], acc[14*6 +: 13],
                         acc[14*7 +: 13], acc[14*8 +: 13], acc[14*9 +: 13]};
    wire fin_ge      = fin_hi_ones && (acc[12:0] >= 13'h1FFB);

    // Carry pass 2 per lane: lo13(dsum_k) + hi(dsum_(k-1)), lane 0 wraps x5.
    // Result is < 2^14 by construction; only [13:0] is kept.
    wire [159:0] c2_sum;
    wire [19:0]  c2_top;
    genvar gc;
    generate
        for (gc = 0; gc < 10; gc = gc + 1) begin : g_c2
            if (gc == 0) begin : g_wrap
                assign c2_sum[16*gc +: 16] = {3'b000, dsum[25*gc +: 13]} + c2_h9x5;
            end else begin : g_prev
                assign c2_sum[16*gc +: 16] = {3'b000, dsum[25*gc +: 13]}
                                           + {4'd0, dsum[25*(gc-1)+13 +: 12]};
            end
            assign c2_top[2*gc +: 2] = c2_sum[16*gc+14 +: 2];
        end
    endgenerate

    // Final ripple: lane[fidx] + carry
    wire [14:0] fin_t  = {1'b0, acc[14*fidx +: 14]} + {12'd0, fc};
    wire        fin_co = fin_t[13];

    // Bits that are zero by the bounds above (checked in sim)
    wire _unused_ok = &{1'b0, c2_top, fin_t[14], acc_val[129:128]};

    // Streaming bytes keep arriving while the multiplier works; park them.
    wire in_compute = (state == S_ADD) || (state == S_MAC) || (state == S_SUM) ||
                      (state == S_C1)  || (state == S_C2);

    // Finalization scratch
    reg [3:0]  fidx;       // ripple lane
    reg        fround;     // 0: first rotation, 1: second
    reg [2:0]  fc;         // ripple carry (0..5)
    reg [63:0] fin_lo;
    reg [63:0] fin_hi;
    reg        fin_c;

    // =========================================================================
    // Datapath load / shift (no reset: always written before use)
    // =========================================================================
    integer li;
    always @(posedge clk) begin
        if (state == S_ADD) begin
            for (li = 0; li < 10; li = li + 1) begin
                a_sh[15*li +: 15] <= {1'b0, (use_acc ? acc[14*li +: 14] : 14'd0)}
                                   + {2'b00, n_ext[13*li +: 13]};
                m0[16*li +: 16]   <= {3'b000, r_ext[13*li +: 13]};
                if (li >= 5)
                    m1[16*li +: 16] <= {3'b000, r_ext[13*((li+5)%10) +: 13]};
                else
                    m1[16*li +: 16] <= mul5({3'b000, r_ext[13*((li+5)%10) +: 13]});
            end
        end else if (mac_shift) begin
            a_sh <= {15'd0, a_sh[149:15]};
            m0   <= {m0[143:0], mul5(m0[159:144])};
            m1   <= {m1[143:0], mul5(m1[159:144])};
        end

        if (state == S_SUM) begin
            for (li = 0; li < 10; li = li + 1)
                col[35*li +: 35] <= {1'b0, ac0_bus[34*li +: 34]}
                                  + {1'b0, ac1_bus[34*li +: 34]};
        end

        if (state == S_C1) begin
            for (li = 0; li < 10; li = li + 1)
                dsum[25*li +: 25] <= {12'd0, col[35*li +: 13]}
                                   + ((li == 0) ? c1_h9x5
                                                : {3'd0, col[35*((li+9)%10)+13 +: 22]});
        end
    end

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
            acc           <= 140'd0;
            buf_count     <= 4'd0;
            eof_seen      <= 1'b0;
            n_reg         <= 129'd0;
            use_acc       <= 1'b0;
            is_last_chunk <= 1'b0;
            mac_cnt       <= 3'd0;
            fidx          <= 4'd0;
            fround        <= 1'b0;
            fc            <= 3'd0;
            fin_lo        <= 64'd0;
            fin_hi        <= 64'd0;
            fin_c         <= 1'b0;

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
                acc       <= 140'd0;
                eof_seen  <= 1'b0;
                buf_count <= 4'd0;
            end

            // Buffer any incoming streaming bytes during the multiply pipeline
            if (in_compute && msg_valid) begin
                buf_bytes[buf_count] <= msg_data;
                buf_count <= buf_count + 4'd1;
                if (msg_eof) eof_seen <= 1'b1;
            end

            // -----------------------------------------------------------------
            // Main Processing FSM
            // -----------------------------------------------------------------
            case (state)
                S_IDLE: begin
                    busy <= 1'b0;
                    if (msg_sof || (msg_valid && !busy)) begin
                        // Start of new streaming message
                        acc        <= 140'd0;
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
                            acc   <= 140'd0;
                            state <= S_FIN_NORM;
                        end else begin : blk_direct_calc
                            reg [128:0] n_blk;
                            n_blk = {1'b0, blk_data} | (129'd1 << (blk_len * 8));
                            n_reg         <= n_blk;
                            use_acc       <= 1'b0;
                            is_last_chunk <= blk_last;
                            state         <= S_ADD;
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
                                n_reg         <= n_chunk;
                                use_acc       <= 1'b1;
                                is_last_chunk <= 1'b1;
                                buf_count     <= 4'd0;
                                state         <= S_ADD;
                            end
                        end else if (buf_count == 4'd15) begin
                            // Full 16-byte chunk ready
                            begin : blk_full_chunk
                                reg [128:0] n_chunk;
                                n_chunk = build_n(5'd16, msg_data, 1'b1);
                                n_reg         <= n_chunk;
                                use_acc       <= 1'b1;
                                is_last_chunk <= 1'b0;
                                buf_count     <= 4'd0;
                                state         <= S_ADD;
                            end
                        end else begin
                            buf_count <= buf_count + 4'd1;
                        end
                    end else if (eof_seen) begin
                        // Final chunk trigger if eof arrived without byte in this cycle
                        if (buf_count > 4'd0) begin : blk_rem_chunk
                            reg [128:0] n_chunk;
                            n_chunk = build_n({1'b0, buf_count}, 8'd0, 1'b0);
                            n_reg         <= n_chunk;
                            use_acc       <= 1'b1;
                            is_last_chunk <= 1'b1;
                            buf_count     <= 4'd0;
                            state         <= S_ADD;
                        end else begin
                            // Empty remaining buffer, go straight to finalize
                            state <= S_FIN_NORM;
                        end
                    end else if (blk_valid) begin : blk_wait_direct
                        reg [128:0] n_blk;
                        n_blk = {1'b0, blk_data} | (129'd1 << (blk_len * 8));
                        n_reg         <= n_blk;
                        use_acc       <= 1'b1;
                        is_last_chunk <= blk_last;
                        state         <= S_ADD;
                    end
                end

                // ---- chunk multiply: acc <= (acc + n) * r  (loosely reduced) ----
                S_ADD: begin
                    // a_sh / m0 / m1 are loaded by the datapath block above
                    mac_cnt <= 3'd0;
                    state   <= S_MAC;
                end

                S_MAC: begin
                    mac_cnt <= mac_cnt + 3'd1;
                    if (mac_cnt == 3'd5)
                        state <= S_SUM;
                end

                S_SUM: begin
                    state <= S_C1;
                end

                S_C1: begin
                    state <= S_C2;
                end

                S_C2: begin
                    // Carry pass 2: every lane ends < 2^14 (value stays
                    // congruent to (acc + n) * r mod 2^130 - 5).
                    for (idx = 0; idx < 10; idx = idx + 1)
                        acc[14*idx +: 14] <= c2_sum[16*idx +: 14];
                    if (is_last_chunk)
                        state <= S_FIN_NORM;
                    else
                        state <= S_BUF_WAIT;
                end

                // ---- finalization: exact (acc mod p), then tag ----------------
                S_FIN_NORM: begin
                    // Ripple carry limb by limb, two rotations. Rotation 2
                    // injects 5 * (carry out of limb 9) into limb 0.
                    acc[14*fidx +: 14] <= {1'b0, fin_t[12:0]};
                    if (fidx == 4'd9) begin
                        fidx   <= 4'd0;
                        fround <= 1'b1;
                        fc     <= fin_co ? 3'd5 : 3'd0;
                        if (fround)
                            state <= S_FIN_CHK;
                    end else begin
                        fidx <= fidx + 4'd1;
                        fc   <= {2'b00, fin_co};
                    end
                end

                S_FIN_CHK: begin
                    // acc is now X in [0, 2^130) with 13-bit lanes.
                    // X >= p only for X in [2^130-5, 2^130-1]; then X-p is
                    // limb0 - 0x1FFB with every other lane zero.
                    fround <= 1'b0;
                    fc     <= 3'd0;
                    if (fin_ge) begin
                        acc[13:0]   <= {1'b0, acc[12:0] - 13'h1FFB};
                        acc[139:14] <= 126'd0;
                    end
                    state <= S_FIN_ADD0;
                end

                S_FIN_ADD0: begin
                    {fin_c, fin_lo} <= {1'b0, acc_val[63:0]} + {1'b0, s_reg[63:0]};
                    state <= S_FIN_ADD1;
                end

                S_FIN_ADD1: begin
                    fin_hi <= acc_val[127:64] + s_reg[127:64] + {63'd0, fin_c};
                    state  <= S_FIN_CMP;
                end

                S_FIN_CMP: begin
                    begin : blk_fin
                        reg [127:0] final_tag;
                        reg         match;

                        final_tag = {fin_hi, fin_lo};
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
                        acc           <= 140'd0;
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

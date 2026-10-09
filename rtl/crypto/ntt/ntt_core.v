//==========================================================================
// rtl/crypto/ntt/ntt_core.v
//
// Number Theoretic Transform (NTT) Core for ML-KEM-512.
// Bit-exact synthesizable RTL twin of model/mlkem/ntt.py.
//
// Features & Architecture:
//   - Parameterized pipeline depth (PIPE_DEPTH = 3, nominal).
//   - Single Butterfly Unit (1 DSP48E1, 0 BRAM for butterfly itself).
//   - 1 internal RAMB18E1 Scratch buffer (256x12 True Dual-Port RAM).
//   - Scratch Parity Handling:
//       * Forward NTT (7 stages, odd parity): results end in Scratch buffer.
//         Includes an automatic 256-cycle copy-back phase from Scratch to Main RAM.
//       * Inverse INTT (7 stages + 1 scaling stage): butterfly stages end in Scratch,
//         and the final scaling stage (INV_N = 3303) streams from Scratch directly
//         into Main RAM (zero copy-back overhead!).
//   - External Memory: Interfaces with synchronous Dual-Port Polynomial RAM (1-cycle read latency).
//   - Fully constant-time execution: starts during busy are strictly ignored.
//
// Timing & Resource Estimates (XC7Z020 @ 100 MHz, estimated, pre-synthesis):
//   Forward NTT Latency: ~1,196 clock cycles (~12.0 us)
//   Inverse INTT Latency: ~1,199 clock cycles (~12.0 us)
//   DSP48E1: 1 slice (inside modmul.v)
//   BRAMs: 1 RAMB18E1 (internal scratch memory)
//   Slice LUTs: ~450-520 LUTs total (FSM, address generators, butterfly datapath)
//   Slice FFs: ~320 registers
//==========================================================================

`timescale 1ns / 1ps

module ntt_core #(
    parameter integer PIPE_DEPTH = 3
) (
    input  wire        clk,
    input  wire        rst,

    // Control & Status
    input  wire        start,     // 1-cycle start pulse (ignored if busy)
    input  wire        mode,      // 0: Forward NTT, 1: Inverse INTT
    output wire        busy,      // High while computing
    output wire        done,      // 1-cycle completion pulse

    // Main Polynomial RAM Dual-Port Interface (1-cycle synchronous read latency)
    output wire [7:0]  mem_a_addr,
    input  wire [11:0] mem_a_rdata,
    output wire        mem_a_we,
    output wire [11:0] mem_a_wdata,

    output wire [7:0]  mem_b_addr,
    input  wire [11:0] mem_b_rdata,
    output wire        mem_b_we,
    output wire [11:0] mem_b_wdata
);

    `include "ntt_zetas.vh"

    localparam [1:0] BF_MODE_CT  = 2'b00;
    localparam [1:0] BF_MODE_GS  = 2'b01;
    localparam [1:0] BF_MODE_MUL = 2'b10;

    localparam [2:0] S_IDLE        = 3'd0;
    localparam [2:0] S_STAGE_READ  = 3'd1;
    localparam [2:0] S_STAGE_DRAIN = 3'd2;
    localparam [2:0] S_COPY_BACK   = 3'd3;
    localparam [2:0] S_INTT_SCALE  = 3'd4;
    localparam [2:0] S_DONE        = 3'd5;

    reg [2:0] state;
    reg       mode_reg;
    reg [2:0] stage_reg;
    reg [6:0] bf_cnt;

    // -------------------------------------------------------------------------
    // Internal Scratch RAM (256x12 True Dual-Port, 1-cycle synchronous read)
    // -------------------------------------------------------------------------
    reg [11:0] scratch_mem [0:255];

    reg [7:0]  scratch_a_addr;
    reg        scratch_a_we;
    reg [11:0] scratch_a_wdata;
    reg [11:0] scratch_a_rdata;

    reg [7:0]  scratch_b_addr;
    reg        scratch_b_we;
    reg [11:0] scratch_b_wdata;
    reg [11:0] scratch_b_rdata;

    always @(posedge clk) begin
        if (scratch_a_we) scratch_mem[scratch_a_addr] <= scratch_a_wdata;
        scratch_a_rdata <= scratch_mem[scratch_a_addr];

        if (scratch_b_we) scratch_mem[scratch_b_addr] <= scratch_b_wdata;
        scratch_b_rdata <= scratch_mem[scratch_b_addr];
    end

    // -------------------------------------------------------------------------
    // Address & Twiddle Generator Logic
    // -------------------------------------------------------------------------
    // Forward NTT: stride = 128 >> stage
    wire [7:0] fwd_stride = 8'd128 >> stage_reg;
    wire [6:0] fwd_group  = bf_cnt >> (3'd7 - stage_reg);
    wire [6:0] fwd_offset = bf_cnt & (fwd_stride[6:0] - 7'd1);
    wire [7:0] fwd_start  = {fwd_group, 1'b0} << (3'd7 - stage_reg);
    wire [7:0] fwd_addr_a = fwd_start + {1'b0, fwd_offset};
    wire [7:0] fwd_addr_b = fwd_addr_a + fwd_stride;
    wire [6:0] fwd_k      = (7'd1 << stage_reg) + fwd_group;

    // Inverse INTT: stride = 1 << (stage + 1)
    wire [7:0] inv_stride = 8'd1 << (stage_reg + 3'd1);
    wire [6:0] inv_offset = bf_cnt & (inv_stride[6:0] - 7'd1);
    wire [6:0] inv_group  = bf_cnt >> (stage_reg + 3'd1);
    wire [7:0] inv_start  = {inv_group, 1'b0} << (stage_reg + 3'd1);
    wire [7:0] inv_addr_a = inv_start + {1'b0, inv_offset};
    wire [7:0] inv_addr_b = inv_addr_a + inv_stride;
    /* verilator lint_off UNUSEDSIGNAL */
    wire [7:0] inv_k_wide = (8'd128 >> stage_reg) - 8'd1 - {1'b0, inv_group};
    /* verilator lint_on UNUSEDSIGNAL */
    wire [6:0] inv_k      = inv_k_wide[6:0];

    // Active addresses and twiddle selection
    wire [7:0] cur_addr_a = (mode_reg == 1'b0) ? fwd_addr_a : inv_addr_a;
    wire [7:0] cur_addr_b = (mode_reg == 1'b0) ? fwd_addr_b : inv_addr_b;
    wire [6:0] cur_k      = (mode_reg == 1'b0) ? fwd_k      : inv_k;

    // Twiddle Lookup from generated NTT_ZETAS_FLAT
    wire [10:0] z_bit_idx = {1'b0, cur_k, 3'b000} + {2'b00, cur_k, 2'b00}; // 12 * cur_k
    wire [11:0] cur_zeta  = NTT_ZETAS_FLAT[z_bit_idx +: 12];

    // Read Source / Write Destination based on stage parity:
    //   Even stage (0, 2, 4, 6): Read Main RAM, Write Scratch RAM
    //   Odd stage  (1, 3, 5):    Read Scratch RAM, Write Main RAM
    wire stage_is_even = ~stage_reg[0];

    // Scaling address in S_INTT_SCALE
    reg [8:0] scale_cnt;
    wire [7:0] cur_scale_addr = scale_cnt[7:0];

    // -------------------------------------------------------------------------
    // BRAM Read Latency Tracking & Butterfly Feeding Pipeline
    // -------------------------------------------------------------------------
    reg        bf_in_val;
    reg [7:0]  bf_in_addr_a;
    reg [7:0]  bf_in_addr_b;
    reg [11:0] bf_in_zeta;
    reg [1:0]  bf_in_mode;

    always @(posedge clk) begin
        if (rst) begin
            bf_in_val    <= 1'b0;
            bf_in_addr_a <= 8'd0;
            bf_in_addr_b <= 8'd0;
            bf_in_zeta   <= 12'd0;
            bf_in_mode   <= 2'd0;
        end else if (state == S_STAGE_READ) begin
            bf_in_val    <= 1'b1;
            bf_in_addr_a <= cur_addr_a;
            bf_in_addr_b <= cur_addr_b;
            bf_in_zeta   <= cur_zeta;
            bf_in_mode   <= (mode_reg == 1'b0) ? BF_MODE_CT : BF_MODE_GS;
        end else if (state == S_INTT_SCALE) begin
            bf_in_val    <= (scale_cnt < 9'd256);
            bf_in_addr_a <= cur_scale_addr;
            bf_in_addr_b <= 8'd0;
            bf_in_zeta   <= NTT_INV_N;
            bf_in_mode   <= BF_MODE_MUL;
        end else begin
            bf_in_val    <= 1'b0;
        end
    end

    // Selected operands arriving at butterfly inputs (cycle T+1)
    wire [11:0] bf_op_u = (stage_is_even || state == S_INTT_SCALE) ?
                          ((state == S_INTT_SCALE) ? scratch_a_rdata : mem_a_rdata) :
                          scratch_a_rdata;
    wire [11:0] bf_op_v = (stage_is_even) ? mem_b_rdata : scratch_b_rdata;

    // -------------------------------------------------------------------------
    // Butterfly Unit Instance (PIPE_DEPTH = 3, Latency = 4 cycles)
    // -------------------------------------------------------------------------
    wire        bf_out_val;
    wire [11:0] bf_out_u;
    wire [11:0] bf_out_v;

    butterfly #(
        .PIPE_DEPTH(PIPE_DEPTH)
    ) u_butterfly (
        .clk       (clk),
        .rst       (rst),
        .en        (bf_in_val),
        .mode      (bf_in_mode),
        .u         (bf_op_u),
        .v         (bf_op_v),
        .zeta      (bf_in_zeta),
        .valid_out (bf_out_val),
        .u_out     (bf_out_u),
        .v_out     (bf_out_v)
    );

    // -------------------------------------------------------------------------
    // Butterfly Output Write Address Pipeline (4 cycles matching butterfly)
    // -------------------------------------------------------------------------
    reg [7:0] wr_addr_a_pipe [0:3];
    reg [7:0] wr_addr_b_pipe [0:3];
    reg       wr_stage_even_pipe [0:3];
    reg       wr_is_scale_pipe [0:3];

    integer p;
    always @(posedge clk) begin
        if (rst) begin
            for (p = 0; p < 4; p = p + 1) begin
                wr_addr_a_pipe[p]     <= 8'd0;
                wr_addr_b_pipe[p]     <= 8'd0;
                wr_stage_even_pipe[p] <= 1'b0;
                wr_is_scale_pipe[p]   <= 1'b0;
            end
        end else begin
            wr_addr_a_pipe[0]     <= bf_in_addr_a;
            wr_addr_b_pipe[0]     <= bf_in_addr_b;
            wr_stage_even_pipe[0] <= stage_is_even;
            wr_is_scale_pipe[0]   <= (state == S_INTT_SCALE);
            for (p = 1; p < 4; p = p + 1) begin
                wr_addr_a_pipe[p]     <= wr_addr_a_pipe[p-1];
                wr_addr_b_pipe[p]     <= wr_addr_b_pipe[p-1];
                wr_stage_even_pipe[p] <= wr_stage_even_pipe[p-1];
                wr_is_scale_pipe[p]   <= wr_is_scale_pipe[p-1];
            end
        end
    end

    wire [7:0] active_wr_addr_a    = wr_addr_a_pipe[3];
    wire [7:0] active_wr_addr_b    = wr_addr_b_pipe[3];
    wire       active_dest_scratch = wr_stage_even_pipe[3] && !wr_is_scale_pipe[3];
    wire       active_is_scale     = wr_is_scale_pipe[3];

    // Counter for retired butterflies in stage
    reg [6:0] retired_bf_cnt;
    always @(posedge clk) begin
        if (rst || state == S_IDLE || (state == S_STAGE_DRAIN && retired_bf_cnt == 7'd127)) begin
            retired_bf_cnt <= 7'd0;
        end else if (bf_out_val && (state == S_STAGE_READ || state == S_STAGE_DRAIN)) begin
            retired_bf_cnt <= retired_bf_cnt + 7'd1;
        end
    end

    // -------------------------------------------------------------------------
    // Copy-Back State Logic (Forward NTT scratch parity correction: 256 cycles)
    // -------------------------------------------------------------------------
    reg [8:0] copy_cnt;
    reg [7:0] copy_addr_delayed;
    reg       copy_val_delayed;

    always @(posedge clk) begin
        if (rst || state != S_COPY_BACK) begin
            copy_cnt          <= 9'd0;
            copy_addr_delayed <= 8'd0;
            copy_val_delayed  <= 1'b0;
        end else begin
            if (copy_cnt < 9'd256) begin
                copy_cnt <= copy_cnt + 9'd1;
            end
            copy_addr_delayed <= copy_cnt[7:0];
            copy_val_delayed  <= (copy_cnt < 9'd256);
        end
    end

    // -------------------------------------------------------------------------
    // INTT Scaling Stage Counter (256 coefficients scaled by INV_N)
    // -------------------------------------------------------------------------
    reg [8:0] retired_scale_cnt;

    always @(posedge clk) begin
        if (rst || state != S_INTT_SCALE) begin
            scale_cnt         <= 9'd0;
            retired_scale_cnt <= 9'd0;
        end else begin
            if (scale_cnt < 9'd256) begin
                scale_cnt <= scale_cnt + 9'd1;
            end
            if (bf_out_val) begin
                retired_scale_cnt <= retired_scale_cnt + 9'd1;
            end
        end
    end

    // -------------------------------------------------------------------------
    // Main Control FSM
    // -------------------------------------------------------------------------
    reg done_r;

    always @(posedge clk) begin
        if (rst) begin
            state     <= S_IDLE;
            mode_reg  <= 1'b0;
            stage_reg <= 3'd0;
            bf_cnt    <= 7'd0;
            done_r    <= 1'b0;
        end else begin
            done_r <= 1'b0;
            case (state)
                S_IDLE: begin
                    if (start) begin
                        mode_reg  <= mode;
                        stage_reg <= 3'd0;
                        bf_cnt    <= 7'd0;
                        state     <= S_STAGE_READ;
                    end
                end

                S_STAGE_READ: begin
                    if (bf_cnt == 7'd127) begin
                        bf_cnt <= 7'd0;
                        state  <= S_STAGE_DRAIN;
                    end else begin
                        bf_cnt <= bf_cnt + 7'd1;
                    end
                end

                S_STAGE_DRAIN: begin
                    if (retired_bf_cnt == 7'd127 && bf_out_val) begin
                        if (stage_reg < 3'd6) begin
                            stage_reg <= stage_reg + 3'd1;
                            bf_cnt    <= 7'd0;
                            state     <= S_STAGE_READ;
                        end else begin
                            // Stage 6 complete!
                            if (mode_reg == 1'b0) begin
                                // Forward NTT ends in Scratch -> copy back to Main RAM
                                state <= S_COPY_BACK;
                            end else begin
                                // INTT ends in Scratch -> scale from Scratch to Main RAM
                                state <= S_INTT_SCALE;
                            end
                        end
                    end
                end

                S_COPY_BACK: begin
                    // After 256 read cycles + 1 read delay, all 256 words are written
                    if (copy_cnt >= 9'd256 && !copy_val_delayed) begin
                        state <= S_DONE;
                    end
                end

                S_INTT_SCALE: begin
                    if (retired_scale_cnt == 9'd255 && bf_out_val) begin
                        state <= S_DONE;
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

    // -------------------------------------------------------------------------
    // Memory Port Multiplexing
    // -------------------------------------------------------------------------
    // Main RAM Port A:
    assign mem_a_addr = (state == S_COPY_BACK)  ? copy_addr_delayed :
                        (copy_val_delayed)      ? copy_addr_delayed :
                        (bf_out_val && (!active_dest_scratch || active_is_scale)) ? active_wr_addr_a :
                        cur_addr_a;

    assign mem_a_we   = copy_val_delayed || (bf_out_val && (!active_dest_scratch || active_is_scale));
    assign mem_a_wdata = copy_val_delayed ? scratch_a_rdata : bf_out_u;

    // Main RAM Port B:
    assign mem_b_addr = (bf_out_val && !active_dest_scratch && !active_is_scale) ? active_wr_addr_b : cur_addr_b;
    assign mem_b_we   = bf_out_val && !active_dest_scratch && !active_is_scale;
    assign mem_b_wdata = bf_out_v;

    // Scratch RAM Addressing:
    always @(*) begin
        if (state == S_COPY_BACK) begin
            scratch_a_addr  = copy_cnt[7:0];
            scratch_a_we    = 1'b0;
            scratch_a_wdata = 12'd0;
            scratch_b_addr  = 8'd0;
            scratch_b_we    = 1'b0;
            scratch_b_wdata = 12'd0;
        end else if (state == S_INTT_SCALE) begin
            scratch_a_addr  = cur_scale_addr;
            scratch_a_we    = 1'b0;
            scratch_a_wdata = 12'd0;
            scratch_b_addr  = 8'd0;
            scratch_b_we    = 1'b0;
            scratch_b_wdata = 12'd0;
        end else begin
            // Normal butterfly stage
            if (bf_out_val && active_dest_scratch) begin
                scratch_a_addr  = active_wr_addr_a;
                scratch_a_we    = 1'b1;
                scratch_a_wdata = bf_out_u;
                scratch_b_addr  = active_wr_addr_b;
                scratch_b_we    = 1'b1;
                scratch_b_wdata = bf_out_v;
            end else begin
                scratch_a_addr  = cur_addr_a;
                scratch_a_we    = 1'b0;
                scratch_a_wdata = 12'd0;
                scratch_b_addr  = cur_addr_b;
                scratch_b_we    = 1'b0;
                scratch_b_wdata = 12'd0;
            end
        end
    end

    // Status Signals
    assign busy = (state != S_IDLE);
    assign done = done_r;

endmodule

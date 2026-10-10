//==========================================================================
// rtl/crypto/ntt/butterfly.v
//
// Unified Butterfly Unit for ML-KEM-512 NTT / INTT Core.
// Bit-exact synthesizable RTL twin of model/mlkem/ntt.py.
//
// Supported Modes:
//   MODE_CT  (2'b00): Forward Cooley-Tukey butterfly:
//                     t = (v * zeta) mod q
//                     u' = (u + t) mod q
//                     v' = (u - t) mod q
//   MODE_GS  (2'b01): Inverse Gentleman-Sande butterfly:
//                     u' = (u + v) mod q
//                     diff = (v - u) mod q
//                     v' = (diff * zeta) mod q
//   MODE_MUL (2'b10): Scalar modular multiplication (for INTT scaling INV_N):
//                     u' = (u * zeta) mod q
//                     v' = 0
//
// Timing & Resource Estimates (XC7Z020 @ 100 MHz, estimated, pre-synthesis):
//   Latency: PIPE_DEPTH + 1 = 4 clock cycles (constant-time across all modes)
//   Throughput: 1 butterfly retired per cycle (fully pipelined)
//   DSP48E1: 1 slice (inside instantiated modmul.v)
//   Slice LUTs: ~150-180 LUTs total (modmul + modular add/sub trees)
//   Slice FFs: ~120 registers
//==========================================================================

`timescale 1ns / 1ps

module butterfly #(
    parameter integer PIPE_DEPTH = 3
) (
    input  wire        clk,
    input  wire        rst,
    input  wire        en,
    input  wire [1:0]  mode,      // 00: CT (NTT), 01: GS (INTT), 10: MUL
    input  wire [11:0] u,         // Primary input coefficient in [0, 3328]
    input  wire [11:0] v,         // Secondary input coefficient in [0, 3328]
    input  wire [11:0] zeta,      // Twiddle factor in [0, 3328]
    output wire        valid_out, // Valid 4 cycles after en
    output wire [11:0] u_out,     // Primary output coefficient in [0, 3328]
    output wire [11:0] v_out      // Secondary output coefficient in [0, 3328]
);

    localparam [11:0] Q = 12'd3329;

    localparam [1:0] MODE_CT  = 2'b00;
    localparam [1:0] MODE_GS  = 2'b01;
    localparam [1:0] MODE_MUL = 2'b10;

    // -------------------------------------------------------------------------
    // Input Pre-processing for GS Mode (Single-cycle Combinational before modmul)
    // -------------------------------------------------------------------------
    // In GS mode: u' = (u + v) mod Q, diff = (v - u) mod Q
    wire [12:0] sum_uv_raw = {1'b0, u} + {1'b0, v};
    wire [11:0] sum_uv     = (sum_uv_raw >= {1'b0, Q}) ? (sum_uv_raw[11:0] - Q) : sum_uv_raw[11:0];

    wire [11:0] diff_vu    = (v >= u) ? (v - u) : (v + Q - u);

    // Multiplex modmul inputs based on mode:
    //   MODE_CT:  modmul(v, zeta)
    //   MODE_GS:  modmul(diff_vu, zeta)
    //   MODE_MUL: modmul(u, zeta)
    reg [11:0] mul_op_a;
    always @(*) begin
        case (mode)
            MODE_CT:  mul_op_a = v;
            MODE_GS:  mul_op_a = diff_vu;
            MODE_MUL: mul_op_a = u;
            default:  mul_op_a = u;
        endcase
    end

    // -------------------------------------------------------------------------
    // Core Modular Multiplier (Latency = PIPE_DEPTH = 3 cycles)
    // -------------------------------------------------------------------------
    wire        mul_valid;
    wire [11:0] mul_res;

    modmul #(
        .PIPE_DEPTH(PIPE_DEPTH)
    ) u_modmul (
        .clk       (clk),
        .rst       (rst),
        .en        (en),
        .a         (mul_op_a),
        .b         (zeta),
        .valid_out (mul_valid),
        .res       (mul_res)
    );

    // -------------------------------------------------------------------------
    // Pipeline Delay Registers for Passthrough Operands (3 cycles matching modmul)
    // -------------------------------------------------------------------------
    reg [11:0] u_pipe [0:PIPE_DEPTH-1];
    reg [11:0] gs_sum_pipe [0:PIPE_DEPTH-1];
    reg [1:0]  mode_pipe [0:PIPE_DEPTH-1];

    integer i;
    always @(posedge clk) begin
        if (rst) begin
            for (i = 0; i < PIPE_DEPTH; i = i + 1) begin
                u_pipe[i]      <= 12'd0;
                gs_sum_pipe[i] <= 12'd0;
                mode_pipe[i]   <= 2'd0;
            end
        end else begin
            u_pipe[0]      <= u;
            gs_sum_pipe[0] <= sum_uv;
            mode_pipe[0]   <= mode;
            for (i = 1; i < PIPE_DEPTH; i = i + 1) begin
                u_pipe[i]      <= u_pipe[i-1];
                gs_sum_pipe[i] <= gs_sum_pipe[i-1];
                mode_pipe[i]   <= mode_pipe[i-1];
            end
        end
    end

    // Operands aligned with mul_res at cycle 3
    wire [11:0] u_delayed    = u_pipe[PIPE_DEPTH-1];
    wire [11:0] gs_delayed   = gs_sum_pipe[PIPE_DEPTH-1];
    wire [1:0]  mode_delayed = mode_pipe[PIPE_DEPTH-1];

    // -------------------------------------------------------------------------
    // Post-processing & Output Registration (Stage 4)
    // -------------------------------------------------------------------------
    // For CT mode:
    //   u' = (u_delayed + mul_res) mod Q
    //   v' = (u_delayed - mul_res) mod Q
    wire [12:0] ct_sum_raw = {1'b0, u_delayed} + {1'b0, mul_res};
    wire [11:0] ct_u_out   = (ct_sum_raw >= {1'b0, Q}) ? (ct_sum_raw[11:0] - Q) : ct_sum_raw[11:0];
    wire [11:0] ct_v_out   = (u_delayed >= mul_res) ? (u_delayed - mul_res) : (u_delayed + Q - mul_res);

    reg [11:0] u_out_r;
    reg [11:0] v_out_r;
    reg        val_out_r;

    always @(posedge clk) begin
        if (rst) begin
            u_out_r   <= 12'd0;
            v_out_r   <= 12'd0;
            val_out_r <= 1'b0;
        end else begin
            val_out_r <= mul_valid;
            if (mul_valid) begin
                case (mode_delayed)
                    MODE_CT: begin
                        u_out_r <= ct_u_out;
                        v_out_r <= ct_v_out;
                    end
                    MODE_GS: begin
                        u_out_r <= gs_delayed;
                        v_out_r <= mul_res;
                    end
                    MODE_MUL: begin
                        u_out_r <= mul_res;
                        v_out_r <= 12'd0;
                    end
                    default: begin
                        u_out_r <= mul_res;
                        v_out_r <= 12'd0;
                    end
                endcase
            end
        end
    end

    assign valid_out = val_out_r;
    assign u_out     = u_out_r;
    assign v_out     = v_out_r;

endmodule

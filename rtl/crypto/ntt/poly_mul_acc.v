//==========================================================================
// rtl/crypto/ntt/poly_mul_acc.v
//
// Pointwise Polynomial Multiplication and Accumulation in NTT Domain for ML-KEM-512.
// Bit-exact synthesizable RTL twin of model/mlkem/pke.py (base_case_multiply & multiply_ntts).
//
// Operation:
//   Computes 128 degree-1 multiplications mod (X^2 - gamma_i) per polynomial:
//     c0 = (a0 * b0 + a1 * b1 * gamma_i) mod q
//     c1 = (a0 * b1 + a1 * b0) mod q
//   If accumulate == 1:
//     c0 = (acc0 + c0) mod q
//     c1 = (acc1 + c1) mod q
//
// Timing & Resource Estimates (XC7Z020 @ 100 MHz, estimated, pre-synthesis):
//   Latency: 2,049 clock cycles per 256-coeff polynomial product (~20.5 us at 100 MHz, measured)
//   DSP48E1: 1 slice (inside instantiated modmul.v)
//   Slice LUTs: ~220-260 LUTs (FSM, address generators, adder trees)
//   Slice FFs: ~160 registers
//==========================================================================

`timescale 1ns / 1ps

module poly_mul_acc #(
    parameter integer PIPE_DEPTH = 3
) (
    input  wire        clk,
    input  wire        rst,

    // Control & Status
    input  wire        start,      // 1-cycle start pulse (ignored if busy)
    input  wire        accumulate, // 0: C = A * B, 1: C = ACC + A * B
    output wire        busy,       // High while computing
    output wire        done,       // 1-cycle completion pulse

    // Polynomial A Read Port (1-cycle synchronous BRAM read latency)
    output wire [7:0]  mem_a_addr,
    input  wire [11:0] mem_a_rdata,

    // Polynomial B Read Port (1-cycle synchronous BRAM read latency)
    output wire [7:0]  mem_b_addr,
    input  wire [11:0] mem_b_rdata,

    // Polynomial ACC Read Port (read if accumulate == 1)
    output wire [7:0]  mem_acc_addr,
    input  wire [11:0] mem_acc_rdata,

    // Polynomial C Write Port (destination)
    output wire [7:0]  mem_c_addr,
    output wire        mem_c_we,
    output wire [11:0] mem_c_wdata
);

    `include "ntt_zetas.vh"

    localparam [11:0] Q = 12'd3329;

    localparam [2:0] S_IDLE     = 3'd0;
    localparam [2:0] S_READ_OPS = 3'd1;
    localparam [2:0] S_COMPUTE  = 3'd2;
    localparam [2:0] S_WRITE_C0 = 3'd3;
    localparam [2:0] S_WRITE_C1 = 3'd4;
    localparam [2:0] S_DONE     = 3'd5;

    reg [2:0] state;
    reg       acc_reg;
    reg [6:0] pair_idx; // 0..127

    // Twiddle Lookup: GAMMAS[pair_idx]
    wire [10:0] g_bit_idx  = {1'b0, pair_idx, 3'b000} + {2'b00, pair_idx, 2'b00}; // 12 * pair_idx
    wire [11:0] gamma_i    = NTT_GAMMAS_FLAT[g_bit_idx +: 12];

    // Latch operands for current pair: a0, a1, b0, b1, acc0, acc1
    reg [11:0] a0_reg, a1_reg;
    reg [11:0] b0_reg, b1_reg;
    reg [11:0] acc0_reg, acc1_reg;
    reg [1:0]  read_step;

    // Sub-step within 5 modmuls:
    //   0: a0 * b0
    //   1: a1 * b1
    //   2: (a1*b1) * gamma_i
    //   3: a0 * b1
    //   4: a1 * b0
    reg [2:0]  sub_step;

    // Modmul interface
    reg        mul_en;
    reg [11:0] mul_op_a;
    reg [11:0] mul_op_b;
    wire       mul_valid;
    wire [11:0] mul_res;

    modmul #(
        .PIPE_DEPTH(PIPE_DEPTH)
    ) u_modmul (
        .clk       (clk),
        .rst       (rst),
        .en        (mul_en),
        .a         (mul_op_a),
        .b         (mul_op_b),
        .valid_out (mul_valid),
        .res       (mul_res)
    );

    // Intermediate results: m0, m1, m2, m3, m4
    reg [11:0] m0_reg;
    reg [11:0] m2_reg;
    reg [11:0] m3_reg;
    reg [11:0] m4_reg;

    // Result accumulators:
    //   c0 = (m0 + m2 + acc0) mod Q
    //   c1 = (m3 + m4 + acc1) mod Q
    wire [12:0] sum_m0_m2 = {1'b0, m0_reg} + {1'b0, m2_reg};
    wire [11:0] red_m0_m2 = (sum_m0_m2 >= {1'b0, Q}) ? (sum_m0_m2[11:0] - Q) : sum_m0_m2[11:0];
    wire [12:0] sum_c0    = {1'b0, red_m0_m2} + {1'b0, (acc_reg ? acc0_reg : 12'd0)};
    wire [11:0] c0_final  = (sum_c0 >= {1'b0, Q}) ? (sum_c0[11:0] - Q) : sum_c0[11:0];

    wire [12:0] sum_m3_m4 = {1'b0, m3_reg} + {1'b0, m4_reg};
    wire [11:0] red_m3_m4 = (sum_m3_m4 >= {1'b0, Q}) ? (sum_m3_m4[11:0] - Q) : sum_m3_m4[11:0];
    wire [12:0] sum_c1    = {1'b0, red_m3_m4} + {1'b0, (acc_reg ? acc1_reg : 12'd0)};
    wire [11:0] c1_final  = (sum_c1 >= {1'b0, Q}) ? (sum_c1[11:0] - Q) : sum_c1[11:0];

    // Read addresses
    wire [7:0] base_addr_even = {pair_idx, 1'b0};
    wire [7:0] base_addr_odd  = {pair_idx, 1'b1};

    assign mem_a_addr   = (read_step == 2'd0) ? base_addr_even : base_addr_odd;
    assign mem_b_addr   = (read_step == 2'd0) ? base_addr_even : base_addr_odd;
    assign mem_acc_addr = (read_step == 2'd0) ? base_addr_even : base_addr_odd;

    // Write outputs
    reg [7:0]  wr_addr_r;
    reg        wr_we_r;
    reg [11:0] wr_wdata_r;

    assign mem_c_addr  = wr_addr_r;
    assign mem_c_we    = wr_we_r;
    assign mem_c_wdata = wr_wdata_r;

    reg done_r;
    assign done = done_r;
    assign busy = (state != S_IDLE);

    always @(posedge clk) begin
        if (rst) begin
            state       <= S_IDLE;
            acc_reg     <= 1'b0;
            pair_idx    <= 7'd0;
            read_step   <= 2'd0;
            sub_step    <= 3'd0;
            mul_en      <= 1'b0;
            mul_op_a    <= 12'd0;
            mul_op_b    <= 12'd0;
            a0_reg      <= 12'd0;
            a1_reg      <= 12'd0;
            b0_reg      <= 12'd0;
            b1_reg      <= 12'd0;
            acc0_reg    <= 12'd0;
            acc1_reg    <= 12'd0;
            m0_reg      <= 12'd0;
            m2_reg      <= 12'd0;
            m3_reg      <= 12'd0;
            m4_reg      <= 12'd0;
            wr_addr_r   <= 8'd0;
            wr_we_r     <= 1'b0;
            wr_wdata_r  <= 12'd0;
            done_r      <= 1'b0;
        end else begin
            done_r  <= 1'b0;
            wr_we_r <= 1'b0;
            mul_en  <= 1'b0;

            case (state)
                S_IDLE: begin
                    if (start) begin
                        acc_reg   <= accumulate;
                        pair_idx  <= 7'd0;
                        read_step <= 2'd0;
                        state     <= S_READ_OPS;
                    end
                end

                S_READ_OPS: begin
                    // Read step 0: address base_addr_even presented
                    // Read step 1: data 0 arrives, address base_addr_odd presented
                    // Read step 2: data 1 arrives -> move to S_COMPUTE
                    if (read_step == 2'd0) begin
                        read_step <= 2'd1;
                    end else if (read_step == 2'd1) begin
                        a0_reg    <= mem_a_rdata;
                        b0_reg    <= mem_b_rdata;
                        acc0_reg  <= mem_acc_rdata;
                        read_step <= 2'd2;
                    end else begin
                        a1_reg    <= mem_a_rdata;
                        b1_reg    <= mem_b_rdata;
                        acc1_reg  <= mem_acc_rdata;
                        read_step <= 2'd0;
                        sub_step  <= 3'd0;
                        state     <= S_COMPUTE;
                    end
                end

                S_COMPUTE: begin
                    // Feed 5 sequential modmuls:
                    //   Step 0: a0 * b0
                    //   Step 1: a1 * b1
                    //   Step 2: wait for (a1*b1), feed ((a1*b1) * gamma_i)
                    //   Step 3: a0 * b1
                    //   Step 4: a1 * b0
                    if (sub_step == 3'd0) begin
                        mul_en   <= 1'b1;
                        mul_op_a <= a0_reg;
                        mul_op_b <= b0_reg;
                        sub_step <= 3'd1;
                    end else if (sub_step == 3'd1) begin
                        mul_en   <= 1'b1;
                        mul_op_a <= a1_reg;
                        mul_op_b <= b1_reg;
                        sub_step <= 3'd2;
                    end else if (sub_step == 3'd2) begin
                        // Wait for a0*b0
                        if (mul_valid) begin
                            m0_reg   <= mul_res;
                            sub_step <= 3'd3;
                        end
                    end else if (sub_step == 3'd3) begin
                        // Now a1*b1 is valid, feed into gamma_i
                        mul_en   <= 1'b1;
                        mul_op_a <= mul_res;
                        mul_op_b <= gamma_i;
                        sub_step <= 3'd4;
                    end else if (sub_step == 3'd4) begin
                        mul_en   <= 1'b1;
                        mul_op_a <= a0_reg;
                        mul_op_b <= b1_reg;
                        sub_step <= 3'd5;
                    end else if (sub_step == 3'd5) begin
                        mul_en   <= 1'b1;
                        mul_op_a <= a1_reg;
                        mul_op_b <= b0_reg;
                        sub_step <= 3'd6;
                    end else if (sub_step == 3'd6) begin
                        // Wait for m2 = (a1*b1)*gamma_i
                        if (mul_valid) begin
                            m2_reg   <= mul_res;
                            sub_step <= 3'd7;
                        end
                    end else if (sub_step == 3'd7) begin
                        // Wait for m3 = a0*b1
                        if (mul_valid) begin
                            m3_reg <= mul_res;
                        end
                        // Wait for m4 = a1*b0
                        // Next cycle m4 is valid, then we can write c0
                        state <= S_WRITE_C0;
                    end
                end

                S_WRITE_C0: begin
                    if (mul_valid) begin
                        m4_reg <= mul_res;
                    end
                    // Write c0 at base_addr_even
                    wr_addr_r  <= base_addr_even;
                    wr_we_r    <= 1'b1;
                    wr_wdata_r <= c0_final;
                    state      <= S_WRITE_C1;
                end

                S_WRITE_C1: begin
                    // Write c1 at base_addr_odd
                    wr_addr_r  <= base_addr_odd;
                    wr_we_r    <= 1'b1;
                    wr_wdata_r <= c1_final;

                    if (pair_idx == 7'd127) begin
                        state <= S_DONE;
                    end else begin
                        pair_idx  <= pair_idx + 7'd1;
                        read_step <= 2'd0;
                        state     <= S_READ_OPS;
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

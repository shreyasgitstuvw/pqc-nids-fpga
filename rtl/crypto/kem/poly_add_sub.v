//==========================================================================
// rtl/crypto/kem/poly_add_sub.v
//
// Modular Polynomial Addition and Subtraction Unit for ML-KEM-512 (q = 3329).
// Supports coefficient-wise streaming modular arithmetic over Z_q:
//   MODE_ADD  (2'b00): R = (A + B) mod 3329
//   MODE_SUB  (2'b01): R = (A - B) mod 3329
//   MODE_ADD3 (2'b10): R = (A + B + C) mod 3329  (for INTT(v) + e2 + mu)
//
// Protocol & Architecture:
//   - Autonomous 256-coefficient sequencer with 1-cycle BRAM read latency.
//   - On 1-cycle 'start' pulse, iterates rd_addr from 0 to 255.
//   - Reads rdata_a, rdata_b, rdata_c from dual-port Polynomial RAM banks.
//   - 1-cycle registered pipelined arithmetic datapath mod 3329.
//   - Emits wr_we, wr_addr (0..255), wr_data to destination RAM bank.
//   - Asserts 1-cycle 'done' pulse at completion.
//
// Timing & Resource Estimates (XC7Z020 @ 100 MHz, estimated, pre-synthesis):
//   - Latency: exactly 259 clock cycles per polynomial (256 stream + 3 pipeline latency, backed by assert in test_poly_add_sub.py)
//   - DSP48E1: 0 slices (estimated, pre-synthesis)
//   - Slice LUTs: ~45-65 LUTs (estimated, pre-synthesis)
//   - Slice FFs: ~40-55 registers (estimated, pre-synthesis)
//==========================================================================

`timescale 1ns / 1ps

module poly_add_sub (
    input  wire        clk,
    input  wire        rst,

    // Control & Status
    input  wire        start,      // 1-cycle start pulse (ignored if busy)
    input  wire [1:0]  mode,       // 00: ADD (A+B), 01: SUB (A-B), 10: ADD3 (A+B+C)
    output wire        busy,       // Active while processing 256 coefficients
    output wire        done,       // 1-cycle completion pulse

    // Polynomial RAM Read Port (Address issued to BRAM; data valid next cycle)
    output reg  [7:0]  rd_addr,
    input  wire [11:0] rdata_a,
    input  wire [11:0] rdata_b,
    input  wire [11:0] rdata_c,

    // Polynomial RAM Write Port (to destination RAM bank)
    output reg  [7:0]  wr_addr,
    output reg         wr_we,
    output reg  [11:0] wr_data
);

    localparam [11:0] Q  = 12'd3329;
    localparam [12:0] Q2 = 13'd6658;

    localparam [1:0] MODE_ADD  = 2'd0;
    localparam [1:0] MODE_SUB  = 2'd1;
    localparam [1:0] MODE_ADD3 = 2'd2;

    localparam [1:0] S_IDLE = 2'd0;
    localparam [1:0] S_RUN  = 2'd1;
    localparam [1:0] S_DONE = 2'd2;

    reg [1:0] state;
    reg [1:0] mode_r;
    reg [8:0] rd_cnt;

    // Pipeline tracking for 2-stage latency (BRAM read + arithmetic register)
    reg [1:0] pipe_valid;
    reg [7:0] pipe_addr_0;

    reg       done_r;

    assign busy = (state != S_IDLE);
    assign done = done_r;

    // -------------------------------------------------------------------------
    // Combinational Modular Arithmetic on incoming BRAM data
    // -------------------------------------------------------------------------
    // 1. Two-operand addition: (a + b) mod Q
    wire [12:0] sum2_raw = {1'b0, rdata_a} + {1'b0, rdata_b};
    wire [11:0] sum2_res = (sum2_raw >= {1'b0, Q}) ? (sum2_raw[11:0] - Q) : sum2_raw[11:0];

    // 2. Two-operand subtraction: (a - b) mod Q
    wire [11:0] sub_res  = (rdata_a >= rdata_b) ? (rdata_a - rdata_b) : (rdata_a + Q - rdata_b);

    // 3. Three-operand addition: (a + b + c) mod Q
    wire [13:0] sum3_raw = {2'b00, rdata_a} + {2'b00, rdata_b} + {2'b00, rdata_c};
    reg  [11:0] sum3_res;
    always @(*) begin
        if (sum3_raw >= {1'b0, Q2})
            sum3_res = sum3_raw[11:0] - Q2[11:0];
        else if (sum3_raw >= {2'b00, Q})
            sum3_res = sum3_raw[11:0] - Q;
        else
            sum3_res = sum3_raw[11:0];
    end

    // Selected result multiplexer
    reg [11:0] arith_res;
    always @(*) begin
        case (mode_r)
            MODE_ADD:  arith_res = sum2_res;
            MODE_SUB:  arith_res = sub_res;
            MODE_ADD3: arith_res = sum3_res;
            default:   arith_res = sum2_res;
        endcase
    end

    // -------------------------------------------------------------------------
    // Sequential Control & Pipeline Datapath
    // -------------------------------------------------------------------------
    always @(posedge clk) begin
        if (rst) begin
            state       <= S_IDLE;
            mode_r      <= MODE_ADD;
            rd_cnt      <= 9'd0;
            rd_addr     <= 8'd0;
            pipe_valid  <= 2'd0;
            pipe_addr_0 <= 8'd0;
            wr_addr     <= 8'd0;
            wr_we       <= 1'b0;
            wr_data     <= 12'd0;
            done_r      <= 1'b0;
        end else begin
            done_r <= 1'b0;

            case (state)
                S_IDLE: begin
                    pipe_valid <= 2'd0;
                    wr_we      <= 1'b0;
                    if (start) begin
                        state       <= S_RUN;
                        mode_r      <= mode;
                        rd_cnt      <= 9'd1;
                        rd_addr     <= 8'd0;
                        pipe_valid  <= 2'b01; // Stage 0 active
                        pipe_addr_0 <= 8'd0;
                    end
                end

                S_RUN: begin
                    // Read Address Generation (cycles 0..255)
                    if (rd_cnt < 9'd256) begin
                        rd_addr    <= rd_cnt[7:0];
                        rd_cnt     <= rd_cnt + 9'd1;
                        pipe_valid <= {pipe_valid[0], 1'b1};
                    end else begin
                        pipe_valid <= {pipe_valid[0], 1'b0};
                    end

                    // Pipeline Address Tracking
                    pipe_addr_0 <= rd_addr;

                    // Pipeline Write Stage (latches arithmetic result)
                    wr_we   <= pipe_valid[1];
                    wr_addr <= pipe_addr_0;
                    wr_data <= arith_res;

                    // When final coefficient (255) is in write stage, transition to S_DONE
                    if (pipe_valid[1] && (pipe_addr_0 == 8'd255)) begin
                        state <= S_DONE;
                    end
                end

                S_DONE: begin
                    wr_we  <= 1'b0;
                    done_r <= 1'b1;
                    state  <= S_IDLE;
                end

                default: state <= S_IDLE;
            endcase
        end
    end

endmodule

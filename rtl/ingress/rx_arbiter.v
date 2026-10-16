//==============================================================================
// rtl/ingress/rx_arbiter.v
//
// Merges two uart_rx byte streams (A = legitimate sender, B = attacker) into the
// ONE byte stream deframer.v expects, one whole frame at a time.
//
//   A uart_rx -> rx_frame_buf -+
//                              +--> round-robin --> paced drain --> deframer
//   B uart_rx -> rx_frame_buf -+
//
// PACING
//   Everything downstream (deframer watchdog, parser, aead_framer, the inspection
//   setup time measured at ~50 cycles) was built and measured against a byte
//   arriving every 10 bit-times. The drain therefore emits one byte every PACE
//   cycles, PACE = floor(10 * CLK_HZ / BAUD_RATE) = 333 at 100 MHz / 3 Mbaud, the
//   UART's own byte time (333.33) rounded DOWN. Rounding up would make the drain
//   0.3% slower than a back-to-back stream and frames would pile up; rounded
//   down, a flood from one source never accumulates lag. The deframer cannot tell
//   the arbiter from a single uart_rx.
//
// CAPACITY
//   The drain runs at ONE link's rate. Two sources both sending at line rate
//   for a sustained period offer twice what can leave; the four-slot buffers
//   absorb bursts, and anything beyond that is counted in drop_a/drop_b and
//   surfaces as the overflow bit in telemetry. It is never lost silently.
//
// FAIRNESS
//   Round robin by frame. A flood on B cannot starve A: when both have a frame
//   ready they alternate. (Strict priority to A would hide the flood from the
//   telemetry; fairness keeps the attack visible and the sender alive.)
//
// TRUNCATED FRAMES
//   rx_frame_buf commits a frame that went quiet mid-frame, flagged trunc. The
//   deframer would then wait out its own watchdog (DEFRAMER_TIMEOUT) and report
//   RC_FRAME_TIMEOUT. The arbiter must not feed it the next frame during that
//   wait, or those bytes would be swallowed as the tail of the truncated frame.
//   So after a trunc frame it holds the output idle for DEFRAMER_TIMEOUT + 16.
//
// Owner: Member C (integration). Verilog-2001, single clock, sync active-high rst.
//==============================================================================

`timescale 1ns / 1ps

module rx_arbiter #(
    parameter integer CLK_HZ           = 100_000_000,
    parameter integer BAUD_RATE        = 3_000_000,
    parameter integer DEFRAMER_TIMEOUT = 50000,    // deframer.v TIMEOUT_CYCLES
    parameter integer IDLE_TO          = 50000,    // mid-frame idle before commit
    parameter integer AW               = 10
) (
    input  wire        clk,
    input  wire        rst,

    input  wire        a_valid,
    input  wire [7:0]  a_data,
    input  wire        b_valid,
    input  wire [7:0]  b_data,

    output reg         out_valid,
    output reg  [7:0]  out_data,

    output wire [15:0] drop_a,        // frames not stored, source A
    output wire [15:0] drop_b,        // frames not stored, source B
    output reg  [15:0] fwd_a,         // frames forwarded from A
    output reg  [15:0] fwd_b,         // frames forwarded from B
    output reg         drop_sticky    // any frame ever lost to a full buffer
);

    localparam integer PACE_I = (10 * CLK_HZ) / BAUD_RATE;   // floor: drain never slower than the wire
    localparam [15:0]  PACE_M1 = PACE_I[15:0] - 16'd1;
    localparam integer HOLD_I = DEFRAMER_TIMEOUT + 16;
    localparam [31:0]  HOLD   = HOLD_I[31:0];

    wire          a_ready, b_ready, a_trunc, b_trunc;
    wire [10:0]   a_len, b_len;
    wire [7:0]    a_rd, b_rd;
    reg  [AW-1:0] rd_addr;
    wire          a_pop, b_pop;

    rx_frame_buf #(.AW(AW), .IDLE_TO(IDLE_TO)) u_buf_a (
        .clk(clk), .rst(rst), .in_valid(a_valid), .in_data(a_data),
        .rd_ready(a_ready), .rd_len(a_len), .rd_trunc(a_trunc),
        .rd_addr(rd_addr), .rd_data(a_rd), .rd_pop(a_pop), .drop_cnt(drop_a)
    );
    rx_frame_buf #(.AW(AW), .IDLE_TO(IDLE_TO)) u_buf_b (
        .clk(clk), .rst(rst), .in_valid(b_valid), .in_data(b_data),
        .rd_ready(b_ready), .rd_len(b_len), .rd_trunc(b_trunc),
        .rd_addr(rd_addr), .rd_data(b_rd), .rd_pop(b_pop), .drop_cnt(drop_b)
    );

    localparam [1:0] S_IDLE = 2'd0, S_SEND = 2'd1, S_DONE = 2'd2, S_HOLD = 2'd3;
    reg  [1:0]  st;
    reg         sel;          // 0 = A, 1 = B
    reg         last;         // last source granted
    reg  [10:0] len, idx;
    reg         trunc_r;
    reg  [15:0] pace;
    reg  [31:0] hold;

    assign a_pop = (st == S_DONE) && !sel;
    assign b_pop = (st == S_DONE) &&  sel;

    wire pick = (a_ready && b_ready) ? ~last : b_ready;

    always @(posedge clk) begin
        out_valid <= 1'b0;
        if (rst) begin
            st <= S_IDLE; sel <= 1'b0; last <= 1'b1; len <= 11'd0; idx <= 11'd0;
            trunc_r <= 1'b0; pace <= 16'd0; hold <= 32'd0; rd_addr <= {AW{1'b0}};
            out_data <= 8'd0; fwd_a <= 16'd0; fwd_b <= 16'd0; drop_sticky <= 1'b0;
        end else begin
            if ((drop_a != 16'd0) || (drop_b != 16'd0)) drop_sticky <= 1'b1;

            case (st)
            S_IDLE: begin
                if (a_ready || b_ready) begin
                    sel     <= pick;
                    last    <= pick;
                    len     <= pick ? b_len   : a_len;
                    trunc_r <= pick ? b_trunc : a_trunc;
                    idx     <= 11'd0;
                    pace    <= 16'd0;
                    st      <= S_SEND;
                end
            end

            S_SEND: begin
                pace <= pace + 16'd1;
                if (pace == 16'd0) rd_addr <= idx[AW-1:0];
                if (pace == PACE_M1) begin
                    out_valid <= 1'b1;
                    out_data  <= sel ? b_rd : a_rd;
                    idx       <= idx + 11'd1;
                    pace      <= 16'd0;
                    if (idx + 11'd1 == len) st <= S_DONE;
                end
            end

            S_DONE: begin
                if (sel) fwd_b <= fwd_b + 16'd1; else fwd_a <= fwd_a + 16'd1;
                if (trunc_r) begin
                    hold <= HOLD;
                    st   <= S_HOLD;
                end else begin
                    st <= S_IDLE;
                end
            end

            S_HOLD: begin
                hold <= hold - 32'd1;
                if (hold == 32'd1) st <= S_IDLE;
            end
            endcase
        end
    end

endmodule

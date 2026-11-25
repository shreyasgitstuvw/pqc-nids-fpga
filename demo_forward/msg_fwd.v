//==============================================================================
// demo_forward/msg_fwd.v   (proposed, NOT yet in the main build)
//
// Delivery port. Holds the decrypted payload of one DATA packet until the drop
// engine has delivered its verdict, then:
//   pass -> streams the payload (plus CR LF) out a UART to Device B
//   fail -> discards it; nothing ever leaves the board
//
// Why store-and-forward: chacha_poly emits plaintext before the Poly1305 tag and
// the detector verdicts are known, so releasing bytes as they appear would
// deliver messages that are later condemned.
//
// Limits (counted, never silent):
//   - one message buffered at a time; a new pt_sof while the previous message is
//     still being sent is counted in cnt_lost
//   - payloads longer than DEPTH are discarded (cnt_oversize)
//==============================================================================
`timescale 1ns / 1ps

module msg_fwd #(
    parameter DEPTH = 512,
    parameter AW    = 9,
    parameter APPEND_CRLF = 1
) (
    input  wire        clk,
    input  wire        rst,
    input  wire        pt_valid,
    input  wire [7:0]  pt_data,
    input  wire        pt_sof,
    input  wire        pt_eof,
    input  wire        pt_tag_ok,
    input  wire        pt_tag_valid,
    input  wire        drop_valid,
    input  wire        drop_fail,
    output reg  [7:0]  tx_data,
    output reg         tx_valid,
    input  wire        tx_busy,
    output reg  [31:0] cnt_delivered,
    output reg  [31:0] cnt_discarded,
    output reg  [31:0] cnt_lost,
    output reg  [31:0] cnt_oversize,
    output wire        busy
);
    localparam S_IDLE = 3'd0, S_RECV = 3'd1, S_HOLD = 3'd2,
               S_RD   = 3'd3, S_LAT  = 3'd4, S_PUT  = 3'd5, S_WAIT = 3'd6;

    reg [7:0]  mem [0:DEPTH-1];
    reg [AW:0] wptr, len, rptr;
    reg [2:0]  st;
    reg        ovf, tag_bad, early_valid, early_fail, wait_seen;
    reg [7:0]  rdat;
    reg [1:0]  tail;

    assign busy = (st >= S_RD);
    wire start    = pt_valid && pt_sof && (st == S_IDLE || st == S_HOLD);
    wire recv_now = start || st == S_RECV;
    wire [AW:0] wa = start ? {(AW+1){1'b0}} : wptr;

    always @(posedge clk) begin
        tx_valid <= 1'b0;
        if (rst) begin
            st <= S_IDLE; wptr <= 0; len <= 0; rptr <= 0; ovf <= 0;
            tag_bad <= 0; early_valid <= 0; early_fail <= 0; tail <= 0;
            wait_seen <= 0; rdat <= 0;
            cnt_delivered <= 0; cnt_discarded <= 0; cnt_lost <= 0;
            cnt_oversize <= 0; tx_data <= 0;
        end else begin
            // ---- capture the plaintext stream ----
            if (start) begin
                if (st == S_HOLD) cnt_discarded <= cnt_discarded + 1;
                ovf <= 1'b0; tag_bad <= 1'b0; early_valid <= 1'b0;
                early_fail <= 1'b0;
            end else if (pt_valid && pt_sof) begin
                cnt_lost <= cnt_lost + 1;
            end
            if (recv_now && pt_valid) begin
                if (wa < DEPTH) begin
                    mem[wa[AW-1:0]] <= pt_data;
                    wptr <= wa + 1'b1;
                end else ovf <= 1'b1;
                if (pt_eof) begin
                    st  <= S_HOLD;
                    len <= (wa < DEPTH) ? wa + 1'b1 : DEPTH[AW:0];
                end else st <= S_RECV;
            end
            if (pt_tag_valid && !pt_tag_ok && (recv_now || st == S_HOLD))
                tag_bad <= 1'b1;

            // ---- verdict ----
            if (drop_valid) begin
                if (st == S_HOLD) begin
                    if (drop_fail || tag_bad || ovf) begin
                        cnt_discarded <= cnt_discarded + 1;
                        if (ovf && !drop_fail) cnt_oversize <= cnt_oversize + 1;
                        st <= S_IDLE;
                    end else begin
                        rptr <= 0; tail <= APPEND_CRLF ? 2'd2 : 2'd0;
                        st <= S_RD;
                    end
                end else if (st == S_RECV) begin
                    early_valid <= 1'b1; early_fail <= drop_fail;
                end
                // S_IDLE: verdict for a non-DATA packet: ignore
            end
            if (st == S_HOLD && early_valid) begin
                early_valid <= 1'b0;
                if (early_fail || tag_bad || ovf) begin
                    cnt_discarded <= cnt_discarded + 1; st <= S_IDLE;
                end else begin
                    rptr <= 0; tail <= APPEND_CRLF ? 2'd2 : 2'd0; st <= S_RD;
                end
            end

            // ---- send ----
            case (st)
                S_RD:  begin rdat <= mem[rptr[AW-1:0]]; st <= S_LAT; end
                S_LAT: st <= S_PUT;
                S_PUT: if (!tx_busy) begin
                    tx_data <= rdat; tx_valid <= 1'b1; wait_seen <= 1'b0;
                    st <= S_WAIT;
                end
                S_WAIT: begin
                    if (tx_busy) wait_seen <= 1'b1;
                    if (wait_seen && !tx_busy) begin
                        if (rptr + 1 < len) begin
                            rptr <= rptr + 1; st <= S_RD;
                        end else if (tail != 0) begin
                            rdat <= (tail == 2'd2) ? 8'h0D : 8'h0A;
                            tail <= tail - 1'b1; st <= S_PUT; rptr <= len;
                        end else begin
                            cnt_delivered <= cnt_delivered + 1; st <= S_IDLE;
                        end
                    end
                end
                default: ;
            endcase
        end
    end
endmodule

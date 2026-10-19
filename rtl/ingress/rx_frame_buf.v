//==============================================================================
// rtl/ingress/rx_frame_buf.v
//
// One receive source's frame store: four slots, each holding one complete wire
// frame, filled byte-by-byte from a uart_rx and drained by rx_arbiter.
//
// WHY STORE-AND-FORWARD AND NOT A BYTE LOCK
//   A UART cannot be paused. If the arbiter locked the deframer to one source
//   for the length of a frame, the other source's bytes would arrive with
//   nowhere to go and be lost, which under a flood is exactly when the loss
//   would matter. So each source writes into its own slot at line rate, and
//   only a COMPLETE frame becomes visible to the arbiter.
//
// FRAME BOUNDARIES
//   The wire frame is [2B total_len BE][payload][4B CRC] and total_len counts
//   all of it (deframer.v). A frame is committed when
//     - the byte count reaches total_len (total_len >= 6), or
//     - the source goes quiet for IDLE_TO cycles mid-frame (a truncated or
//       malformed frame; flagged `trunc`).
//   IDLE_TO defaults to deframer.v's own watchdog so a mid-frame gap is
//   tolerated exactly as long as it was when the UART fed the deframer directly.
//   total_len < 6 gives no usable end marker, so those frames end on idle too.
//
// NOTHING IS SILENTLY LOST
//   If both slots are full when a frame starts, the frame is read and counted
//   but not stored, and drop_cnt increments. A frame larger than a slot is
//   stored up to BUF_BYTES, flagged trunc, and the deframer then reports it as
//   RC_FRAME_TIMEOUT because the rest of its bytes never arrive.
//
// Owner: Member C (integration). Verilog-2001, single clock, sync active-high rst.
//==============================================================================

`timescale 1ns / 1ps

module rx_frame_buf #(
    parameter integer AW      = 10,       // slot = 2**AW bytes (1024); 4 slots = one RAMB36
    parameter integer IDLE_TO = 50000     // mid-frame idle cycles before commit
) (
    input  wire          clk,
    input  wire          rst,

    // byte stream from uart_rx
    input  wire          in_valid,
    input  wire [7:0]    in_data,

    // read side (rx_arbiter)
    output wire          rd_ready,        // head slot holds a complete frame
    output wire [10:0]   rd_len,          // stored bytes in head slot
    output wire          rd_trunc,        // frame was cut short or oversized
    input  wire [AW-1:0] rd_addr,
    output reg  [7:0]    rd_data,         // valid 2 cycles after rd_addr settles
    input  wire          rd_pop,          // 1-cycle: release head slot

    output reg  [15:0]   drop_cnt         // frames read but not stored (saturating)
);

    localparam integer BUF_BYTES = (1 << AW);
    localparam [10:0]  BUF11     = BUF_BYTES[10:0];
    localparam [15:0]  BUF16     = BUF_BYTES[15:0];
    localparam [16:0]  IDLE_TO17 = IDLE_TO[16:0];

    (* ram_style = "block" *) reg [7:0] mem [0:(4*BUF_BYTES)-1];

    reg                we;
    reg  [AW+1:0]      wr_idx;
    reg  [7:0]         wr_dat;
    always @(posedge clk) begin
        if (we) mem[wr_idx] <= wr_dat;
    end

    reg  [1:0]         rd_slot;
    always @(posedge clk) rd_data <= mem[{rd_slot, rd_addr}];

    reg  [1:0]         wr_slot;
    reg  [3:0]         full;
    reg  [10:0]        slot_len [0:3];
    reg  [3:0]         slot_trunc;

    assign rd_ready = full[rd_slot];
    assign rd_len   = slot_len[rd_slot];
    assign rd_trunc = slot_trunc[rd_slot];

    localparam [1:0] ST_IDLE = 2'd0, ST_LEN2 = 2'd1, ST_BODY = 2'd2;
    reg  [1:0]         st;
    reg  [7:0]         hi;
    reg  [15:0]        total;
    reg                len_ok;           // total >= 6: end marker usable
    reg                oversize;         // total > BUF_BYTES
    reg  [15:0]        cnt;              // bytes seen so far in this frame
    reg                discard;          // no free slot: count, do not store
    reg  [16:0]        idle;

    wire [15:0] total_now = {hi, in_data};
    wire [15:0] cnt_n     = cnt + 16'd1;
    // bytes actually held in the slot after this byte / at an idle commit
    wire [10:0] held_n    = (cnt_n > BUF16) ? BUF11 : cnt_n[10:0];
    wire [10:0] held_i    = (cnt   > BUF16) ? BUF11 : cnt[10:0];

    always @(posedge clk) begin
        we <= 1'b0;
        if (rst) begin
            rd_slot <= 2'd0;  wr_slot <= 2'd0;  full <= 4'b0000;
            slot_len[0] <= 11'd0; slot_len[1] <= 11'd0; slot_len[2] <= 11'd0;
            slot_len[3] <= 11'd0; slot_trunc <= 4'b0000;
            st <= ST_IDLE; hi <= 8'd0; total <= 16'd0; len_ok <= 1'b0;
            oversize <= 1'b0; cnt <= 16'd0; discard <= 1'b0; idle <= 17'd0;
            drop_cnt <= 16'd0; wr_idx <= {(AW+2){1'b0}}; wr_dat <= 8'd0;
        end else begin
            if (rd_pop) begin
                full[rd_slot] <= 1'b0;
                rd_slot       <= rd_slot + 2'd1;
            end

            case (st)
            ST_IDLE: begin
                if (in_valid) begin
                    hi      <= in_data;
                    cnt     <= 16'd1;
                    idle    <= 17'd0;
                    discard <= full[wr_slot];
                    if (!full[wr_slot]) begin
                        we <= 1'b1; wr_idx <= {wr_slot, {AW{1'b0}}}; wr_dat <= in_data;
                    end
                    st <= ST_LEN2;
                end
            end

            ST_LEN2, ST_BODY: begin
                if (in_valid) begin
                    idle <= 17'd0;
                    cnt  <= cnt_n;
                    if (!discard && cnt < BUF16) begin
                        we <= 1'b1; wr_idx <= {wr_slot, cnt[AW-1:0]}; wr_dat <= in_data;
                    end
                    if (st == ST_LEN2) begin
                        total    <= total_now;
                        len_ok   <= (total_now >= 16'd6);
                        oversize <= (total_now > BUF16);
                        st       <= ST_BODY;
                    end else if (len_ok && cnt_n == total) begin
                        // complete frame
                        st <= ST_IDLE;
                        if (discard) begin
                            if (drop_cnt != 16'hFFFF) drop_cnt <= drop_cnt + 16'd1;
                        end else begin
                            slot_len[wr_slot]   <= held_n;
                            slot_trunc[wr_slot] <= oversize;
                            full[wr_slot]       <= 1'b1;
                            wr_slot             <= wr_slot + 2'd1;
                        end
                    end
                end else begin
                    idle <= idle + 17'd1;
                    if (idle + 17'd1 >= IDLE_TO17) begin
                        // quiet mid-frame: hand over what there is, flagged
                        st <= ST_IDLE;
                        if (discard) begin
                            if (drop_cnt != 16'hFFFF) drop_cnt <= drop_cnt + 16'd1;
                        end else begin
                            slot_len[wr_slot]   <= held_i;
                            slot_trunc[wr_slot] <= 1'b1;
                            full[wr_slot]       <= 1'b1;
                            wr_slot             <= wr_slot + 2'd1;
                        end
                    end
                end
            end

            default: st <= ST_IDLE;
            endcase
        end
    end

endmodule

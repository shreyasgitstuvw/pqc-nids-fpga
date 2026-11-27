//==============================================================================
// rtl/relay/msg_relay.v
//
// Decrypt -> assess -> RE-ENCRYPT relay. The board never puts plaintext on a wire.
//
//   chacha_poly pt_* ---> ring buffer (held until the drop engine's verdict)
//                     ---> descriptor queue (so a second message is not lost)
//   drop_engine pass ---> encrypt with the DESTINATION peer's key
//                         (own chacha20 + poly1305, bit-exact with RFC 8439)
//                     ---> frame:  B0 7E | len | ctr(8, LE) | ciphertext | tag(16)
//                     ---> UART to the destination peer
//
// IDENTITY IS THE PHYSICAL LINK (src_link), NOT ANY ADDRESS IN THE PACKET.
//   slot 0 = link JA (peer A), slot 1 = link JB (the attacker), slot 2 = link JD
//   (peer B). An earlier version derived the slot by comparing ip_src_addr against
//   A_IP/B_IP, which let a sender choose its own identity by writing an address.
//   The link is the one field a sender cannot forge. See session_lookup.v for why
//   this is structural rather than a detection, and for why it does not generalise
//   beyond dedicated point-to-point links.
//
// ROUTING: a message from link JD (peer B) goes to peer A; anything else (peer A,
//   the attacker) goes to peer B.
//
// KEYS: every completed Encaps (an HS_INIT answered) loads the shared secret into
//   the slot of the LINK that HS_INIT arrived on. The same secret is the ingress
//   key held by session_mgr, so each peer has ONE key shared with the board; the
//   egress direction uses its own nonce space (nonce = ctr || 00 00 00 80, byte 11
//   = 0x80) so a (key, nonce) pair is never reused across directions.
//
// QUEUING: the ring buffer holds up to QDEPTH committed messages plus the one being
//   captured, so a message arriving while another is being relayed waits its turn
//   instead of being dropped. RING_BYTES >= (QDEPTH + 1) * MAXMSG, which is what
//   makes an overwrite of unread bytes impossible and means no occupancy test is
//   needed on the capture path. Past that depth a message IS dropped, and counted
//   in cnt_full rather than lost silently.
//
// A message is relayed only if ALL lanes passed it (verdict from drop_engine).
// A signature match, bad tag, flood... -> the plaintext is discarded here.
// Empty messages are never relayed. Messages > MAXMSG bytes are discarded.
//
// Arbitration with handshake_tx on a shared UART: egress claims the transmitter
// only when the handshake engine is idle (hs_hold_off low) and raises eg_active,
// which the top feeds back into handshake_tx's tx_busy so a late reply waits.
//==============================================================================

`timescale 1ns / 1ps

module msg_relay #(
    parameter integer MAXMSG  = 240,   // longest relayed message, bytes
    parameter integer QDEPTH  = 4,     // committed messages that may wait
    parameter integer RING_AW = 11     // ring = 2**RING_AW bytes; >= (QDEPTH+1)*MAXMSG
) (
    input  wire         clk,
    input  wire         rst,

    // plaintext tap from chacha_poly + the link it arrived on
    input  wire         pt_valid,
    input  wire [7:0]   pt_data,
    input  wire         pt_sof,
    input  wire [1:0]   src_link,

    // drop_engine verdict (one per packet)
    input  wire         drop_valid,
    input  wire         drop_fail,

    // egress key load (slot = the link of the HS_INIT that produced it)
    input  wire         key_load,
    input  wire [1:0]   key_slot,
    input  wire [255:0] key_data,

    // transmit side
    input  wire         hs_hold_off,   // handshake engine busy or about to start
    input  wire         tx_busy,       // busy of the UART selected by eg_dest
    output reg          eg_active,     // relay owns the transmitter
    output reg          tx_valid,
    output reg  [7:0]   tx_data,
    output reg  [1:0]   eg_dest,       // 0 = peer A's UART, 1 = peer B's UART

    // observability
    output reg  [15:0]  cnt_relayed,
    output reg  [15:0]  cnt_nopeer,
    output reg  [15:0]  cnt_full,
    output reg  [15:0]  cnt_toolong,
    output wire [2:0]   q_level
);

    localparam [1:0] LINK_A = 2'd0;    // JA
    localparam [1:0] LINK_C = 2'd1;    // JB, the attacker
    localparam [1:0] LINK_B = 2'd2;    // JD

    // ------------------------------------------------------------ key table
    reg [255:0] key_t   [0:2];
    reg [63:0]  ctr_t   [0:2];
    reg [2:0]   ok_t;
    reg         ctr_inc;
    reg [1:0]   inc_slot;

    always @(posedge clk) begin
        if (rst) begin
            ok_t <= 3'b000;
            ctr_t[0] <= 64'd0; ctr_t[1] <= 64'd0; ctr_t[2] <= 64'd0;
        end else begin
            if (ctr_inc) ctr_t[inc_slot] <= ctr_t[inc_slot] + 64'd1;
            if (key_load) begin
                key_t[key_slot] <= key_data;
                ctr_t[key_slot] <= 64'd0;
                ok_t[key_slot]  <= 1'b1;
            end
        end
    end

    // ------------------------------------------------- capture into the ring
    reg [7:0]          ring [0:(1 << RING_AW) - 1];
    reg [RING_AW-1:0]  wp;        // committed write pointer
    reg [RING_AW-1:0]  wp_t;      // tentative: this message, not yet passed
    reg [8:0]          cap_len;
    reg                cap_over;
    reg [1:0]          cap_link;

    // Destination of a message that arrived on `l`: peer B talks to peer A,
    // everyone else talks to peer B.
    function [1:0] dest_link_of;
        input [1:0] l;
        begin
            dest_link_of = (l == LINK_B) ? LINK_A : LINK_B;
        end
    endfunction

    function [1:0] uart_of;
        input [1:0] l;
        begin
            uart_of = (l == LINK_A) ? 2'd0 : 2'd1;
        end
    endfunction

    wire [1:0] cap_dest_link = dest_link_of(cap_link);

    always @(posedge clk) begin
        if (pt_valid) begin
            if (pt_sof)                  ring[wp]   <= pt_data;
            else if (cap_len < MAXMSG)   ring[wp_t] <= pt_data;
        end
    end

    // ------------------------------------------------------ descriptor queue
    reg [RING_AW-1:0] q_start [0:QDEPTH-1];
    reg [7:0]         q_len   [0:QDEPTH-1];
    reg [1:0]         q_dlink [0:QDEPTH-1];
    reg [2:0]         q_wr, q_rd, q_cnt;

    assign q_level = q_cnt;

    wire q_full  = (q_cnt == QDEPTH[2:0]);
    wire q_empty = (q_cnt == 3'd0);

    reg  q_pop;
    wire q_push = drop_valid && !drop_fail && (cap_len != 9'd0) && !cap_over
                  && !q_full && ok_t[cap_dest_link];

    always @(posedge clk) begin
        if (rst) begin
            q_wr <= 3'd0; q_rd <= 3'd0; q_cnt <= 3'd0;
        end else begin
            if (q_push) begin
                q_start[q_wr[1:0]] <= wp;
                q_len  [q_wr[1:0]] <= cap_len[7:0];
                q_dlink[q_wr[1:0]] <= cap_dest_link;
                q_wr <= (q_wr + 3'd1 == QDEPTH[2:0]) ? 3'd0 : q_wr + 3'd1;
            end
            if (q_pop)
                q_rd <= (q_rd + 3'd1 == QDEPTH[2:0]) ? 3'd0 : q_rd + 3'd1;
            if (q_push && !q_pop)      q_cnt <= q_cnt + 3'd1;
            else if (q_pop && !q_push) q_cnt <= q_cnt - 3'd1;
        end
    end

    always @(posedge clk) begin
        if (rst) begin
            wp <= {RING_AW{1'b0}}; wp_t <= {RING_AW{1'b0}};
            cap_len <= 9'd0; cap_over <= 1'b0; cap_link <= LINK_A;
            cnt_nopeer <= 16'd0; cnt_full <= 16'd0; cnt_toolong <= 16'd0;
        end else begin
            if (pt_valid) begin
                if (pt_sof) begin
                    wp_t     <= wp + {{(RING_AW-1){1'b0}}, 1'b1};
                    cap_len  <= 9'd1;
                    cap_over <= 1'b0;
                    cap_link <= src_link;
                end else if (cap_len < MAXMSG) begin
                    wp_t    <= wp_t + {{(RING_AW-1){1'b0}}, 1'b1};
                    cap_len <= cap_len + 9'd1;
                end else begin
                    cap_over <= 1'b1;
                end
            end
            if (drop_valid) begin
                if (!drop_fail && cap_len != 9'd0) begin
                    if (cap_over)                   cnt_toolong <= cnt_toolong + 16'd1;
                    else if (q_full)                cnt_full    <= cnt_full + 16'd1;
                    else if (!ok_t[cap_dest_link])  cnt_nopeer  <= cnt_nopeer + 16'd1;
                    else
                        wp <= wp_t;          // commit the bytes; q_push queues them

                end
                if (!(pt_valid && pt_sof)) cap_len <= 9'd0;
            end
        end
    end

    // ------------------------------------------------------------- crypto
    reg          cc_start;
    reg  [255:0] cc_key;
    reg  [31:0]  cc_counter;
    reg  [95:0]  cc_nonce;
    wire         cc_done;
    wire [511:0] cc_ks;

    chacha20 u_cc (
        .clk(clk), .rst(rst),
        .start(cc_start), .key(cc_key), .counter(cc_counter), .nonce(cc_nonce),
        .busy(), .done(cc_done), .keystream_block(cc_ks),
        .ct_valid(1'b0), .ct_data(8'd0), .ct_sof(1'b0), .ct_eof(1'b0),
        .pt_valid(), .pt_data(), .pt_sof(), .pt_eof()
    );

    reg          pk_valid;
    reg  [255:0] pk;
    reg          pb_valid, pb_last;
    reg  [127:0] pb_data;
    wire         pb_ready, p_tag_valid;
    wire [127:0] p_tag;

    poly1305 u_poly (
        .clk(clk), .rst(rst),
        .key_valid(pk_valid), .key(pk),
        .msg_valid(1'b0), .msg_data(8'd0), .msg_sof(1'b0), .msg_eof(1'b0),
        .blk_valid(pb_valid), .blk_data(pb_data), .blk_len(5'd16), .blk_last(pb_last),
        .expected_tag(128'd0),
        .blk_ready(pb_ready), .busy(), .tag_valid(p_tag_valid), .tag_out(p_tag),
        .tag_ok(), .pt_tag_ok(), .pt_tag_valid(),
        .v_poly_valid(), .v_poly_fail(), .v_poly_reason()
    );

    // -------------------------------------------------------------- FSM
    localparam [4:0]
        S_IDLE   = 5'd0,  S_OTK    = 5'd1,  S_OTKW   = 5'd2,  S_KS     = 5'd3,
        S_KSW    = 5'd4,  S_RD     = 5'd5,  S_BYTE   = 5'd6,  S_FEED   = 5'd7,
        S_FEEDW  = 5'd8,  S_DLY    = 5'd9,  S_NEXT   = 5'd10, S_LEN    = 5'd11,
        S_TAGW   = 5'd12, S_CLAIM  = 5'd13, S_PREP   = 5'd14, S_SEND   = 5'd15,
        S_DRAIN0 = 5'd16, S_DRAIN1 = 5'd17;

    reg [4:0]          st;
    reg [7:0]          n;             // message length
    reg [7:0]          idx;
    reg [RING_AW-1:0]  rp;            // read pointer: base of the message in flight
    reg [7:0]          ct_rd;
    reg [7:0]          pt_rd;
    reg [7:0]          ct_mem [0:255];
    reg [511:0]        ks;
    reg [6:0]          bidx;
    reg [31:0]         blk;
    reg [127:0]        chunk;
    reg [3:0]          cnt16;
    reg [255:0]        ekey;
    reg [63:0]         ectr;
    reg [127:0]        tag;
    reg [8:0]          j;
    reg [3:0]          dly;
    wire [8:0]  frame_len = 9'd27 + {1'b0, n};   // 2 magic + 1 len + 8 ctr + n + 16 tag

    // synchronous memory reads (address registers are stable when sampled)
    always @(posedge clk) begin
        pt_rd <= ring[rp + {{(RING_AW-8){1'b0}}, idx}];
        ct_rd <= ct_mem[j[7:0] - 8'd11];
    end

    function [7:0] frame_byte;
        input [8:0] jj;
        input [7:0] nn;
        input [63:0] c;
        input [127:0] t;
        input [7:0] cb;
        reg [8:0] k;
        begin
            if (jj == 9'd0)       frame_byte = 8'hB0;
            else if (jj == 9'd1)  frame_byte = 8'h7E;
            else if (jj == 9'd2)  frame_byte = nn;
            else if (jj < 9'd11)  frame_byte = c[(jj - 9'd3) * 8 +: 8];
            else if (jj < 9'd11 + {1'b0, nn}) frame_byte = cb;
            else begin
                k = jj - 9'd11 - {1'b0, nn};
                frame_byte = t[k[3:0] * 8 +: 8];
            end
        end
    endfunction

    always @(posedge clk) begin
        cc_start <= 1'b0;
        pk_valid <= 1'b0;
        pb_valid <= 1'b0;
        tx_valid <= 1'b0;
        ctr_inc  <= 1'b0;
        q_pop    <= 1'b0;
        if (rst) begin
            st <= S_IDLE; eg_active <= 1'b0; eg_dest <= 2'd1;
            cnt_relayed <= 16'd0; n <= 8'd0; idx <= 8'd0; j <= 9'd0; dly <= 4'd0;
            bidx <= 7'd0; blk <= 32'd1; chunk <= 128'd0; cnt16 <= 4'd0;
            tx_data <= 8'd0; cc_key <= 256'd0; cc_nonce <= 96'd0; cc_counter <= 32'd0;
            pk <= 256'd0; pb_data <= 128'd0; pb_last <= 1'b0; ks <= 512'd0;
            ekey <= 256'd0; ectr <= 64'd0; tag <= 128'd0; rp <= {RING_AW{1'b0}};
        end else begin
            case (st)
            S_IDLE: begin
                if (!q_empty) begin
                    rp      <= q_start[q_rd[1:0]];
                    n       <= q_len  [q_rd[1:0]];
                    ekey    <= key_t  [q_dlink[q_rd[1:0]]];
                    ectr    <= ctr_t  [q_dlink[q_rd[1:0]]];
                    eg_dest <= uart_of(q_dlink[q_rd[1:0]]);
                    ctr_inc <= 1'b1; inc_slot <= q_dlink[q_rd[1:0]];
                    q_pop   <= 1'b1;
                    idx <= 8'd0; blk <= 32'd1; cnt16 <= 4'd0; chunk <= 128'd0;
                    st <= S_OTK;
                end
            end
            S_OTK: begin
                cc_key <= ekey; cc_nonce <= {8'h80, 24'd0, ectr};
                cc_counter <= 32'd0; cc_start <= 1'b1;
                st <= S_OTKW;
            end
            S_OTKW: if (cc_done) begin
                pk <= cc_ks[255:0]; pk_valid <= 1'b1;
                st <= S_KS;
            end
            S_KS: begin
                cc_counter <= blk; cc_start <= 1'b1; st <= S_KSW;
            end
            S_KSW: if (cc_done) begin
                ks <= cc_ks; bidx <= 7'd0; st <= S_RD;
            end
            S_RD: st <= S_BYTE;                    // pt_rd settles
            S_BYTE: begin
                begin : b
                    reg [7:0] c;
                    c = pt_rd ^ ks[bidx[5:0] * 8 +: 8];
                    ct_mem[idx] <= c;
                    chunk[cnt16 * 8 +: 8] <= c;
                end
                idx   <= idx + 8'd1;
                bidx  <= bidx + 7'd1;
                cnt16 <= cnt16 + 4'd1;
                if (cnt16 == 4'd15 || idx == n - 8'd1) st <= S_FEED;
                else                                   st <= S_NEXT;
            end
            S_FEED: if (pb_ready) begin
                pb_data <= chunk; pb_last <= 1'b0; pb_valid <= 1'b1;
                chunk <= 128'd0; cnt16 <= 4'd0;
                st <= S_FEEDW;
            end
            S_FEEDW: st <= S_DLY;
            S_DLY:   st <= S_NEXT;
            S_NEXT: begin
                if (idx == n) st <= S_LEN;
                else if (bidx == 7'd64) begin
                    bidx <= 7'd0; blk <= blk + 32'd1; st <= S_KS;
                end else st <= S_RD;
            end
            S_LEN: if (pb_ready) begin
                pb_data <= {56'd0, n, 64'd0}; pb_last <= 1'b1; pb_valid <= 1'b1;
                st <= S_TAGW;
            end
            S_TAGW: if (p_tag_valid) begin
                tag <= p_tag; j <= 9'd0; st <= S_CLAIM;
            end
            S_CLAIM: if (!hs_hold_off && !tx_busy) begin
                eg_active <= 1'b1; st <= S_PREP;
            end
            S_PREP: st <= S_SEND;
            S_SEND: if (!tx_busy && !tx_valid) begin
                tx_data  <= frame_byte(j, n, ectr, tag, ct_rd);
                tx_valid <= 1'b1;
                j <= j + 9'd1;
                if (j + 9'd1 == frame_len) begin dly <= 4'd0; st <= S_DRAIN0; end
                else st <= S_PREP;
            end
            S_DRAIN0: begin
                dly <= dly + 4'd1;
                if (dly == 4'd8) st <= S_DRAIN1;
            end
            S_DRAIN1: if (!tx_busy) begin
                eg_active <= 1'b0;
                cnt_relayed <= cnt_relayed + 16'd1;
                st <= S_IDLE;
            end
            default: st <= S_IDLE;
            endcase
        end
    end

    wire _unused_ok = &{1'b0, pt_valid};
endmodule

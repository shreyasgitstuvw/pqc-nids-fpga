//==========================================================================
// rtl/io/handshake_tx.v
//
// Transmits the ML-KEM ciphertext reply.
//
// WHY THIS IS REQUIRED, NOT OPTIONAL
//   Contract section 4 makes this board the handshake RESPONDER: an HS_INIT
//   packet carrying the 800-byte encapsulation key arrives on port 51001,
//   mlkem_top runs Encaps, and the resulting shared secret goes into the session
//   table. But the initiator cannot derive that same secret unless it receives
//   the 768-byte ciphertext c back. Without this reply the handshake is
//   one-sided, no data packet can ever decrypt, and the demo cannot run.
//
// FRAME IT BUILDS (contract sections 1 and 2)
//   [2 B total_length BE] [810 B payload] [4 B CRC-32 BE]      = 816 B
//   payload = 14 B Ethernet + 20 B IPv4 + 8 B UDP + 768 B ciphertext
//   total_length includes the 2-byte prefix and the 4-byte CRC, matching
//   deframer.v's decode. The CRC covers the payload only, MSB first, exactly as
//   deframer.v accumulates and compares it.
//
//   The Ethernet and IP addresses are the received HS_INIT's, reversed, so the
//   reply goes back to whoever initiated. UDP destination port is 51002
//   (PORT_HS_RESP), which is what classifies it as a ciphertext packet at the
//   far end. The IPv4 header checksum is computed properly so the frame is a
//   valid capture in Wireshark during the demo; the UDP checksum is left 0,
//   which IPv4 permits.
//
// CIPHERTEXT SOURCE
//   mlkem_top.v's c_ram, 96 words of 64 bits, read through
//   c_ram_rd_addr_ext / c_ram_rdata_ext. Byte j of c is word j/8, byte j%8,
//   little-endian within the word, which is mlkem_top's packing convention.
//
// Resource estimate (XC7Z020, pre-synthesis): ~260 FFs for the latched header
//   context and the byte counter, ~200 LUTs including the IPv4 checksum folds,
//   plus one crc32.v instance. No BRAM, no DSP.
//==========================================================================

`timescale 1ns / 1ps

module handshake_tx (
    input  wire        clk,
    input  wire        rst,

    // Trigger: an Encaps started by an HS_INIT packet has completed.
    input  wire        send_req,

    // Header context of the HS_INIT that caused it, latched on send_req.
    input  wire [47:0] rx_eth_src_mac,
    input  wire [47:0] rx_eth_dst_mac,
    input  wire [31:0] rx_ip_src_addr,
    input  wire [31:0] rx_ip_dst_addr,

    // mlkem_top.v ciphertext RAM read port
    output reg  [6:0]  c_ram_rd_addr,
    input  wire [63:0] c_ram_rdata,

    // uart_tx.v interface
    output reg  [7:0]  tx_data,
    output reg         tx_valid,
    input  wire        tx_busy,

    output reg         busy        // high for the whole frame; arbitrates the UART
);

    localparam [15:0] CT_BYTES     = 16'd768;
    localparam [15:0] HDR_BYTES    = 16'd42;                 // 14 + 20 + 8
    localparam [15:0] PAYLOAD_LEN  = HDR_BYTES + CT_BYTES;   // 810
    localparam [15:0] TOTAL_LEN    = PAYLOAD_LEN + 16'd6;    // 816, incl. prefix+CRC
    localparam [15:0] IP_TOTAL_LEN = 16'd20 + 16'd8 + CT_BYTES;  // 796
    localparam [15:0] UDP_LEN      = 16'd8 + CT_BYTES;       // 776
    localparam [15:0] PORT_HS_RESP = 16'd51002;
    localparam [15:0] PORT_HS_INIT = 16'd51001;

    localparam [2:0] S_IDLE   = 3'd0,
                     S_PREP   = 3'd1,
                     S_SEND   = 3'd2,
                     S_DRAIN0 = 3'd3,   // final byte handed over, wait for the UART
                     S_DRAIN1 = 3'd4;   // ...and wait for it to finish shifting

    reg [2:0]  state;
    reg [15:0] idx;          // byte index within the frame, 0..815
    reg [15:0] ip_id;        // IPv4 identification, incremented per reply
    reg [6:0]  drain_cnt;    // bounded wait for the transmitter, see S_DRAIN0

    // Latched reply addresses (received, reversed)
    reg [47:0] eth_dst, eth_src;
    reg [31:0] ip_src, ip_dst;

    // ---- IPv4 header checksum over the 10 header words ----
    // Fields are fixed except the addresses and the id, so this is a small
    // combinational fold evaluated once in S_PREP.
    wire [15:0] w0 = 16'h4500;
    wire [15:0] w1 = IP_TOTAL_LEN;
    wire [15:0] w2 = ip_id;
    wire [15:0] w3 = 16'h0000;
    wire [15:0] w4 = {8'd64, 8'd17};     // TTL 64, protocol UDP
    wire [15:0] w6 = ip_src[31:16];
    wire [15:0] w7 = ip_src[15:0];
    wire [15:0] w8 = ip_dst[31:16];
    wire [15:0] w9 = ip_dst[15:0];
    // w5 is the checksum field itself, taken as zero while summing.
    wire [19:0] csum_sum = {4'd0, w0} + {4'd0, w1} + {4'd0, w2} + {4'd0, w3}
                         + {4'd0, w4} + {4'd0, w6} + {4'd0, w7} + {4'd0, w8}
                         + {4'd0, w9};
    wire [16:0] fold1    = {1'b0, csum_sum[15:0]} + {13'd0, csum_sum[19:16]};
    wire [15:0] fold2    = fold1[15:0] + {15'd0, fold1[16]};
    wire [15:0] ip_csum  = ~fold2;
    reg  [15:0] ip_csum_r;

    // ---- CRC-32 over the payload, same engine the receiver uses ----
    reg         crc_init, crc_in_valid, crc_eof;
    reg  [7:0]  crc_in_data;
    wire [31:0] crc_out;
    wire        crc_valid;

    crc32 u_crc32 (
        .clk(clk), .rst(rst),
        .init(crc_init), .in_valid(crc_in_valid), .in_data(crc_in_data),
        .eof(crc_eof), .crc_out(crc_out), .crc_valid(crc_valid)
    );
    wire _unused_crc_valid = crc_valid;

    // ---- byte selection ----
    // Frame layout:
    //   0..1     total_length          (not covered by the CRC)
    //   2..15    Ethernet              (CRC'd)
    //   16..35   IPv4                  (CRC'd)
    //   36..43   UDP                   (CRC'd)
    //   44..811  ciphertext            (CRC'd)
    //   812..815 CRC-32, MSB first
    wire [15:0] p = idx - 16'd2;        // payload-relative index
    wire [15:0] ct_i = p - HDR_BYTES;   // ciphertext-relative index
    wire [2:0]  ct_byte_in_word = ct_i[2:0];
    // Only the low bits of ct_i select within a word; the word address is taken
    // from next_ct_i below, so the rest is intentionally unused here.
    wire _unused_ct_i = &{1'b0, ct_i[15:3]};

    reg [7:0] hdr_byte;
    always @(*) begin
        case (p[5:0])
            6'd0:  hdr_byte = eth_dst[47:40];
            6'd1:  hdr_byte = eth_dst[39:32];
            6'd2:  hdr_byte = eth_dst[31:24];
            6'd3:  hdr_byte = eth_dst[23:16];
            6'd4:  hdr_byte = eth_dst[15:8];
            6'd5:  hdr_byte = eth_dst[7:0];
            6'd6:  hdr_byte = eth_src[47:40];
            6'd7:  hdr_byte = eth_src[39:32];
            6'd8:  hdr_byte = eth_src[31:24];
            6'd9:  hdr_byte = eth_src[23:16];
            6'd10: hdr_byte = eth_src[15:8];
            6'd11: hdr_byte = eth_src[7:0];
            6'd12: hdr_byte = 8'h08;              // EtherType 0x0800
            6'd13: hdr_byte = 8'h00;
            6'd14: hdr_byte = 8'h45;              // IPv4, IHL 5
            6'd15: hdr_byte = 8'h00;              // DSCP/ECN
            6'd16: hdr_byte = IP_TOTAL_LEN[15:8];
            6'd17: hdr_byte = IP_TOTAL_LEN[7:0];
            6'd18: hdr_byte = ip_id[15:8];
            6'd19: hdr_byte = ip_id[7:0];
            6'd20: hdr_byte = 8'h00;              // flags / fragment offset
            6'd21: hdr_byte = 8'h00;
            6'd22: hdr_byte = 8'd64;              // TTL
            6'd23: hdr_byte = 8'd17;              // protocol UDP
            6'd24: hdr_byte = ip_csum_r[15:8];
            6'd25: hdr_byte = ip_csum_r[7:0];
            6'd26: hdr_byte = ip_src[31:24];
            6'd27: hdr_byte = ip_src[23:16];
            6'd28: hdr_byte = ip_src[15:8];
            6'd29: hdr_byte = ip_src[7:0];
            6'd30: hdr_byte = ip_dst[31:24];
            6'd31: hdr_byte = ip_dst[23:16];
            6'd32: hdr_byte = ip_dst[15:8];
            6'd33: hdr_byte = ip_dst[7:0];
            6'd34: hdr_byte = PORT_HS_INIT[15:8]; // UDP source port
            6'd35: hdr_byte = PORT_HS_INIT[7:0];
            6'd36: hdr_byte = PORT_HS_RESP[15:8]; // UDP destination port
            6'd37: hdr_byte = PORT_HS_RESP[7:0];
            6'd38: hdr_byte = UDP_LEN[15:8];
            6'd39: hdr_byte = UDP_LEN[7:0];
            6'd40: hdr_byte = 8'h00;              // UDP checksum, 0 = not computed
            6'd41: hdr_byte = 8'h00;
            default: hdr_byte = 8'h00;
        endcase
    end

    reg [7:0] ct_byte;
    always @(*) begin
        case (ct_byte_in_word)
            3'd0: ct_byte = c_ram_rdata[7:0];
            3'd1: ct_byte = c_ram_rdata[15:8];
            3'd2: ct_byte = c_ram_rdata[23:16];
            3'd3: ct_byte = c_ram_rdata[31:24];
            3'd4: ct_byte = c_ram_rdata[39:32];
            3'd5: ct_byte = c_ram_rdata[47:40];
            3'd6: ct_byte = c_ram_rdata[55:48];
            3'd7: ct_byte = c_ram_rdata[63:56];
        endcase
    end

    reg [7:0] frame_byte;
    always @(*) begin
        if (idx < 16'd2)
            frame_byte = (idx == 16'd0) ? TOTAL_LEN[15:8] : TOTAL_LEN[7:0];
        else if (p < HDR_BYTES)
            frame_byte = hdr_byte;
        else if (p < PAYLOAD_LEN)
            frame_byte = ct_byte;
        else begin
            case (p - PAYLOAD_LEN)
                16'd0: frame_byte = crc_out[31:24];
                16'd1: frame_byte = crc_out[23:16];
                16'd2: frame_byte = crc_out[15:8];
                default: frame_byte = crc_out[7:0];
            endcase
        end
    end

    // The ciphertext word must be presented before its first byte is sent, so
    // the read address runs one byte ahead of idx.
    wire [15:0] next_p    = (idx + 16'd1) - 16'd2;
    wire [15:0] next_ct_i = next_p - HDR_BYTES;

    // c_ram holds 96 words, so only next_ct_i[9:3] addresses it.
    wire _unused_next_ct_i = &{1'b0, next_ct_i[15:10], next_ct_i[2:0]};

    wire sending_payload = (p >= HDR_BYTES) && (p < PAYLOAD_LEN);
    wire sending_hdr     = (idx >= 16'd2) && (p < HDR_BYTES);

    always @(posedge clk) begin
        if (rst) begin
            state         <= S_IDLE;
            idx           <= 16'd0;
            ip_id         <= 16'd1;
            eth_dst       <= 48'd0;
            eth_src       <= 48'd0;
            ip_src        <= 32'd0;
            ip_dst        <= 32'd0;
            ip_csum_r     <= 16'd0;
            c_ram_rd_addr <= 7'd0;
            drain_cnt     <= 7'd0;
            tx_data       <= 8'd0;
            tx_valid      <= 1'b0;
            busy          <= 1'b0;
            crc_init      <= 1'b0;
            crc_in_valid  <= 1'b0;
            crc_in_data   <= 8'd0;
            crc_eof       <= 1'b0;
        end else begin
            tx_valid     <= 1'b0;
            crc_init     <= 1'b0;
            crc_in_valid <= 1'b0;
            crc_eof      <= 1'b0;

            case (state)
                S_IDLE: begin
                    busy <= 1'b0;
                    if (send_req) begin
                        // Reply to the initiator: swap the addresses round.
                        eth_dst       <= rx_eth_src_mac;
                        eth_src       <= rx_eth_dst_mac;
                        ip_src        <= rx_ip_dst_addr;
                        ip_dst        <= rx_ip_src_addr;
                        idx           <= 16'd0;
                        c_ram_rd_addr <= 7'd0;
                        busy          <= 1'b1;
                        state         <= S_PREP;
                    end
                end

                S_PREP: begin
                    // Addresses are registered now, so the checksum fold is valid.
                    ip_csum_r <= ip_csum;
                    state     <= S_SEND;
                end

                S_SEND: begin
                    if (!tx_busy && !tx_valid) begin
                        tx_data  <= frame_byte;
                        tx_valid <= 1'b1;

                        // Feed the CRC with payload bytes only, and flag the last.
                        if (sending_hdr || sending_payload) begin
                            crc_in_valid <= 1'b1;
                            crc_in_data  <= frame_byte;
                            crc_init     <= (p == 16'd0);
                            crc_eof      <= (p == (PAYLOAD_LEN - 16'd1));
                        end

                        if (idx == (TOTAL_LEN - 16'd1)) begin
                            // busy MUST stay asserted here. pqc_nids_top muxes
                            // the UART on busy, so clearing it in the same cycle
                            // as the final tx_valid handed the transmitter back
                            // to telemetry_tx before uart_tx had taken the byte
                            // -- the frame went out one byte short (measured:
                            // 815 of 816 bytes captured).
                            state     <= S_DRAIN0;
                            drain_cnt <= 7'd0;
                        end else begin
                            idx <= idx + 16'd1;
                            // Keep the ciphertext word one byte ahead.
                            if ((next_p >= HDR_BYTES) && (next_p < PAYLOAD_LEN))
                                c_ram_rd_addr <= next_ct_i[9:3];
                        end
                    end
                end

                S_DRAIN0: begin
                    // uart_tx raises tx_busy once it starts shifting the byte.
                    // Bounded, because waiting on another module's handshake
                    // with no timeout is how a transmitter wedges: if tx_busy
                    // never rises, release anyway rather than holding the shared
                    // UART forever. 127 clocks is far longer than uart_tx needs
                    // to react (one clock) and far shorter than one bit time.
                    if (tx_busy) begin
                        state <= S_DRAIN1;
                    end else if (drain_cnt == 7'd127) begin
                        busy  <= 1'b0;
                        ip_id <= ip_id + 16'd1;
                        state <= S_IDLE;
                    end else begin
                        drain_cnt <= drain_cnt + 7'd1;
                    end
                end

                S_DRAIN1: begin
                    if (!tx_busy) begin
                        busy  <= 1'b0;
                        // One identification value per reply, so two handshakes
                        // are distinguishable in a packet capture. S_PREP folds
                        // the IPv4 checksum from ip_id, so incrementing at the
                        // end of a frame means the next frame picks up the new
                        // value with a matching checksum.
                        ip_id <= ip_id + 16'd1;
                        state <= S_IDLE;
                    end
                end

                default: state <= S_IDLE;
            endcase
        end
    end

endmodule

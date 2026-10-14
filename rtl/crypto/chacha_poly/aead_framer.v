//==========================================================================
// rtl/crypto/chacha_poly/aead_framer.v
//
// Glue between the internal packet bus and chacha_poly.v. This is the module
// the interface contract implies but never specified, and without it
// chacha_poly.v cannot be instantiated at all: it needs a key, a 96-bit nonce,
// an AAD block and a *parallel* 128-bit expected_tag, none of which exist on
// the packet bus.
//
// WHAT IT DOES, per DATA packet (packet_type == 2'b01)
//   1. Resolves the session. session_lookup.v has already put the id on the
//      bus; this module issues lk_req/lk_id to session_mgr.v and reads back
//      lk_key / lk_nonce / lk_ok.
//   2. Builds the AAD (see "AAD DEFINITION" below) and strobes key_valid.
//   3. Splits the payload. Contract section 4 says a DATA payload is ChaCha20
//      ciphertext followed by its 16-byte Poly1305 tag. payload_len is on the
//      bus before the first payload byte, so the split point is known up front:
//      the first (payload_len - 16) bytes are ciphertext and the last 16 are the
//      tag. The tag bytes go straight into expected_tag; no store-and-forward
//      of the whole packet is needed.
//   4. Streams the ciphertext into chacha_poly.v, honouring its `ready`.
//   5. On completion, pulses nonce_adv so the session's ChaCha20 nonce counter
//      advances. Nothing drove that port before, so every packet in a session
//      reused nonce 0 -- complete keystream reuse.
//
// WHY THE FIFO EXISTS
//   chacha_poly.v deasserts `ready` for 22 cycles every 64 bytes while
//   chacha20.v regenerates a keystream block, and for ~50 cycles after
//   key_valid. The packet bus in contract section 3 has no backpressure, so
//   without buffering those bytes are simply lost: measured, a 100-byte payload
//   arriving at one byte per cycle loses 25 plaintext bytes, and at six cycles
//   per byte it loses 4.
//
//   FIFO_DEPTH bytes of ciphertext buffer absorb that. Input runs at up to one
//   byte per cycle; chacha_poly sustains 64 bytes per 86 cycles, i.e. 0.744
//   bytes per cycle; so the backlog grows at 0.256 bytes per cycle and a payload
//   of N bytes needs about 0.256*N + 50 bytes of buffer at full bus rate. The
//   default 512 bytes therefore covers payloads up to ~1800 B, i.e. any Ethernet
//   frame (max 1518 B). At the 3 Mbaud line rate the bus delivers one byte every
//   333 cycles and the FIFO never holds more than one byte.
//
//   The FIFO is read combinationally, so it infers distributed RAM (512 x 8 =
//   4096 bits, about 64 LUTs, estimated) rather than a BRAM. That is
//   deliberate: see
//   "WHY ct_valid IS COMBINATIONAL" below.
//
// WHY THE LAST CIPHERTEXT BYTE IS HELD BACK
//   chacha_poly.v compares against expected_tag only after the whole ciphertext
//   and the length block have been fed, but it is driven from the payload tail,
//   which arrives *after* all the ciphertext. If the ciphertext is streamed
//   eagerly, the comparison can happen before the last tag bytes have landed and
//   a valid packet fails. Measured: correct at one byte per cycle (the tag
//   arrives while the core is still starting up) but failing at six cycles per
//   byte.
//
//   The fix needs no extra buffering: withhold the final ct_eof transfer until
//   the whole payload, tag included, has been accepted. Everything before it can
//   stream freely.
//
// WHY ct_valid IS COMBINATIONAL
//   chacha_poly.v's `ready` means "I am in S_STREAM_CT and will consume
//   ct_valid on this edge". It drops on the same edge that consumes the 64th
//   byte of a block. So a ct_valid registered from a `ready` sampled one cycle
//   earlier arrives when the core has already left S_STREAM_CT, and that byte is
//   silently dropped -- which is the same byte-loss failure the FIFO exists to
//   prevent, just moved one level up. The transfer therefore has to be decided
//   in the same cycle `ready` is asserted, which means ct_valid/ct_data/ct_sof/
//   ct_eof are combinational and rd_ptr advances only on an actual transfer.
//
//   If a payload ever does overrun the buffer, fifo_overflow latches and the
//   packet is failed rather than silently corrupted.
//
// AAD DEFINITION (contract amendment -- section 3.1 did not define this)
//   AAD = ip_src_addr(4) || ip_dst_addr(4) || l4_src_port(2) || l4_dst_port(2)
//   12 bytes, little-endian into aad_data[95:0] to match chacha_poly.v's
//   convention that byte 0 sits at aad_data[7:0].
//
//   Rationale: these are exactly the header fields an attacker could rewrite to
//   replay a validly-tagged ciphertext into a different session or host.
//   Authenticating them binds the ciphertext to its 5-tuple. They are plaintext
//   on the wire, so putting them in the AAD rather than the ciphertext costs
//   nothing and keeps the detection lane's header reads (section 3) unchanged.
//
// THE POLY VERDICT LANE
//   This module owns v_poly_* rather than wiring chacha_poly's straight to
//   drop_engine. drop_engine waits for the poly lane before it will commit a
//   DATA packet, so a DATA packet whose cipher never runs -- no session, or a
//   payload too short to hold a tag -- must still produce exactly one poly
//   verdict or that packet stalls forever. Those cases fail with RC_BAD_TAG:
//   the packet could not be authenticated, which is what that code means.
//
// Resource estimate (XC7Z020, pre-synthesis, not from a synthesis report):
//   the 512-byte ciphertext FIFO is distributed RAM, about 64 LUTs (estimated);
//   ~350 FFs (estimated) for the latched header/key/nonce/tag state; ~250 LUTs
//   (estimated) of control. No BRAM, no DSP.
//   (An earlier revision used a 2048-byte BRAM FIFO; the depth changed when the
//    read became combinational. Figures updated with it.)
//==========================================================================

`timescale 1ns / 1ps

`include "reason_codes.vh"

module aead_framer #(
    parameter integer FIFO_DEPTH = 512,       // bytes; must be a power of two
    parameter integer FIFO_AW    = 9          // log2(FIFO_DEPTH)
) (
    input  wire         clk,
    input  wire         rst,

    // ---- packet bus header context (contract section 3) ----
    input  wire         hdr_valid,
    input  wire [1:0]   packet_type,
    input  wire [15:0]  payload_len,
    input  wire [15:0]  session_id,       // from session_lookup.v
    input  wire [31:0]  ip_src_addr,
    input  wire [31:0]  ip_dst_addr,
    input  wire [15:0]  l4_src_port,
    input  wire [15:0]  l4_dst_port,

    // ---- packet bus payload stream ----
    input  wire         pb_valid,
    input  wire         pb_sof,
    input  wire         pb_eof,
    input  wire [7:0]   pb_data,

    // ---- session table (session_mgr.v) ----
    output reg          lk_req,
    output reg  [15:0]  lk_id,
    input  wire         lk_valid,
    input  wire         lk_ok,
    input  wire [255:0] lk_key,
    input  wire [95:0]  lk_nonce,
    output reg          nonce_adv,
    output reg  [15:0]  nonce_adv_id,

    // ---- chacha_poly.v ----
    output reg          key_valid,
    output reg  [255:0] key,
    output reg  [95:0]  nonce,
    output reg  [127:0] aad_data,
    output reg  [4:0]   aad_len,
    output wire         ct_valid,
    output wire [7:0]   ct_data,
    output wire         ct_sof,
    output wire         ct_eof,
    output reg  [127:0] expected_tag,
    input  wire         cp_ready,
    input  wire         cp_done,
    input  wire         cp_v_poly_valid,
    input  wire         cp_v_poly_fail,
    input  wire [3:0]   cp_v_poly_reason,

    // ---- uniform verdict to drop_engine (contract section 6) ----
    output reg          v_poly_valid,
    output reg          v_poly_fail,
    output reg  [3:0]   v_poly_reason,

    // ---- telemetry ----
    output reg          fifo_overflow,    // latched: a payload outran the buffer
    output reg          no_session_drop,  // 1-cycle: DATA with no established session

    // 1-cycle: this DATA packet produced NO plaintext, so cam_matcher.v will
    // never see a byte of it and will never strobe its verdict. drop_engine
    // waits for the CAM lane on every DATA packet, so without this the packet
    // would sit unadjudicated until the watchdog expired. The top level ORs this
    // into the CAM lane as a pass: there is nothing to match against.
    output reg          cam_bypass
);

    localparam [1:0] PKT_DATA = 2'b01;

    localparam [2:0] S_IDLE       = 3'd0,
                     S_WAIT_LK    = 3'd1,
                     S_START_CP   = 3'd2,
                     S_WAIT_READY = 3'd3,
                     S_STREAM     = 3'd4,
                     S_WAIT_DONE  = 3'd5,
                     S_REJECT     = 3'd6;

    reg [2:0]  state;

    // ---- latched per-packet header context ----
    reg [15:0] sid_r;
    reg [15:0] ct_len_r;        // payload_len - 16 = ciphertext byte count
    reg        active_r;        // a DATA packet is being collected
    reg        rejected_r;      // this packet cannot be authenticated

    // ---- ciphertext FIFO ----
    reg [7:0]           fifo [0:FIFO_DEPTH-1];
    reg [FIFO_AW:0]     wr_ptr, rd_ptr;     // one extra bit for full/empty
    wire [FIFO_AW:0]    fifo_count = wr_ptr - rd_ptr;
    wire                fifo_empty = (wr_ptr == rd_ptr);
    wire                fifo_full  = (fifo_count == FIFO_DEPTH[FIFO_AW:0]);

    // ---- payload byte accounting (write side) ----
    reg [15:0] in_cnt;          // payload bytes accepted this packet
    reg [15:0] out_cnt;         // ciphertext bytes handed to chacha_poly

    // Liveness guard. A truncated or malformed packet can leave this module
    // waiting for bytes or for cp_done that never come; without a timeout it
    // would hold the poly lane forever and drop_engine would never commit the
    // packet. 65535 cycles is ~0.66 ms at 100 MHz, far longer than any legitimate
    // packet needs (a 1518-byte frame at 3 Mbaud occupies ~505,000 cycles of bus
    // time, but this counter only runs while no progress is being made).
    reg [15:0] stall_cnt;

    wire        is_data_hdr   = hdr_valid && (packet_type == PKT_DATA);
    wire [15:0] ct_len_calc   = payload_len - 16'd16;
    // Need at least one ciphertext byte in addition to the 16-byte tag. A
    // payload of exactly 16 bytes is an empty encrypted packet, which this
    // design does not carry; it is failed rather than specially handled.
    wire        len_ok        = (payload_len > 16'd16);
    wire        session_ok    = (session_id != 16'd0);

    // A payload byte belongs to the tag once in_cnt has passed the split point.
    wire        byte_is_tag   = active_r && (in_cnt >= ct_len_r);
    wire [3:0]  tag_idx       = in_cnt[3:0] - ct_len_r[3:0];


    // ---- combinational transfer to chacha_poly (see header) ----
    wire streaming     = (state == S_STREAM);
    wire more_bytes    = (out_cnt < ct_len_r);
    wire last_ct_byte  = (out_cnt == (ct_len_r - 16'd1));
    // The whole payload, tag included, has been accepted.
    wire tag_complete  = (in_cnt >= (ct_len_r + 16'd16));
    wire do_xfer       = streaming && cp_ready && !fifo_empty && more_bytes
                         && !fifo_overflow && (!last_ct_byte || tag_complete);

    assign ct_valid = do_xfer;
    assign ct_data  = fifo[rd_ptr[FIFO_AW-1:0]];
    assign ct_sof   = do_xfer && (out_cnt == 16'd0);
    assign ct_eof   = do_xfer && last_ct_byte;

    // =====================================================================
    // Write side: accept payload bytes unconditionally (the bus cannot stall)
    // =====================================================================
    always @(posedge clk) begin
        if (rst) begin
            wr_ptr        <= {(FIFO_AW+1){1'b0}};
            in_cnt        <= 16'd0;
            expected_tag  <= 128'd0;
            fifo_overflow <= 1'b0;
            active_r      <= 1'b0;
            sid_r         <= 16'd0;
            ct_len_r      <= 16'd0;
            rejected_r    <= 1'b0;
        end else begin
            // New DATA packet: latch its context and reset the collector.
            if (is_data_hdr) begin
                active_r     <= 1'b1;
                sid_r        <= session_id;
                ct_len_r     <= len_ok ? ct_len_calc : 16'd0;
                rejected_r   <= !(len_ok && session_ok);
                in_cnt       <= 16'd0;
                expected_tag <= 128'd0;
                wr_ptr       <= rd_ptr;        // discard anything stale
            end else if (hdr_valid) begin
                // A non-DATA packet: this module does not participate.
                active_r   <= 1'b0;
                rejected_r <= 1'b0;
            end

            if (pb_valid && active_r) begin
                if (byte_is_tag) begin
                    // Last 16 payload bytes are the Poly1305 tag. Byte 0 of the
                    // tag sits at expected_tag[7:0], matching chacha_poly.v.
                    expected_tag[8*tag_idx +: 8] <= pb_data;
                end else if (!fifo_full) begin
                    fifo[wr_ptr[FIFO_AW-1:0]] <= pb_data;
                    wr_ptr <= wr_ptr + {{FIFO_AW{1'b0}}, 1'b1};
                end else begin
                    // Buffer outran: fail the packet rather than corrupt it.
                    fifo_overflow <= 1'b1;
                end
                in_cnt <= in_cnt + 16'd1;
            end
        end
    end

    // =====================================================================
    // Read side / control FSM
    // =====================================================================
    always @(posedge clk) begin
        if (rst) begin
            state         <= S_IDLE;
            rd_ptr        <= {(FIFO_AW+1){1'b0}};
            out_cnt       <= 16'd0;
            lk_req        <= 1'b0;
            lk_id         <= 16'd0;
            nonce_adv     <= 1'b0;
            nonce_adv_id  <= 16'd0;
            key_valid     <= 1'b0;
            key           <= 256'd0;
            nonce         <= 96'd0;
            aad_data      <= 128'd0;
            aad_len       <= 5'd0;
            v_poly_valid  <= 1'b0;
            v_poly_fail   <= 1'b0;
            v_poly_reason <= `RC_NONE;
            no_session_drop <= 1'b0;
            cam_bypass    <= 1'b0;
            stall_cnt     <= 16'd0;
        end else begin
            // 1-cycle strobes default low
            lk_req          <= 1'b0;
            key_valid       <= 1'b0;
            nonce_adv       <= 1'b0;
            v_poly_valid    <= 1'b0;
            v_poly_fail     <= 1'b0;
            v_poly_reason   <= `RC_NONE;
            no_session_drop <= 1'b0;
            cam_bypass      <= 1'b0;

            // Progress watchdog: cleared whenever something advances.
            if (state == S_IDLE || do_xfer || lk_valid || cp_done || is_data_hdr)
                stall_cnt <= 16'd0;
            else
                stall_cnt <= stall_cnt + 16'd1;

            case (state)
                S_IDLE: begin
                    if (is_data_hdr) begin
                        out_cnt <= 16'd0;
                        if (!(len_ok && session_ok)) begin
                            // No session, or too short to contain a tag.
                            no_session_drop <= session_ok ? 1'b0 : 1'b1;
                            state           <= S_REJECT;
                        end else begin
                            lk_req <= 1'b1;
                            lk_id  <= session_id;
                            state  <= S_WAIT_LK;
                        end
                    end
                end

                S_WAIT_LK: begin
                    if (lk_valid) begin
                        if (!lk_ok) begin
                            // Session exists on the bus but is not ESTABLISHED,
                            // or its nonce counter is exhausted.
                            no_session_drop <= 1'b1;
                            state           <= S_REJECT;
                        end else begin
                            key   <= lk_key;
                            nonce <= lk_nonce;
                            // AAD: 5-tuple, byte 0 at [7:0] (see header)
                            aad_data <= {32'd0,
                                         l4_dst_port[7:0], l4_dst_port[15:8],
                                         l4_src_port[7:0], l4_src_port[15:8],
                                         ip_dst_addr[7:0],  ip_dst_addr[15:8],
                                         ip_dst_addr[23:16], ip_dst_addr[31:24],
                                         ip_src_addr[7:0],  ip_src_addr[15:8],
                                         ip_src_addr[23:16], ip_src_addr[31:24]};
                            aad_len <= 5'd12;
                            state   <= S_START_CP;
                        end
                    end
                end

                S_START_CP: begin
                    key_valid <= 1'b1;
                    state     <= S_WAIT_READY;
                end

                S_WAIT_READY: begin
                    if (cp_ready) state <= S_STREAM;
                end

                S_STREAM: begin
                    if (fifo_overflow) begin
                        state <= S_REJECT;
                    end else if (do_xfer) begin
                        rd_ptr  <= rd_ptr + {{FIFO_AW{1'b0}}, 1'b1};
                        out_cnt <= out_cnt + 16'd1;
                        if (out_cnt == (ct_len_r - 16'd1))
                            state <= S_WAIT_DONE;
                    end
                end

                S_WAIT_DONE: begin
                    if (cp_done) begin
                        // Advance this session's nonce so the next packet in the
                        // session uses a fresh one.
                        nonce_adv     <= 1'b1;
                        nonce_adv_id  <= sid_r;
                        // Pass chacha_poly's own verdict through unchanged.
                        v_poly_valid  <= 1'b1;
                        v_poly_fail   <= cp_v_poly_fail;
                        v_poly_reason <= cp_v_poly_fail ? cp_v_poly_reason : `RC_NONE;
                        state         <= S_IDLE;
                    end else if (cp_v_poly_valid) begin
                        // Defensive: verdict without done.
                        v_poly_valid  <= 1'b1;
                        v_poly_fail   <= cp_v_poly_fail;
                        v_poly_reason <= cp_v_poly_reason;
                        state         <= S_IDLE;
                    end
                end

                S_REJECT: begin
                    // Emit exactly one poly verdict so drop_engine can commit
                    // this packet, then wait for the payload to finish arriving.
                    v_poly_valid  <= 1'b1;
                    v_poly_fail   <= 1'b1;
                    v_poly_reason <= `RC_BAD_TAG;
                    cam_bypass    <= 1'b1;   // no plaintext for this packet
                    state         <= S_IDLE;
                end

                default: state <= S_IDLE;
            endcase

            // Watchdog expiry: fail the packet so the poly lane always reports.
            if ((state != S_IDLE) && (stall_cnt == 16'hFFFF)) begin
                v_poly_valid  <= 1'b1;
                v_poly_fail   <= 1'b1;
                v_poly_reason <= `RC_BAD_TAG;
                cam_bypass    <= 1'b1;
                state         <= S_IDLE;
            end
        end
    end

    // Unused-but-contract-present inputs, sunk explicitly for lint.
    wire _unused_ok = &{1'b0, pb_sof, pb_eof, rejected_r, fifo_count};

endmodule

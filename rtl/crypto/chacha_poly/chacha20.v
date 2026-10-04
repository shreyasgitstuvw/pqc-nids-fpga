// rtl/crypto/chacha_poly/chacha20.v
//
// ChaCha20 keystream generator -- RFC 8439 Section 2.3
// Member D (@control)
//
// Architecture
// ============
// One 64-byte keystream block per 22 clock cycles:
//   Cycle 0        : latch key / counter / nonce into s_init[15:0]
//   Cycles 1..20   : 10 double-rounds (col-round on odd count, diag-round on even)
//                    4 quarter-rounds in parallel each cycle
//   Cycle 21       : add s_work + s_init, register result
//   Cycle 22       : assert done, keystream_block valid
//
// Plaintext inspection bus (contract v1.1.0 Section 3.1)
// ======================================================
// When the caller drives ct_valid/ct_data/ct_sof/ct_eof, this module XORs
// each ciphertext byte against the appropriate keystream byte and presents the
// decrypted plaintext on pt_valid/pt_data/pt_sof/pt_eof.
// pt_tag_ok and pt_tag_valid are driven by poly1305.v at the chacha_poly top
// level, not here.
//
// Constraints: Verilog-2001, one module per file, single clock clk,
// synchronous active-high reset rst, registered outputs, no latches,
// no DSPs, no BRAMs.

module chacha20 (
    input  wire         clk,
    input  wire         rst,

    // ---- keystream generation ------------------------------------------------
    input  wire         start,          // 1-cycle strobe; key/counter/nonce must be stable
    input  wire [255:0] key,            // 256-bit key, little-endian word packing
    input  wire [31:0]  counter,        // 32-bit block counter
    input  wire [95:0]  nonce,          // 96-bit nonce, little-endian word packing
    output reg          busy,
    output reg          done,           // 1-cycle strobe: keystream_block valid
    output reg  [511:0] keystream_block, // 64-byte serialised keystream

    // ---- plaintext inspection bus (contract Section 3.1) ---------------------
    input  wire         ct_valid,       // ciphertext byte arriving
    input  wire [7:0]   ct_data,        // ciphertext byte
    input  wire         ct_sof,         // first byte of packet
    input  wire         ct_eof,         // last byte of packet
    output reg          pt_valid,       // decrypted byte valid
    output reg  [7:0]   pt_data,        // decrypted byte
    output reg          pt_sof,         // first plaintext byte of packet
    output reg          pt_eof          // last plaintext byte of packet
);

    // =========================================================================
    // Constants -- "expand 32-byte k"
    // =========================================================================
    localparam [31:0] C0 = 32'h61707865;
    localparam [31:0] C1 = 32'h3320646E;
    localparam [31:0] C2 = 32'h79622D32;
    localparam [31:0] C3 = 32'h6B206574;

    // =========================================================================
    // Round counter: 0=idle, 1..20=rounds, 21=add, 22=out
    // =========================================================================
    reg [4:0] round_cnt;

    // =========================================================================
    // 16-word working and initial state
    // =========================================================================
    reg [31:0] s_work [0:15];
    reg [31:0] s_init [0:15];

    // =========================================================================
    // Byte index into the 64-byte keystream block for the XOR path
    // =========================================================================
    reg [5:0] ks_byte_idx;

    // =========================================================================
    // Quarter-round function (pure combinational)
    // Returns {a_out, b_out, c_out, d_out} packed into 128 bits.
    // =========================================================================
    function [127:0] qr_fn;
        input [31:0] a, b, c, d;
        reg [31:0] ar, br, cr, dr;
        begin
            ar = a + b;               dr = d ^ ar;  dr = (dr << 16) | (dr >> 16);
            cr = c + dr;              br = b ^ cr;  br = (br << 12) | (br >> 20);
            ar = ar + br;             dr = dr ^ ar; dr = (dr <<  8) | (dr >> 24);
            cr = cr + dr;             br = br ^ cr; br = (br <<  7) | (br >> 25);
            qr_fn = {ar, br, cr, dr};
        end
    endfunction

    // =========================================================================
    // Combinational quarter-round inputs (selected by round type)
    // =========================================================================
    reg [31:0] in0a, in0b, in0c, in0d;
    reg [31:0] in1a, in1b, in1c, in1d;
    reg [31:0] in2a, in2b, in2c, in2d;
    reg [31:0] in3a, in3b, in3c, in3d;

    wire [127:0] out0 = qr_fn(in0a, in0b, in0c, in0d);
    wire [127:0] out1 = qr_fn(in1a, in1b, in1c, in1d);
    wire [127:0] out2 = qr_fn(in2a, in2b, in2c, in2d);
    wire [127:0] out3 = qr_fn(in3a, in3b, in3c, in3d);

    // Column round (round_cnt odd): QR(0,4,8,12), QR(1,5,9,13), QR(2,6,10,14), QR(3,7,11,15)
    // Diagonal round (even):        QR(0,5,10,15), QR(1,6,11,12), QR(2,7,8,13), QR(3,4,9,14)
    wire col = round_cnt[0];

    always @(col,
            s_work[0],s_work[1],s_work[2],s_work[3],
            s_work[4],s_work[5],s_work[6],s_work[7],
            s_work[8],s_work[9],s_work[10],s_work[11],
            s_work[12],s_work[13],s_work[14],s_work[15]) begin
        if (col) begin
            in0a=s_work[0]; in0b=s_work[4];  in0c=s_work[8];  in0d=s_work[12];
            in1a=s_work[1]; in1b=s_work[5];  in1c=s_work[9];  in1d=s_work[13];
            in2a=s_work[2]; in2b=s_work[6];  in2c=s_work[10]; in2d=s_work[14];
            in3a=s_work[3]; in3b=s_work[7];  in3c=s_work[11]; in3d=s_work[15];
        end else begin
            in0a=s_work[0]; in0b=s_work[5];  in0c=s_work[10]; in0d=s_work[15];
            in1a=s_work[1]; in1b=s_work[6];  in1c=s_work[11]; in1d=s_work[12];
            in2a=s_work[2]; in2b=s_work[7];  in2c=s_work[8];  in2d=s_work[13];
            in3a=s_work[3]; in3b=s_work[4];  in3c=s_work[9];  in3d=s_work[14];
        end
    end

    // =========================================================================
    // Main sequential logic
    // =========================================================================
    integer idx;

    always @(posedge clk) begin
        if (rst) begin
            round_cnt       <= 5'd0;
            busy            <= 1'b0;
            done            <= 1'b0;
            ks_byte_idx     <= 6'd0;
            keystream_block <= 512'd0;
            pt_valid        <= 1'b0;
            pt_data         <= 8'd0;
            pt_sof          <= 1'b0;
            pt_eof          <= 1'b0;
            for (idx = 0; idx < 16; idx = idx + 1) begin
                s_work[idx] <= 32'd0;
                s_init[idx] <= 32'd0;
            end
        end else begin
            // Default: clear one-cycle strobes
            done     <= 1'b0;
            pt_valid <= 1'b0;
            pt_sof   <= 1'b0;
            pt_eof   <= 1'b0;

            // ------------------------------------------------------------------
            // Cycle 0 (start): latch initial state and copy to working state
            // ------------------------------------------------------------------
            if (start) begin
                s_init[0]  <= C0;           s_work[0]  <= C0;
                s_init[1]  <= C1;           s_work[1]  <= C1;
                s_init[2]  <= C2;           s_work[2]  <= C2;
                s_init[3]  <= C3;           s_work[3]  <= C3;
                s_init[4]  <= key[31:0];    s_work[4]  <= key[31:0];
                s_init[5]  <= key[63:32];   s_work[5]  <= key[63:32];
                s_init[6]  <= key[95:64];   s_work[6]  <= key[95:64];
                s_init[7]  <= key[127:96];  s_work[7]  <= key[127:96];
                s_init[8]  <= key[159:128]; s_work[8]  <= key[159:128];
                s_init[9]  <= key[191:160]; s_work[9]  <= key[191:160];
                s_init[10] <= key[223:192]; s_work[10] <= key[223:192];
                s_init[11] <= key[255:224]; s_work[11] <= key[255:224];
                s_init[12] <= counter;      s_work[12] <= counter;
                s_init[13] <= nonce[31:0];  s_work[13] <= nonce[31:0];
                s_init[14] <= nonce[63:32]; s_work[14] <= nonce[63:32];
                s_init[15] <= nonce[95:64]; s_work[15] <= nonce[95:64];
                busy       <= 1'b1;
                round_cnt  <= 5'd1;
                ks_byte_idx <= 6'd0;
            end

            // ------------------------------------------------------------------
            // Cycles 1..20: apply 4 quarter-rounds
            // ------------------------------------------------------------------
            else if (round_cnt >= 5'd1 && round_cnt <= 5'd20) begin
                if (col) begin
                    {s_work[0], s_work[4],  s_work[8],  s_work[12]} <= out0;
                    {s_work[1], s_work[5],  s_work[9],  s_work[13]} <= out1;
                    {s_work[2], s_work[6],  s_work[10], s_work[14]} <= out2;
                    {s_work[3], s_work[7],  s_work[11], s_work[15]} <= out3;
                end else begin
                    {s_work[0], s_work[5],  s_work[10], s_work[15]} <= out0;
                    {s_work[1], s_work[6],  s_work[11], s_work[12]} <= out1;
                    {s_work[2], s_work[7],  s_work[8],  s_work[13]} <= out2;
                    {s_work[3], s_work[4],  s_work[9],  s_work[14]} <= out3;
                end
                round_cnt <= round_cnt + 5'd1;
            end

            // ------------------------------------------------------------------
            // Cycle 21: final add
            // ------------------------------------------------------------------
            else if (round_cnt == 5'd21) begin
                for (idx = 0; idx < 16; idx = idx + 1)
                    s_work[idx] <= s_work[idx] + s_init[idx];
                round_cnt <= 5'd22;
            end

            // ------------------------------------------------------------------
            // Cycle 22: serialize to keystream_block, pulse done
            // ------------------------------------------------------------------
            else if (round_cnt == 5'd22) begin
                keystream_block[31:0]    <= s_work[0];
                keystream_block[63:32]   <= s_work[1];
                keystream_block[95:64]   <= s_work[2];
                keystream_block[127:96]  <= s_work[3];
                keystream_block[159:128] <= s_work[4];
                keystream_block[191:160] <= s_work[5];
                keystream_block[223:192] <= s_work[6];
                keystream_block[255:224] <= s_work[7];
                keystream_block[287:256] <= s_work[8];
                keystream_block[319:288] <= s_work[9];
                keystream_block[351:320] <= s_work[10];
                keystream_block[383:352] <= s_work[11];
                keystream_block[415:384] <= s_work[12];
                keystream_block[447:416] <= s_work[13];
                keystream_block[479:448] <= s_work[14];
                keystream_block[511:480] <= s_work[15];
                done      <= 1'b1;
                busy      <= 1'b0;
                round_cnt <= 5'd0;
            end

            // ------------------------------------------------------------------
            // Plaintext inspection bus (Section 3.1)
            // XOR ciphertext bytes against the live keystream_block.
            // Caller must not assert ct_valid before done has fired for this
            // packet's block. ks_byte_idx resets to 0 on ct_eof.
            // ------------------------------------------------------------------
            if (ct_valid) begin
                pt_valid <= 1'b1;
                pt_sof   <= ct_sof;
                pt_eof   <= ct_eof;
                // Variable-index byte select from 512-bit register.
                // Byte N lives at keystream_block[(N*8)+7 : N*8].
                pt_data  <= ct_data ^ keystream_block[ks_byte_idx*8 +: 8];
                if (ct_eof)
                    ks_byte_idx <= 6'd0;
                else
                    ks_byte_idx <= ks_byte_idx + 6'd1;
            end

        end // else (not rst)
    end // always

endmodule

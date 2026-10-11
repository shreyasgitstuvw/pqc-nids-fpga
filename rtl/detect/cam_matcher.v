// ============================================================================
// Module: cam_matcher
// Description: Streaming Content-Addressable Memory (CAM) Signature Matcher
// Target: ZedBoard XC7Z020 @ 100 MHz
// Owner: Member B (Lane 2 - Threat Detection)
// Interface: Plaintext Inspection Bus (Interface Contract v1.1.0 Section 3.1)
// Egress: Uniform Strobe Verdict to drop_engine.v (Interface Contract Section 6)
// ============================================================================

`timescale 1ns / 1ps
`include "reason_codes.vh"

module cam_matcher (
    input  wire        clk,
    input  wire        rst,

    // ---- Plaintext Inspection Bus (Interface Contract v1.1.0 Section 3.1) ---
    // Driven by Member D (chacha_poly.v) after decryption
    input  wire        pt_valid,      // Asserted for every cycle carrying a valid plaintext byte
    input  wire [7:0]  pt_data,       // Decrypted payload byte
    input  wire        pt_sof,        // First plaintext byte of this packet
    input  wire        pt_eof,        // Last plaintext byte of this packet
    input  wire        pt_tag_ok,     // Qualifies packet: 1 = Poly1305 tag verified
    input  wire        pt_tag_valid,  // 1-cycle strobe: pt_tag_ok is meaningful

    // ---- Drop Engine Verdict Interface (Interface Contract Section 6) --------
    output reg         v_cam_valid,   // 1-cycle strobe: CAM verdict resolved
    output reg         v_cam_fail,    // 1 = attack signature matched, 0 = clean
    output reg  [3:0]  v_cam_reason,  // 4'h4 (RC_SIGNATURE) if fail, else 4'h0 (RC_NONE)

    // ---- Telemetry & Diagnostics ---------------------------------------------
    output reg  [4:0]  match_sig_id,  // Matched signature ID (1..16, 0 = none)
    output reg  [15:0] match_offset   // Payload byte offset where match occurred
);

    // =========================================================================
    // Sliding Window History Register (15 prior bytes + current byte = 16 bytes)
    // =========================================================================
    reg [7:0] w [1:15];
    reg [15:0] byte_counter;

    wire [7:0] b0 = pt_data; // Current streaming byte

    // =========================================================================
    // Parallel 16-Way Signature Match Logic (1 Cycle Combinational Lookup)
    // =========================================================================
    // Sig 01: LOG4SHELL ("${jndi:") -- 7 bytes
    wire m_sig01 = (b0 == 8'h3A) && (w[1] == 8'h69) && (w[2] == 8'h64) &&
                   (w[3] == 8'h6E) && (w[4] == 8'h6A) && (w[5] == 8'h7B) && (w[6] == 8'h24);

    // Sig 02: SHELL_EXEC ("/bin/sh") -- 7 bytes
    wire m_sig02 = (b0 == 8'h68) && (w[1] == 8'h73) && (w[2] == 8'h2F) &&
                   (w[3] == 8'h6E) && (w[4] == 8'h69) && (w[5] == 8'h62) && (w[6] == 8'h2F);

    // Sig 03: REVERSE_SHELL ("/bin/bash") -- 9 bytes
    wire m_sig03 = (b0 == 8'h68) && (w[1] == 8'h73) && (w[2] == 8'h61) &&
                   (w[3] == 8'h62) && (w[4] == 8'h2F) && (w[5] == 8'h6E) &&
                   (w[6] == 8'h69) && (w[7] == 8'h62) && (w[8] == 8'h2F);

    // Sig 04: WEBSHELL_CMD ("cmd.exe") -- 7 bytes
    wire m_sig04 = (b0 == 8'h65) && (w[1] == 8'h78) && (w[2] == 8'h65) &&
                   (w[3] == 8'h2E) && (w[4] == 8'h64) && (w[5] == 8'h6D) && (w[6] == 8'h63);

    // Sig 05: POWERSHELL ("powershell") -- 10 bytes
    wire m_sig05 = (b0 == 8'h6C) && (w[1] == 8'h6C) && (w[2] == 8'h65) &&
                   (w[3] == 8'h68) && (w[4] == 8'h73) && (w[5] == 8'h72) &&
                   (w[6] == 8'h65) && (w[7] == 8'h77) && (w[8] == 8'h6F) && (w[9] == 8'h70);

    // Sig 06: NOP_SLED (8 x 0x90) -- 8 bytes
    wire m_sig06 = (b0 == 8'h90) && (w[1] == 8'h90) && (w[2] == 8'h90) &&
                   (w[3] == 8'h90) && (w[4] == 8'h90) && (w[5] == 8'h90) &&
                   (w[6] == 8'h90) && (w[7] == 8'h90);

    // Sig 07: SQL_INJECTION ("UNION+SELECT" or "UNION SELECT") -- 12 bytes
    wire m_sig07 = (b0 == 8'h54) && (w[1] == 8'h43) && (w[2] == 8'h45) &&
                   (w[3] == 8'h4C) && (w[4] == 8'h45) && (w[5] == 8'h53) &&
                   ((w[6] == 8'h2B) || (w[6] == 8'h20)) &&
                   (w[7] == 8'h4E) && (w[8] == 8'h4F) && (w[9] == 8'h49) &&
                   (w[10] == 8'h4E) && (w[11] == 8'h55);

    // Sig 08: PHP_EVAL ("eval(base64") -- 11 bytes
    wire m_sig08 = (b0 == 8'h34) && (w[1] == 8'h36) && (w[2] == 8'h65) &&
                   (w[3] == 8'h73) && (w[4] == 8'h61) && (w[5] == 8'h62) &&
                   (w[6] == 8'h28) && (w[7] == 8'h6C) && (w[8] == 8'h61) &&
                   (w[9] == 8'h76) && (w[10] == 8'h65);

    // Sig 09: PHP_SYSTEM ("system($_GET") -- 12 bytes
    wire m_sig09 = (b0 == 8'h54) && (w[1] == 8'h45) && (w[2] == 8'h47) &&
                   (w[3] == 8'h5F) && (w[4] == 8'h24) && (w[5] == 8'h28) &&
                   (w[6] == 8'h6D) && (w[7] == 8'h65) && (w[8] == 8'h74) &&
                   (w[9] == 8'h73) && (w[10] == 8'h79) && (w[11] == 8'h73);

    // Sig 10: ETC_PASSWD ("/etc/passwd") -- 11 bytes
    wire m_sig10 = (b0 == 8'h64) && (w[1] == 8'h77) && (w[2] == 8'h73) &&
                   (w[3] == 8'h73) && (w[4] == 8'h61) && (w[5] == 8'h70) &&
                   (w[6] == 8'h2F) && (w[7] == 8'h63) && (w[8] == 8'h74) &&
                   (w[9] == 8'h65) && (w[10] == 8'h2F);

    // Sig 11: XSS_SCRIPT ("<script>") -- 8 bytes
    wire m_sig11 = (b0 == 8'h3E) && (w[1] == 8'h74) && (w[2] == 8'h70) &&
                   (w[3] == 8'h69) && (w[4] == 8'h72) && (w[5] == 8'h63) &&
                   (w[6] == 8'h73) && (w[7] == 8'h3C);

    // Sig 12: PATH_TRAVERSAL ("../../") -- 6 bytes
    wire m_sig12 = (b0 == 8'h2F) && (w[1] == 8'h2E) && (w[2] == 8'h2E) &&
                   (w[3] == 8'h2F) && (w[4] == 8'h2E) && (w[5] == 8'h2E);

    // Sig 13: WGET_DROPPER ("wget ") -- 5 bytes
    wire m_sig13 = (b0 == 8'h20) && (w[1] == 8'h74) && (w[2] == 8'h65) &&
                   (w[3] == 8'h67) && (w[4] == 8'h77);

    // Sig 14: CURL_DROPPER ("curl ") -- 5 bytes
    wire m_sig14 = (b0 == 8'h20) && (w[1] == 8'h6C) && (w[2] == 8'h72) &&
                   (w[3] == 8'h75) && (w[4] == 8'h63);

    // Sig 15: CHMOD_EXEC ("chmod +x") -- 8 bytes
    wire m_sig15 = (b0 == 8'h78) && (w[1] == 8'h2B) && (w[2] == 8'h20) &&
                   (w[3] == 8'h64) && (w[4] == 8'h6F) && (w[5] == 8'h6D) &&
                   (w[6] == 8'h68) && (w[7] == 8'h63);

    // Sig 16: RECON_WHOAMI ("whoami") -- 6 bytes
    wire m_sig16 = (b0 == 8'h69) && (w[1] == 8'h6D) && (w[2] == 8'h61) &&
                   (w[3] == 8'h6F) && (w[4] == 8'h68) && (w[5] == 8'h77);

    // Current cycle match evaluation (only valid when pt_valid is high)
    wire [15:0] match_vec = {
        m_sig16, m_sig15, m_sig14, m_sig13,
        m_sig12, m_sig11, m_sig10, m_sig09,
        m_sig08, m_sig07, m_sig06, m_sig05,
        m_sig04, m_sig03, m_sig02, m_sig01
    };

    wire any_match_now = pt_valid && (|match_vec);

    // Priority encoder for matched signature ID
    function [4:0] encode_sig_id;
        input [15:0] vec;
        begin
            if      (vec[0])  encode_sig_id = 5'd1;
            else if (vec[1])  encode_sig_id = 5'd2;
            else if (vec[2])  encode_sig_id = 5'd3;
            else if (vec[3])  encode_sig_id = 5'd4;
            else if (vec[4])  encode_sig_id = 5'd5;
            else if (vec[5])  encode_sig_id = 5'd6;
            else if (vec[6])  encode_sig_id = 5'd7;
            else if (vec[7])  encode_sig_id = 5'd8;
            else if (vec[8])  encode_sig_id = 5'd9;
            else if (vec[9])  encode_sig_id = 5'd10;
            else if (vec[10]) encode_sig_id = 5'd11;
            else if (vec[11]) encode_sig_id = 5'd12;
            else if (vec[12]) encode_sig_id = 5'd13;
            else if (vec[13]) encode_sig_id = 5'd14;
            else if (vec[14]) encode_sig_id = 5'd15;
            else if (vec[15]) encode_sig_id = 5'd16;
            else              encode_sig_id = 5'd0;
        end
    endfunction

    // Signature pattern length lookup for accurate offset calculation
    function [4:0] get_sig_len;
        input [4:0] id;
        begin
            case (id)
                5'd1:  get_sig_len = 5'd7;  // ${jndi:
                5'd2:  get_sig_len = 5'd7;  // /bin/sh
                5'd3:  get_sig_len = 5'd9;  // /bin/bash
                5'd4:  get_sig_len = 5'd7;  // cmd.exe
                5'd5:  get_sig_len = 5'd10; // powershell
                5'd6:  get_sig_len = 5'd8;  // NOP sled
                5'd7:  get_sig_len = 5'd12; // UNION+SELECT
                5'd8:  get_sig_len = 5'd11; // eval(base64
                5'd9:  get_sig_len = 5'd12; // system($_GET
                5'd10: get_sig_len = 5'd11; // /etc/passwd
                5'd11: get_sig_len = 5'd8;  // <script>
                5'd12: get_sig_len = 5'd6;  // ../../
                5'd13: get_sig_len = 5'd5;  // wget 
                5'd14: get_sig_len = 5'd5;  // curl 
                5'd15: get_sig_len = 5'd8;  // chmod +x
                5'd16: get_sig_len = 5'd6;  // whoami
                default: get_sig_len = 5'd0;
            endcase
        end
    endfunction

    // =========================================================================
    // Packet Evaluation & Latch State
    // =========================================================================
    reg match_latched;
    reg eof_pending;

    integer i;

    always @(posedge clk) begin
        if (rst) begin
            v_cam_valid   <= 1'b0;
            v_cam_fail    <= 1'b0;
            v_cam_reason  <= `RC_NONE;
            match_sig_id  <= 5'd0;
            match_offset  <= 16'd0;
            byte_counter  <= 16'd0;
            match_latched <= 1'b0;
            eof_pending   <= 1'b0;
            for (i = 1; i <= 15; i = i + 1) begin
                w[i] <= 8'd0;
            end
        end else begin
            // Default 1-cycle strobe clear
            v_cam_valid <= 1'b0;

            // -----------------------------------------------------------------
            // Stream Processing Window
            // -----------------------------------------------------------------
            if (pt_valid) begin
                // Update sliding window history & counter
                if (pt_sof) begin
                    byte_counter  <= 16'd1;
                    match_latched <= 1'b0;
                    match_sig_id  <= 5'd0;
                    match_offset  <= 16'd0;
                    w[1]          <= b0;
                    for (i = 2; i <= 15; i = i + 1) begin
                        w[i] <= 8'd0;
                    end
                end else begin
                    byte_counter  <= byte_counter + 16'd1;
                    w[1]          <= b0;
                    for (i = 2; i <= 15; i = i + 1) begin
                        w[i] <= w[i-1];
                    end
                end

                // Latch match if detected
                if (any_match_now && !match_latched) begin
                    match_latched <= 1'b1;
                    match_sig_id  <= encode_sig_id(match_vec);
                    match_offset  <= (pt_sof ? 16'd1 : (byte_counter + 16'd1)) - {11'd0, get_sig_len(encode_sig_id(match_vec))};
                end

                // Latch EOF to trigger 1-cycle registered verdict strobe
                if (pt_eof) begin
                    eof_pending <= 1'b1;
                end
            end

            // -----------------------------------------------------------------
            // Egress Verdict Generation (1 cycle after pt_eof)
            // -----------------------------------------------------------------
            if (eof_pending) begin
                v_cam_valid  <= 1'b1;
                v_cam_fail   <= match_latched;
                v_cam_reason <= match_latched ? `RC_SIGNATURE : `RC_NONE;
                eof_pending  <= 1'b0;
            end
        end
    end

endmodule

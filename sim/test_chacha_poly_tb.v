// sim/test_chacha_poly_tb.v
//
// Self-checking testbench for ChaCha20-Poly1305 AEAD Core (chacha_poly.v)
// Verifies compliance with RFC 8439 Section 2.8:
//   Test 1: RFC 8439 Sec 2.8.2 Official AEAD Test Vector (114 bytes)
//   Test 2: Ciphertext tamper detection (RC_BAD_TAG = 4'h7)
//   Test 3: AAD tamper detection (RC_BAD_TAG = 4'h7)
//   Test 4: Tag tamper detection (RC_BAD_TAG = 4'h7)
//
// Member D (@control) -- pqc-nids-fpga

`timescale 1ns / 1ps
`include "reason_codes.vh"

module test_chacha_poly_tb;

    reg         clk;
    reg         rst;

    reg         key_valid;
    reg [255:0] key;
    reg [95:0]  nonce;

    reg [127:0] aad_data;
    reg [4:0]   aad_len;

    reg         ct_valid;
    reg [7:0]   ct_data;
    reg         ct_sof;
    reg         ct_eof;

    reg [127:0] expected_tag;

    wire        ready;
    wire        busy;
    wire        done;

    wire        pt_valid;
    wire [7:0]  pt_data;
    wire        pt_sof;
    wire        pt_eof;
    wire        pt_tag_ok;
    wire        pt_tag_valid;

    wire        v_poly_valid;
    wire        v_poly_fail;
    wire [3:0]  v_poly_reason;

    wire [127:0] tag_out;
    wire        tag_ok;

    // Instantiate DUT
    chacha_poly u_dut (
        .clk          (clk),
        .rst          (rst),
        .key_valid    (key_valid),
        .key          (key),
        .nonce        (nonce),
        .aad_data     (aad_data),
        .aad_len      (aad_len),
        .ct_valid     (ct_valid),
        .ct_data      (ct_data),
        .ct_sof       (ct_sof),
        .ct_eof       (ct_eof),
        .expected_tag (expected_tag),
        .ready        (ready),
        .busy         (busy),
        .done         (done),
        .pt_valid     (pt_valid),
        .pt_data      (pt_data),
        .pt_sof       (pt_sof),
        .pt_eof       (pt_eof),
        .pt_tag_ok    (pt_tag_ok),
        .pt_tag_valid (pt_tag_valid),
        .v_poly_valid (v_poly_valid),
        .v_poly_fail  (v_poly_fail),
        .v_poly_reason(v_poly_reason),
        .tag_out      (tag_out),
        .tag_ok       (tag_ok)
    );

    // 100 MHz clock generation (10 ns period)
    always #5 clk = ~clk;

    integer errors;
    integer i;
    reg [7:0] ct_arr [0:113];
    reg [7:0] exp_pt [0:113];
    integer pt_idx;
    reg     check_pt;

    // RFC 8439 Section 2.8.2 Test Constants:
    localparam [255:0] RFC_KEY   = 256'h9f9e9d9c9b9a999897969594939291908f8e8d8c8b8a89888786858483828180;
    localparam [95:0]  RFC_NONCE = 96'h474645444342414000000007;
    localparam [127:0] RFC_AAD   = 128'hc7c6c5c4c3c2c1c053525150;
    localparam [4:0]   RFC_AAD_LEN = 5'd12;
    localparam [127:0] RFC_TAG   = 128'h910660d0cb2e907e6ae2094f590be11a;

    initial begin
        clk          = 0;
        rst          = 1;
        key_valid    = 0;
        key          = 256'd0;
        nonce        = 96'd0;
        aad_data     = 128'd0;
        aad_len      = 5'd0;
        ct_valid     = 0;
        ct_data      = 8'd0;
        ct_sof       = 0;
        ct_eof       = 0;
        expected_tag = 128'd0;
        errors       = 0;

        // Ciphertext bytes from RFC 8439 Sec 2.8.2
        ct_arr[0] = 8'hd3; ct_arr[1] = 8'h1a; ct_arr[2] = 8'h8d; ct_arr[3] = 8'h34;
        ct_arr[4] = 8'h64; ct_arr[5] = 8'h8e; ct_arr[6] = 8'h60; ct_arr[7] = 8'hdb;
        ct_arr[8] = 8'h7b; ct_arr[9] = 8'h86; ct_arr[10] = 8'haf; ct_arr[11] = 8'hbc;
        ct_arr[12] = 8'h53; ct_arr[13] = 8'hef; ct_arr[14] = 8'h7e; ct_arr[15] = 8'hc2;
        ct_arr[16] = 8'ha4; ct_arr[17] = 8'had; ct_arr[18] = 8'hed; ct_arr[19] = 8'h51;
        ct_arr[20] = 8'h29; ct_arr[21] = 8'h6e; ct_arr[22] = 8'h08; ct_arr[23] = 8'hfe;
        ct_arr[24] = 8'ha9; ct_arr[25] = 8'he2; ct_arr[26] = 8'hb5; ct_arr[27] = 8'ha7;
        ct_arr[28] = 8'h36; ct_arr[29] = 8'hee; ct_arr[30] = 8'h62; ct_arr[31] = 8'hd6;
        ct_arr[32] = 8'h3d; ct_arr[33] = 8'hbe; ct_arr[34] = 8'ha4; ct_arr[35] = 8'h5e;
        ct_arr[36] = 8'h8c; ct_arr[37] = 8'ha9; ct_arr[38] = 8'h67; ct_arr[39] = 8'h12;
        ct_arr[40] = 8'h82; ct_arr[41] = 8'hfa; ct_arr[42] = 8'hfb; ct_arr[43] = 8'h69;
        ct_arr[44] = 8'hda; ct_arr[45] = 8'h92; ct_arr[46] = 8'h72; ct_arr[47] = 8'h8b;
        ct_arr[48] = 8'h1a; ct_arr[49] = 8'h71; ct_arr[50] = 8'hde; ct_arr[51] = 8'h0a;
        ct_arr[52] = 8'h9e; ct_arr[53] = 8'h06; ct_arr[54] = 8'h0b; ct_arr[55] = 8'h29;
        ct_arr[56] = 8'h05; ct_arr[57] = 8'hd6; ct_arr[58] = 8'ha5; ct_arr[59] = 8'hb6;
        ct_arr[60] = 8'h7e; ct_arr[61] = 8'hcd; ct_arr[62] = 8'h3b; ct_arr[63] = 8'h36;
        ct_arr[64] = 8'h92; ct_arr[65] = 8'hdd; ct_arr[66] = 8'hbd; ct_arr[67] = 8'h7f;
        ct_arr[68] = 8'h2d; ct_arr[69] = 8'h77; ct_arr[70] = 8'h8b; ct_arr[71] = 8'h8c;
        ct_arr[72] = 8'h98; ct_arr[73] = 8'h03; ct_arr[74] = 8'hae; ct_arr[75] = 8'he3;
        ct_arr[76] = 8'h28; ct_arr[77] = 8'h09; ct_arr[78] = 8'h1b; ct_arr[79] = 8'h58;
        ct_arr[80] = 8'hfa; ct_arr[81] = 8'hb3; ct_arr[82] = 8'h24; ct_arr[83] = 8'he4;
        ct_arr[84] = 8'hfa; ct_arr[85] = 8'hd6; ct_arr[86] = 8'h75; ct_arr[87] = 8'h94;
        ct_arr[88] = 8'h55; ct_arr[89] = 8'h85; ct_arr[90] = 8'h80; ct_arr[91] = 8'h8b;
        ct_arr[92] = 8'h48; ct_arr[93] = 8'h31; ct_arr[94] = 8'hd7; ct_arr[95] = 8'hbc;
        ct_arr[96] = 8'h3f; ct_arr[97] = 8'hf4; ct_arr[98] = 8'hde; ct_arr[99] = 8'hf0;
        ct_arr[100] = 8'h8e; ct_arr[101] = 8'h4b; ct_arr[102] = 8'h7a; ct_arr[103] = 8'h9d;
        ct_arr[104] = 8'he5; ct_arr[105] = 8'h76; ct_arr[106] = 8'hd2; ct_arr[107] = 8'h65;
        ct_arr[108] = 8'h86; ct_arr[109] = 8'hce; ct_arr[110] = 8'hc6; ct_arr[111] = 8'h4b;
        ct_arr[112] = 8'h61; ct_arr[113] = 8'h16;

        // Expected Plaintext: "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
        exp_pt[0]  = "L"; exp_pt[1]  = "a"; exp_pt[2]  = "d"; exp_pt[3]  = "i";
        exp_pt[4]  = "e"; exp_pt[5]  = "s"; exp_pt[6]  = " "; exp_pt[7]  = "a";
        exp_pt[8]  = "n"; exp_pt[9]  = "d"; exp_pt[10] = " "; exp_pt[11] = "G";
        exp_pt[12] = "e"; exp_pt[13] = "n"; exp_pt[14] = "t"; exp_pt[15] = "l";
        exp_pt[16] = "e"; exp_pt[17] = "m"; exp_pt[18] = "e"; exp_pt[19] = "n";
        exp_pt[20] = " "; exp_pt[21] = "o"; exp_pt[22] = "f"; exp_pt[23] = " ";
        exp_pt[24] = "t"; exp_pt[25] = "h"; exp_pt[26] = "e"; exp_pt[27] = " ";
        exp_pt[28] = "c"; exp_pt[29] = "l"; exp_pt[30] = "a"; exp_pt[31] = "s";
        exp_pt[32] = "s"; exp_pt[33] = " "; exp_pt[34] = "o"; exp_pt[35] = "f";
        exp_pt[36] = " "; exp_pt[37] = "'"; exp_pt[38] = "9"; exp_pt[39] = "9";
        exp_pt[40] = ":"; exp_pt[41] = " "; exp_pt[42] = "I"; exp_pt[43] = "f";
        exp_pt[44] = " "; exp_pt[45] = "I"; exp_pt[46] = " "; exp_pt[47] = "c";
        exp_pt[48] = "o"; exp_pt[49] = "u"; exp_pt[50] = "l"; exp_pt[51] = "d";
        exp_pt[52] = " "; exp_pt[53] = "o"; exp_pt[54] = "f"; exp_pt[55] = "f";
        exp_pt[56] = "e"; exp_pt[57] = "r"; exp_pt[58] = " "; exp_pt[59] = "y";
        exp_pt[60] = "o"; exp_pt[61] = "u"; exp_pt[62] = " "; exp_pt[63] = "o";
        exp_pt[64] = "n"; exp_pt[65] = "l"; exp_pt[66] = "y"; exp_pt[67] = " ";
        exp_pt[68] = "o"; exp_pt[69] = "n"; exp_pt[70] = "e"; exp_pt[71] = " ";
        exp_pt[72] = "t"; exp_pt[73] = "i"; exp_pt[74] = "p"; exp_pt[75] = " ";
        exp_pt[76] = "f"; exp_pt[77] = "o"; exp_pt[78] = "r"; exp_pt[79] = " ";
        exp_pt[80] = "t"; exp_pt[81] = "h"; exp_pt[82] = "e"; exp_pt[83] = " ";
        exp_pt[84] = "f"; exp_pt[85] = "u"; exp_pt[86] = "t"; exp_pt[87] = "u";
        exp_pt[88] = "r"; exp_pt[89] = "e"; exp_pt[90] = ","; exp_pt[91] = " ";
        exp_pt[92] = "s"; exp_pt[93] = "u"; exp_pt[94] = "n"; exp_pt[95] = "s";
        exp_pt[96] = "c"; exp_pt[97] = "r"; exp_pt[98] = "e"; exp_pt[99] = "e";
        exp_pt[100]= "n"; exp_pt[101]= " "; exp_pt[102]= "w"; exp_pt[103]= "o";
        exp_pt[104]= "u"; exp_pt[105]= "l"; exp_pt[106]= "d"; exp_pt[107]= " ";
        exp_pt[108]= "b"; exp_pt[109]= "e"; exp_pt[110]= " "; exp_pt[111]= "i";
        exp_pt[112]= "t"; exp_pt[113]= ".";

        #20;
        @(negedge clk);
        rst = 0;
        #10;

        $display("================================================================================");
        $display("Starting chacha_poly.v Self-Checking Test Suite (RFC 8439 Section 2.8)");
        $display("================================================================================");

        // =====================================================================
        // Test 1: RFC 8439 Section 2.8.2 AEAD Authenticated Decryption
        // =====================================================================
        $display("\n--- Test 1: RFC 8439 Sec 2.8.2 AEAD Authenticated Decryption (114 bytes) ---");
        @(negedge clk);
        key          = RFC_KEY;
        nonce        = RFC_NONCE;
        aad_data     = RFC_AAD;
        aad_len      = RFC_AAD_LEN;
        expected_tag = RFC_TAG;
        check_pt     = 1;
        pt_idx       = 0;
        key_valid    = 1;
        @(negedge clk);
        key_valid    = 0;

        // Wait until core is ready for ciphertext streaming
        while (!ready) @(negedge clk);

        $display("  DUT ready for ciphertext stream. Streaming 114 bytes...");

        pt_idx = 0;
        for (i = 0; i < 114; i = i + 1) begin
            // If DUT pauses between blocks (for multi-block ChaCha20 step), wait until ready
            while (!ready) @(negedge clk);

            @(negedge clk);
            ct_valid = 1;
            ct_data  = ct_arr[i];
            ct_sof   = (i == 0);
            ct_eof   = (i == 113);
        end
        @(negedge clk);
        ct_valid = 0;
        ct_sof   = 0;
        ct_eof   = 0;

        // Await done
        while (!done) @(negedge clk);

        $display("  AEAD completion: tag_ok=%b, pt_tag_ok=%b, v_poly_fail=%b, reason=%h",
                 tag_ok, pt_tag_ok, v_poly_fail, v_poly_reason);
        $display("  Computed tag: 0x%032x", tag_out);
        $display("  Expected tag: 0x%032x", RFC_TAG);

        if (tag_out !== RFC_TAG) begin
            $display("[FAIL] Test 1: Tag mismatch!");
            errors = errors + 1;
        end else if (tag_ok !== 1'b1 || pt_tag_ok !== 1'b1) begin
            $display("[FAIL] Test 1: Tag ok flag mismatch (expected 1)");
            errors = errors + 1;
        end else if (v_poly_valid !== 1'b1 || v_poly_fail !== 1'b0 || v_poly_reason !== `RC_NONE) begin
            $display("[FAIL] Test 1: Drop engine verdict mismatch: valid=%b fail=%b reason=%h",
                     v_poly_valid, v_poly_fail, v_poly_reason);
            errors = errors + 1;
        end else begin
            $display("[PASS] Test 1: RFC 8439 Sec 2.8.2 AEAD exact match (tag_ok=1, verdict=PASS)");
        end

        check_pt = 0;
        #30;

        // =====================================================================
        // Test 2: Ciphertext Tamper Detection
        // =====================================================================
        $display("\n--- Test 2: Ciphertext Tamper Detection (1 bit corrupted) ---");
        @(negedge clk);
        key          = RFC_KEY;
        nonce        = RFC_NONCE;
        aad_data     = RFC_AAD;
        aad_len      = RFC_AAD_LEN;
        expected_tag = RFC_TAG;
        key_valid    = 1;
        @(negedge clk);
        key_valid    = 0;

        while (!ready) @(negedge clk);

        for (i = 0; i < 114; i = i + 1) begin
            while (!ready) @(negedge clk);
            @(negedge clk);
            ct_valid = 1;
            // Corrupt byte 0
            ct_data  = (i == 0) ? (ct_arr[i] ^ 8'h01) : ct_arr[i];
            ct_sof   = (i == 0);
            ct_eof   = (i == 113);
        end
        @(negedge clk);
        ct_valid = 0;
        ct_sof   = 0;
        ct_eof   = 0;

        while (!done) @(negedge clk);

        if (tag_ok !== 1'b0 || pt_tag_ok !== 1'b0) begin
            $display("[FAIL] Test 2: Tampered ciphertext was incorrectly accepted!");
            errors = errors + 1;
        end else if (v_poly_valid !== 1'b1 || v_poly_fail !== 1'b1 || v_poly_reason !== `RC_BAD_TAG) begin
            $display("[FAIL] Test 2: Expected RC_BAD_TAG (4'h7), got valid=%b fail=%b reason=%h",
                     v_poly_valid, v_poly_fail, v_poly_reason);
            errors = errors + 1;
        end else begin
            $display("[PASS] Test 2: Ciphertext tamper caught: tag_ok=0, v_poly_fail=1, reason=RC_BAD_TAG (4'h7)");
        end

        #30;

        // =====================================================================
        // Test 3: AAD Tamper Detection
        // =====================================================================
        $display("\n--- Test 3: AAD Tamper Detection (1 bit corrupted) ---");
        @(negedge clk);
        key          = RFC_KEY;
        nonce        = RFC_NONCE;
        // Corrupt 1 bit of AAD
        aad_data     = RFC_AAD ^ 128'h01;
        aad_len      = RFC_AAD_LEN;
        expected_tag = RFC_TAG;
        key_valid    = 1;
        @(negedge clk);
        key_valid    = 0;

        while (!ready) @(negedge clk);

        for (i = 0; i < 114; i = i + 1) begin
            while (!ready) @(negedge clk);
            @(negedge clk);
            ct_valid = 1;
            ct_data  = ct_arr[i];
            ct_sof   = (i == 0);
            ct_eof   = (i == 113);
        end
        @(negedge clk);
        ct_valid = 0;
        ct_sof   = 0;
        ct_eof   = 0;

        while (!done) @(negedge clk);

        if (tag_ok !== 1'b0 || pt_tag_ok !== 1'b0) begin
            $display("[FAIL] Test 3: Tampered AAD was incorrectly accepted!");
            errors = errors + 1;
        end else if (v_poly_valid !== 1'b1 || v_poly_fail !== 1'b1 || v_poly_reason !== `RC_BAD_TAG) begin
            $display("[FAIL] Test 3: Expected RC_BAD_TAG (4'h7), got valid=%b fail=%b reason=%h",
                     v_poly_valid, v_poly_fail, v_poly_reason);
            errors = errors + 1;
        end else begin
            $display("[PASS] Test 3: AAD tamper caught: tag_ok=0, v_poly_fail=1, reason=RC_BAD_TAG (4'h7)");
        end

        #30;

        // =====================================================================
        // Test 4: Expected Tag Tamper Detection
        // =====================================================================
        $display("\n--- Test 4: Expected Tag Tamper Detection ---");
        @(negedge clk);
        key          = RFC_KEY;
        nonce        = RFC_NONCE;
        aad_data     = RFC_AAD;
        aad_len      = RFC_AAD_LEN;
        // Corrupt expected tag
        expected_tag = RFC_TAG ^ 128'h01;
        key_valid    = 1;
        @(negedge clk);
        key_valid    = 0;

        while (!ready) @(negedge clk);

        for (i = 0; i < 114; i = i + 1) begin
            while (!ready) @(negedge clk);
            @(negedge clk);
            ct_valid = 1;
            ct_data  = ct_arr[i];
            ct_sof   = (i == 0);
            ct_eof   = (i == 113);
        end
        @(negedge clk);
        ct_valid = 0;
        ct_sof   = 0;
        ct_eof   = 0;

        while (!done) @(negedge clk);

        if (tag_ok !== 1'b0 || pt_tag_ok !== 1'b0) begin
            $display("[FAIL] Test 4: Corrupted tag was incorrectly accepted!");
            errors = errors + 1;
        end else if (v_poly_valid !== 1'b1 || v_poly_fail !== 1'b1 || v_poly_reason !== `RC_BAD_TAG) begin
            $display("[FAIL] Test 4: Expected RC_BAD_TAG (4'h7), got valid=%b fail=%b reason=%h",
                     v_poly_valid, v_poly_fail, v_poly_reason);
            errors = errors + 1;
        end else begin
            $display("[PASS] Test 4: Corrupted tag caught: tag_ok=0, v_poly_fail=1, reason=RC_BAD_TAG (4'h7)");
        end

        // Final Summary
        $display("\n================================================================================");
        if (errors == 0) begin
            $display("ALL 4 CHACHA20-POLY1305 AEAD TESTS PASSED SUCCESSFULLY! (0 errors)");
        end else begin
            $display("CHACHA20-POLY1305 TEST SUITE FAILED with %0d errors!", errors);
        end
        $display("================================================================================");

        #50;
        $finish;
    end

    // Monitor plaintext output bytes
    always @(posedge clk) begin
        if (!rst && pt_valid && check_pt) begin
            if (pt_data !== exp_pt[pt_idx]) begin
                $display("  [ERROR] Plaintext byte %0d mismatch: got %02h ('%c'), expected %02h ('%c')",
                         pt_idx, pt_data, pt_data, exp_pt[pt_idx], exp_pt[pt_idx]);
                errors = errors + 1;
            end
            pt_idx = pt_idx + 1;
        end
    end

endmodule

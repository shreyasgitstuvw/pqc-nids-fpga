// sim/test_chacha20_tb.v
//
// Self-checking testbench for rtl/crypto/chacha_poly/chacha20.v
// Member D (@control)
//
// Verifies:
//   1. RFC 8439 Section 2.3.2: 64-byte ChaCha20 block function (exact byte-by-byte match)
//   2. Block latency: exactly 22 cycles from start to done
//   3. Contract v1.1.0 Section 3.1 Plaintext Inspection Bus:
//      Streaming decryption of RFC 8439 Section 2.4.2 ciphertext (114 bytes across 2 blocks)
//      with correct pt_sof / pt_eof propagation.

`timescale 1ns / 1ps

module test_chacha20_tb;

    reg          clk;
    reg          rst;

    reg          start;
    reg  [255:0] key;
    reg  [31:0]  counter;
    reg  [95:0]  nonce;
    wire         busy;
    wire         done;
    wire [511:0] keystream_block;

    reg          ct_valid;
    reg  [7:0]   ct_data;
    reg          ct_sof;
    reg          ct_eof;
    wire         pt_valid;
    wire [7:0]   pt_data;
    wire         pt_sof;
    wire         pt_eof;

    // Instantiate DUT
    chacha20 dut (
        .clk(clk),
        .rst(rst),
        .start(start),
        .key(key),
        .counter(counter),
        .nonce(nonce),
        .busy(busy),
        .done(done),
        .keystream_block(keystream_block),
        .ct_valid(ct_valid),
        .ct_data(ct_data),
        .ct_sof(ct_sof),
        .ct_eof(ct_eof),
        .pt_valid(pt_valid),
        .pt_data(pt_data),
        .pt_sof(pt_sof),
        .pt_eof(pt_eof)
    );

    // 100 MHz clock (10 ns period)
    always #5 clk = ~clk;

    integer test_errors;
    integer cycle_count;
    integer i;
    reg [7:0] actual_byte;

    // Expected 64-byte block from RFC 8439 Section 2.3.2
    reg [7:0] exp_block_2_3 [0:63];

    // RFC 8439 Section 2.4.2 114-byte test vectors
    reg [7:0] ct_stream_2_4 [0:113];
    reg [7:0] exp_pt_2_4   [0:113];

    task init_vectors;
        begin
            // RFC 8439 Sec 2.3.2 expected keystream bytes
            exp_block_2_3[0]  = 8'h10; exp_block_2_3[1]  = 8'hf1; exp_block_2_3[2]  = 8'he7; exp_block_2_3[3]  = 8'he4;
            exp_block_2_3[4]  = 8'hd1; exp_block_2_3[5]  = 8'h3b; exp_block_2_3[6]  = 8'h59; exp_block_2_3[7]  = 8'h15;
            exp_block_2_3[8]  = 8'h50; exp_block_2_3[9]  = 8'h0f; exp_block_2_3[10] = 8'hdd; exp_block_2_3[11] = 8'h1f;
            exp_block_2_3[12] = 8'ha3; exp_block_2_3[13] = 8'h20; exp_block_2_3[14] = 8'h71; exp_block_2_3[15] = 8'hc4;
            exp_block_2_3[16] = 8'hc7; exp_block_2_3[17] = 8'hd1; exp_block_2_3[18] = 8'hf4; exp_block_2_3[19] = 8'hc7;
            exp_block_2_3[20] = 8'h33; exp_block_2_3[21] = 8'hc0; exp_block_2_3[22] = 8'h68; exp_block_2_3[23] = 8'h03;
            exp_block_2_3[24] = 8'h04; exp_block_2_3[25] = 8'h22; exp_block_2_3[26] = 8'haa; exp_block_2_3[27] = 8'h9a;
            exp_block_2_3[28] = 8'hc3; exp_block_2_3[29] = 8'hd4; exp_block_2_3[30] = 8'h6c; exp_block_2_3[31] = 8'h4e;
            exp_block_2_3[32] = 8'hd2; exp_block_2_3[33] = 8'h82; exp_block_2_3[34] = 8'h64; exp_block_2_3[35] = 8'h46;
            exp_block_2_3[36] = 8'h07; exp_block_2_3[37] = 8'h9f; exp_block_2_3[38] = 8'haa; exp_block_2_3[39] = 8'h09;
            exp_block_2_3[40] = 8'h14; exp_block_2_3[41] = 8'hc2; exp_block_2_3[42] = 8'hd7; exp_block_2_3[43] = 8'h05;
            exp_block_2_3[44] = 8'hd9; exp_block_2_3[45] = 8'h8b; exp_block_2_3[46] = 8'h02; exp_block_2_3[47] = 8'ha2;
            exp_block_2_3[48] = 8'hb5; exp_block_2_3[49] = 8'h12; exp_block_2_3[50] = 8'h9c; exp_block_2_3[51] = 8'hd1;
            exp_block_2_3[52] = 8'hde; exp_block_2_3[53] = 8'h16; exp_block_2_3[54] = 8'h4e; exp_block_2_3[55] = 8'hb9;
            exp_block_2_3[56] = 8'hcb; exp_block_2_3[57] = 8'hd0; exp_block_2_3[58] = 8'h83; exp_block_2_3[59] = 8'he8;
            exp_block_2_3[60] = 8'ha2; exp_block_2_3[61] = 8'h50; exp_block_2_3[62] = 8'h3c; exp_block_2_3[63] = 8'h4e;

            // RFC 8439 Sec 2.4.2 ciphertext bytes:
            ct_stream_2_4[0]  = 8'h6e; ct_stream_2_4[1]  = 8'h2e; ct_stream_2_4[2]  = 8'h35; ct_stream_2_4[3]  = 8'h9a;
            ct_stream_2_4[4]  = 8'h25; ct_stream_2_4[5]  = 8'h68; ct_stream_2_4[6]  = 8'hf9; ct_stream_2_4[7]  = 8'h80;
            ct_stream_2_4[8]  = 8'h41; ct_stream_2_4[9]  = 8'hba; ct_stream_2_4[10] = 8'h07; ct_stream_2_4[11] = 8'h28;
            ct_stream_2_4[12] = 8'hdd; ct_stream_2_4[13] = 8'h0d; ct_stream_2_4[14] = 8'h69; ct_stream_2_4[15] = 8'h81;
            ct_stream_2_4[16] = 8'he9; ct_stream_2_4[17] = 8'h7e; ct_stream_2_4[18] = 8'h7a; ct_stream_2_4[19] = 8'hec;
            ct_stream_2_4[20] = 8'h1d; ct_stream_2_4[21] = 8'h43; ct_stream_2_4[22] = 8'h60; ct_stream_2_4[23] = 8'hc2;
            ct_stream_2_4[24] = 8'h0a; ct_stream_2_4[25] = 8'h27; ct_stream_2_4[26] = 8'haf; ct_stream_2_4[27] = 8'hcc;
            ct_stream_2_4[28] = 8'hfd; ct_stream_2_4[29] = 8'h9f; ct_stream_2_4[30] = 8'hae; ct_stream_2_4[31] = 8'h0b;
            ct_stream_2_4[32] = 8'hf9; ct_stream_2_4[33] = 8'h1b; ct_stream_2_4[34] = 8'h65; ct_stream_2_4[35] = 8'hc5;
            ct_stream_2_4[36] = 8'h52; ct_stream_2_4[37] = 8'h47; ct_stream_2_4[38] = 8'h33; ct_stream_2_4[39] = 8'hab;
            ct_stream_2_4[40] = 8'h8f; ct_stream_2_4[41] = 8'h59; ct_stream_2_4[42] = 8'h3d; ct_stream_2_4[43] = 8'hab;
            ct_stream_2_4[44] = 8'hcd; ct_stream_2_4[45] = 8'h62; ct_stream_2_4[46] = 8'hb3; ct_stream_2_4[47] = 8'h57;
            ct_stream_2_4[48] = 8'h16; ct_stream_2_4[49] = 8'h39; ct_stream_2_4[50] = 8'hd6; ct_stream_2_4[51] = 8'h24;
            ct_stream_2_4[52] = 8'he6; ct_stream_2_4[53] = 8'h51; ct_stream_2_4[54] = 8'h52; ct_stream_2_4[55] = 8'hab;
            ct_stream_2_4[56] = 8'h8f; ct_stream_2_4[57] = 8'h53; ct_stream_2_4[58] = 8'h0c; ct_stream_2_4[59] = 8'h35;
            ct_stream_2_4[60] = 8'h9f; ct_stream_2_4[61] = 8'h08; ct_stream_2_4[62] = 8'h61; ct_stream_2_4[63] = 8'hd8;
            ct_stream_2_4[64] = 8'h07; ct_stream_2_4[65] = 8'hca; ct_stream_2_4[66] = 8'h0d; ct_stream_2_4[67] = 8'hbf;
            ct_stream_2_4[68] = 8'h50; ct_stream_2_4[69] = 8'h0d; ct_stream_2_4[70] = 8'h6a; ct_stream_2_4[71] = 8'h61;
            ct_stream_2_4[72] = 8'h56; ct_stream_2_4[73] = 8'ha3; ct_stream_2_4[74] = 8'h8e; ct_stream_2_4[75] = 8'h08;
            ct_stream_2_4[76] = 8'h8a; ct_stream_2_4[77] = 8'h22; ct_stream_2_4[78] = 8'hb6; ct_stream_2_4[79] = 8'h5e;
            ct_stream_2_4[80] = 8'h52; ct_stream_2_4[81] = 8'hbc; ct_stream_2_4[82] = 8'h51; ct_stream_2_4[83] = 8'h4d;
            ct_stream_2_4[84] = 8'h16; ct_stream_2_4[85] = 8'hcc; ct_stream_2_4[86] = 8'hf8; ct_stream_2_4[87] = 8'h06;
            ct_stream_2_4[88] = 8'h81; ct_stream_2_4[89] = 8'h8c; ct_stream_2_4[90] = 8'he9; ct_stream_2_4[91] = 8'h1a;
            ct_stream_2_4[92] = 8'hb7; ct_stream_2_4[93] = 8'h79; ct_stream_2_4[94] = 8'h37; ct_stream_2_4[95] = 8'h36;
            ct_stream_2_4[96] = 8'h5a; ct_stream_2_4[97] = 8'hf9; ct_stream_2_4[98] = 8'h0b; ct_stream_2_4[99] = 8'hbf;
            ct_stream_2_4[100]= 8'h74; ct_stream_2_4[101]= 8'ha3; ct_stream_2_4[102]= 8'h5b; ct_stream_2_4[103]= 8'he6;
            ct_stream_2_4[104]= 8'hb4; ct_stream_2_4[105]= 8'h0b; ct_stream_2_4[106]= 8'h8e; ct_stream_2_4[107]= 8'hed;
            ct_stream_2_4[108]= 8'hf2; ct_stream_2_4[109]= 8'h78; ct_stream_2_4[110]= 8'h5e; ct_stream_2_4[111]= 8'h42;
            ct_stream_2_4[112]= 8'h87; ct_stream_2_4[113]= 8'h4d;

            // Expected plaintext string:
            // "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
            exp_pt_2_4[0]  = "L"; exp_pt_2_4[1]  = "a"; exp_pt_2_4[2]  = "d"; exp_pt_2_4[3]  = "i";
            exp_pt_2_4[4]  = "e"; exp_pt_2_4[5]  = "s"; exp_pt_2_4[6]  = " "; exp_pt_2_4[7]  = "a";
            exp_pt_2_4[8]  = "n"; exp_pt_2_4[9]  = "d"; exp_pt_2_4[10] = " "; exp_pt_2_4[11] = "G";
            exp_pt_2_4[12] = "e"; exp_pt_2_4[13] = "n"; exp_pt_2_4[14] = "t"; exp_pt_2_4[15] = "l";
            exp_pt_2_4[16] = "e"; exp_pt_2_4[17] = "m"; exp_pt_2_4[18] = "e"; exp_pt_2_4[19] = "n";
            exp_pt_2_4[20] = " "; exp_pt_2_4[21] = "o"; exp_pt_2_4[22] = "f"; exp_pt_2_4[23] = " ";
            exp_pt_2_4[24] = "t"; exp_pt_2_4[25] = "h"; exp_pt_2_4[26] = "e"; exp_pt_2_4[27] = " ";
            exp_pt_2_4[28] = "c"; exp_pt_2_4[29] = "l"; exp_pt_2_4[30] = "a"; exp_pt_2_4[31] = "s";
            exp_pt_2_4[32] = "s"; exp_pt_2_4[33] = " "; exp_pt_2_4[34] = "o"; exp_pt_2_4[35] = "f";
            exp_pt_2_4[36] = " "; exp_pt_2_4[37] = "'"; exp_pt_2_4[38] = "9"; exp_pt_2_4[39] = "9";
            exp_pt_2_4[40] = ":"; exp_pt_2_4[41] = " "; exp_pt_2_4[42] = "I"; exp_pt_2_4[43] = "f";
            exp_pt_2_4[44] = " "; exp_pt_2_4[45] = "I"; exp_pt_2_4[46] = " "; exp_pt_2_4[47] = "c";
            exp_pt_2_4[48] = "o"; exp_pt_2_4[49] = "u"; exp_pt_2_4[50] = "l"; exp_pt_2_4[51] = "d";
            exp_pt_2_4[52] = " "; exp_pt_2_4[53] = "o"; exp_pt_2_4[54] = "f"; exp_pt_2_4[55] = "f";
            exp_pt_2_4[56] = "e"; exp_pt_2_4[57] = "r"; exp_pt_2_4[58] = " "; exp_pt_2_4[59] = "y";
            exp_pt_2_4[60] = "o"; exp_pt_2_4[61] = "u"; exp_pt_2_4[62] = " "; exp_pt_2_4[63] = "o";
            exp_pt_2_4[64] = "n"; exp_pt_2_4[65] = "l"; exp_pt_2_4[66] = "y"; exp_pt_2_4[67] = " ";
            exp_pt_2_4[68] = "o"; exp_pt_2_4[69] = "n"; exp_pt_2_4[70] = "e"; exp_pt_2_4[71] = " ";
            exp_pt_2_4[72] = "t"; exp_pt_2_4[73] = "i"; exp_pt_2_4[74] = "p"; exp_pt_2_4[75] = " ";
            exp_pt_2_4[76] = "f"; exp_pt_2_4[77] = "o"; exp_pt_2_4[78] = "r"; exp_pt_2_4[79] = " ";
            exp_pt_2_4[80] = "t"; exp_pt_2_4[81] = "h"; exp_pt_2_4[82] = "e"; exp_pt_2_4[83] = " ";
            exp_pt_2_4[84] = "f"; exp_pt_2_4[85] = "u"; exp_pt_2_4[86] = "t"; exp_pt_2_4[87] = "u";
            exp_pt_2_4[88] = "r"; exp_pt_2_4[89] = "e"; exp_pt_2_4[90] = ","; exp_pt_2_4[91] = " ";
            exp_pt_2_4[92] = "s"; exp_pt_2_4[93] = "u"; exp_pt_2_4[94] = "n"; exp_pt_2_4[95] = "s";
            exp_pt_2_4[96] = "c"; exp_pt_2_4[97] = "r"; exp_pt_2_4[98] = "e"; exp_pt_2_4[99] = "e";
            exp_pt_2_4[100]= "n"; exp_pt_2_4[101]= " "; exp_pt_2_4[102]= "w"; exp_pt_2_4[103]= "o";
            exp_pt_2_4[104]= "u"; exp_pt_2_4[105]= "l"; exp_pt_2_4[106]= "d"; exp_pt_2_4[107]= " ";
            exp_pt_2_4[108]= "b"; exp_pt_2_4[109]= "e"; exp_pt_2_4[110]= " "; exp_pt_2_4[111]= "i";
            exp_pt_2_4[112]= "t"; exp_pt_2_4[113]= ".";
        end
    endtask

    initial begin
        clk = 0;
        rst = 1;
        test_errors = 0;
        init_vectors();

        start    = 0;
        key      = 256'd0;
        counter  = 32'd0;
        nonce    = 96'd0;
        ct_valid = 0;
        ct_data  = 8'd0;
        ct_sof   = 0;
        ct_eof   = 0;

        repeat (3) @(negedge clk);
        rst = 0;
        @(negedge clk);

        $display("====================================================================");
        $display("sim/test_chacha20_tb.v -- RFC 8439 ChaCha20 RTL Core Verification");
        $display("====================================================================");

        // ---------------------------------------------------------------------
        // Test 1: RFC 8439 Section 2.3.2: 64-byte Block Function
        // ---------------------------------------------------------------------
        $display("[TEST 1] RFC 8439 Section 2.3.2: ChaCha20 Block Function");

        // Key: 00..1F (little-endian words: 03020100, 07060504, ...)
        key[31:0]    = 32'h03020100;
        key[63:32]   = 32'h07060504;
        key[95:64]   = 32'h0b0a0908;
        key[127:96]  = 32'h0f0e0d0c;
        key[159:128] = 32'h13121110;
        key[191:160] = 32'h17161514;
        key[223:192] = 32'h1b1a1918;
        key[255:224] = 32'h1f1e1d1c;

        counter = 32'd1;

        // Nonce: 00 00 00 09 00 00 00 4a 00 00 00 00
        nonce[31:0]  = 32'h09000000;
        nonce[63:32] = 32'h4a000000;
        nonce[95:64] = 32'h00000000;

        // Strobe start for 1 cycle
        @(negedge clk);
        start = 1;
        cycle_count = 0;
        @(negedge clk);
        start = 0;

        // Measure cycle latency until done fires
        while (!done && cycle_count < 50) begin
            @(negedge clk);
            cycle_count = cycle_count + 1;
        end

        // RFC 8439 Section 2.3 architecture: exactly 22 cycles
        if (cycle_count !== 22) begin
            $display("FAILED: Expected 22 cycles latency from start to done, got %d", cycle_count);
            test_errors = test_errors + 1;
        end else begin
            $display("  --> Cycle latency verified: exactly %d cycles (10 double rounds + add + out)", cycle_count);
        end

        // Check each byte of the generated 64-byte keystream block
        for (i = 0; i < 64; i = i + 1) begin
            actual_byte = keystream_block[i*8 +: 8];
            if (actual_byte !== exp_block_2_3[i]) begin
                $display("FAILED: Block byte %d mismatch: got %02h, expected %02h", i, actual_byte, exp_block_2_3[i]);
                test_errors = test_errors + 1;
            end
        end

        if (test_errors == 0) begin
            $display("  --> PASS: 64-byte block matches RFC 8439 Section 2.3.2 bit-for-bit");
        end

        repeat (2) @(negedge clk);

        // ---------------------------------------------------------------------
        // Test 2: RFC 8439 Section 2.4.2: Streaming Plaintext Inspection Bus (§3.1)
        // ---------------------------------------------------------------------
        $display("[TEST 2] RFC 8439 Section 2.4.2: Plaintext Inspection Bus (§3.1)");

        // Same key, but §2.4.2 nonce has byte 3 = 0x00
        nonce[31:0]  = 32'h00000000;
        nonce[63:32] = 32'h4a000000;
        nonce[95:64] = 32'h00000000;
        counter      = 32'd1;

        // Block 1 generation (bytes 0..63)
        @(negedge clk);
        start = 1;
        @(negedge clk);
        start = 0;
        while (!done) @(negedge clk);
        @(negedge clk);

        // Stream first 64 ciphertext bytes through ct_data
        for (i = 0; i < 64; i = i + 1) begin
            ct_valid = 1;
            ct_data  = ct_stream_2_4[i];
            ct_sof   = (i == 0);
            ct_eof   = 0;
            @(negedge clk);

            // Verify pt output from DUT (registered 1 cycle later)
            #1;
            if (pt_valid !== 1'b1) begin
                $display("FAILED: pt_valid not asserted for byte %d", i);
                test_errors = test_errors + 1;
            end
            if (pt_data !== exp_pt_2_4[i]) begin
                $display("FAILED: pt_data byte %d mismatch: got %02h ('%c'), expected %02h ('%c')",
                         i, pt_data, pt_data, exp_pt_2_4[i], exp_pt_2_4[i]);
                test_errors = test_errors + 1;
            end
            if (i == 0 && pt_sof !== 1'b1) begin
                $display("FAILED: pt_sof not asserted on first byte");
                test_errors = test_errors + 1;
            end
        end

        // Block 2 generation (bytes 64..113)
        ct_valid = 0;
        ct_sof   = 0;
        counter  = 32'd2;
        @(negedge clk);
        start    = 1;
        @(negedge clk);
        start    = 0;
        while (!done) @(negedge clk);
        @(negedge clk);

        // Stream remaining 50 ciphertext bytes through ct_data
        for (i = 64; i < 114; i = i + 1) begin
            ct_valid = 1;
            ct_data  = ct_stream_2_4[i];
            ct_sof   = 0;
            ct_eof   = (i == 113);
            @(negedge clk);

            #1;
            if (pt_valid !== 1'b1) begin
                $display("FAILED: pt_valid not asserted for byte %d", i);
                test_errors = test_errors + 1;
            end
            if (pt_data !== exp_pt_2_4[i]) begin
                $display("FAILED: pt_data byte %d mismatch: got %02h ('%c'), expected %02h ('%c')",
                         i, pt_data, pt_data, exp_pt_2_4[i], exp_pt_2_4[i]);
                test_errors = test_errors + 1;
            end
            if (i == 113 && pt_eof !== 1'b1) begin
                $display("FAILED: pt_eof not asserted on last byte");
                test_errors = test_errors + 1;
            end
        end

        ct_valid = 0;
        ct_eof   = 0;
        @(negedge clk);

        if (test_errors == 0) begin
            $display("  --> PASS: 114-byte ciphertext decrypted into exact plaintext string");
            $display("  --> PASS: Section 3.1 streaming bus pt_sof / pt_eof / pt_valid timing verified");
        end

        // ---------------------------------------------------------------------
        // Final Summary
        // ---------------------------------------------------------------------
        $display("====================================================================");
        if (test_errors == 0) begin
            $display("ALL ChaCha20 RTL checks PASSED with 0 errors.");
        end else begin
            $display("ChaCha20 verification FAILED with %d errors.", test_errors);
        end
        $display("====================================================================");

        $finish;
    end

endmodule

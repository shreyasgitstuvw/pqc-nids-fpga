// sim/test_poly1305_tb.v
//
// Self-checking testbench for Poly1305 MAC authenticator (poly1305.v)
// Verifies compliance with RFC 8439 Section 2.5:
//   Test 1: RFC 8439 Sec 2.5.2 34-byte message vector (streaming byte interface)
//   Test 2: Tamper detection & drop engine rejection (RC_BAD_TAG = 4'h7)
//   Test 3: Direct block interface (128-bit blocks, blk_valid)
//   Test 4: Empty message boundary case (tag = s mod 2^128)
//
// Member D (@control) -- pqc-nids-fpga

`timescale 1ns / 1ps
`include "reason_codes.vh"

module test_poly1305_tb;

    reg         clk;
    reg         rst;

    reg         key_valid;
    reg [255:0] key;

    reg         msg_valid;
    reg [7:0]   msg_data;
    reg         msg_sof;
    reg         msg_eof;

    reg         blk_valid;
    reg [127:0] blk_data;
    reg [4:0]   blk_len;
    reg         blk_last;

    reg [127:0] expected_tag;

    wire        busy;
    wire        tag_valid;
    wire [127:0] tag_out;
    wire        tag_ok;
    wire        pt_tag_ok;
    wire        pt_tag_valid;
    wire        v_poly_valid;
    wire        v_poly_fail;
    wire [3:0]  v_poly_reason;

    // Instantiate DUT
    poly1305 u_dut (
        .clk          (clk),
        .rst          (rst),
        .key_valid    (key_valid),
        .key          (key),
        .msg_valid    (msg_valid),
        .msg_data     (msg_data),
        .msg_sof      (msg_sof),
        .msg_eof      (msg_eof),
        .blk_valid    (blk_valid),
        .blk_data     (blk_data),
        .blk_len      (blk_len),
        .blk_last     (blk_last),
        .expected_tag (expected_tag),
        .busy         (busy),
        .tag_valid    (tag_valid),
        .tag_out      (tag_out),
        .tag_ok       (tag_ok),
        .pt_tag_ok    (pt_tag_ok),
        .pt_tag_valid (pt_tag_valid),
        .v_poly_valid (v_poly_valid),
        .v_poly_fail  (v_poly_fail),
        .v_poly_reason(v_poly_reason)
    );

    // 100 MHz clock generation (10 ns period)
    always #5 clk = ~clk;

    integer errors;
    integer latency_cycles;
    reg [7:0] rfc_msg [0:33];
    integer i;

    // RFC 8439 Sec 2.5.2 Golden Test Vector:
    // Key (32 bytes):
    //   85 d6 be 78 57 55 6d 33 7f 44 52 fe 42 d5 06 a8 (r)
    //   01 03 80 8a fb 0d b2 fd 4a bf f6 af 41 49 f5 1b (s)
    localparam [255:0] RFC_KEY = 256'h1bf54941aff6bf4afdb20dfb8a800301_a806d542fe52447f336d555778bed685;

    // Expected Tag (16 bytes):
    //   a8 06 1d c1 30 51 36 c6 c2 2b 8b af 0c 01 27 a9
    localparam [127:0] RFC_TAG = 128'ha927010caf8b2bc2c6365130c11d06a8;

    initial begin
        clk          = 0;
        rst          = 1;
        key_valid    = 0;
        key          = 256'd0;
        msg_valid    = 0;
        msg_data     = 8'd0;
        msg_sof      = 0;
        msg_eof      = 0;
        blk_valid    = 0;
        blk_data     = 128'd0;
        blk_len      = 5'd0;
        blk_last     = 0;
        expected_tag = 128'd0;
        errors       = 0;

        // Initialize RFC 8439 Sec 2.5.2 message bytes: "Cryptographic Forum Research Group" (34 bytes)
        rfc_msg[0]  = "C"; rfc_msg[1]  = "r"; rfc_msg[2]  = "y"; rfc_msg[3]  = "p";
        rfc_msg[4]  = "t"; rfc_msg[5]  = "o"; rfc_msg[6]  = "g"; rfc_msg[7]  = "r";
        rfc_msg[8]  = "a"; rfc_msg[9]  = "p"; rfc_msg[10] = "h"; rfc_msg[11] = "i";
        rfc_msg[12] = "c"; rfc_msg[13] = " "; rfc_msg[14] = "F"; rfc_msg[15] = "o";
        rfc_msg[16] = "r"; rfc_msg[17] = "u"; rfc_msg[18] = "m"; rfc_msg[19] = " ";
        rfc_msg[20] = "R"; rfc_msg[21] = "e"; rfc_msg[22] = "s"; rfc_msg[23] = "e";
        rfc_msg[24] = "a"; rfc_msg[25] = "r"; rfc_msg[26] = "c"; rfc_msg[27] = "h";
        rfc_msg[28] = " "; rfc_msg[29] = "G"; rfc_msg[30] = "r"; rfc_msg[31] = "o";
        rfc_msg[32] = "u"; rfc_msg[33] = "p";

        // Reset pulse
        #20;
        @(negedge clk);
        rst = 0;
        #10;

        $display("================================================================================");
        $display("Starting poly1305.v Self-Checking Test Suite (RFC 8439 Section 2.5)");
        $display("================================================================================");

        // =====================================================================
        // Test 1: RFC 8439 Section 2.5.2 Golden Vector (Streaming Byte Interface)
        // =====================================================================
        $display("\n--- Test 1: RFC 8439 Sec 2.5.2 Streaming Byte Interface (34 bytes) ---");
        @(negedge clk);
        key          = RFC_KEY;
        expected_tag = RFC_TAG;
        key_valid    = 1;
        @(negedge clk);
        key_valid    = 0;

        // Stream 34 bytes
        for (i = 0; i < 34; i = i + 1) begin
            @(negedge clk);
            msg_valid = 1;
            msg_data  = rfc_msg[i];
            msg_sof   = (i == 0);
            msg_eof   = (i == 33);
        end
        @(negedge clk);
        msg_valid = 0;
        msg_sof   = 0;
        msg_eof   = 0;

        // Count latency cycles from msg_eof deassertion to tag_valid
        latency_cycles = 0;
        while (!tag_valid && latency_cycles < 50) begin
            @(posedge clk);
            latency_cycles = latency_cycles + 1;
        end

        if (!tag_valid) begin
            $display("[FAIL] Test 1: Timeout waiting for tag_valid");
            errors = errors + 1;
        end else begin
            $display("  Tag received in %0d cycles after msg_eof", latency_cycles);
            $display("  Computed tag: 0x%032x", tag_out);
            $display("  Expected tag: 0x%032x", RFC_TAG);

            if (tag_out !== RFC_TAG) begin
                $display("[FAIL] Test 1: Tag mismatch!");
                errors = errors + 1;
            end else if (tag_ok !== 1'b1) begin
                $display("[FAIL] Test 1: tag_ok expected 1, got 0");
                errors = errors + 1;
            end else if (pt_tag_ok !== 1'b1 || pt_tag_valid !== 1'b1) begin
                $display("[FAIL] Test 1: Plaintext inspection bus qualification failure");
                errors = errors + 1;
            end else if (v_poly_valid !== 1'b1 || v_poly_fail !== 1'b0 || v_poly_reason !== `RC_NONE) begin
                $display("[FAIL] Test 1: Drop engine verdict mismatch: valid=%b fail=%b reason=%h",
                         v_poly_valid, v_poly_fail, v_poly_reason);
                errors = errors + 1;
            end else begin
                $display("[PASS] Test 1: RFC 8439 Sec 2.5.2 exact match (tag_ok=1, verdict=PASS)");
            end
        end

        // Allow pipeline to return to IDLE
        #20;

        // =====================================================================
        // Test 2: Tamper Detection (Corrupted Expected Tag)
        // =====================================================================
        $display("\n--- Test 2: Tamper Detection & Drop Engine Rejection (RC_BAD_TAG) ---");
        @(negedge clk);
        key          = RFC_KEY;
        expected_tag = RFC_TAG ^ 128'h1; // Corrupt 1 bit
        key_valid    = 1;
        @(negedge clk);
        key_valid    = 0;

        // Stream 34 bytes again
        for (i = 0; i < 34; i = i + 1) begin
            @(negedge clk);
            msg_valid = 1;
            msg_data  = rfc_msg[i];
            msg_sof   = (i == 0);
            msg_eof   = (i == 33);
        end
        @(negedge clk);
        msg_valid = 0;
        msg_sof   = 0;
        msg_eof   = 0;

        latency_cycles = 0;
        while (!tag_valid && latency_cycles < 50) begin
            @(posedge clk);
            latency_cycles = latency_cycles + 1;
        end

        if (!tag_valid) begin
            $display("[FAIL] Test 2: Timeout waiting for tag_valid");
            errors = errors + 1;
        end else begin
            if (tag_ok !== 1'b0) begin
                $display("[FAIL] Test 2: Corrupted tag incorrectly flagged as ok!");
                errors = errors + 1;
            end else if (pt_tag_ok !== 1'b0 || pt_tag_valid !== 1'b1) begin
                $display("[FAIL] Test 2: pt_tag_ok expected 0, got %b", pt_tag_ok);
                errors = errors + 1;
            end else if (v_poly_valid !== 1'b1 || v_poly_fail !== 1'b1 || v_poly_reason !== `RC_BAD_TAG) begin
                $display("[FAIL] Test 2: Expected v_poly_fail=1 and RC_BAD_TAG (4'h7), got valid=%b fail=%b reason=%h",
                         v_poly_valid, v_poly_fail, v_poly_reason);
                errors = errors + 1;
            end else begin
                $display("[PASS] Test 2: Tamper correctly caught: tag_ok=0, v_poly_fail=1, reason=RC_BAD_TAG (4'h7)");
            end
        end

        #20;

        // =====================================================================
        // Test 3: Direct Block Interface (blk_valid)
        // =====================================================================
        $display("\n--- Test 3: Direct Block Interface Verification ---");
        @(negedge clk);
        key          = RFC_KEY;
        expected_tag = RFC_TAG;
        key_valid    = 1;
        @(negedge clk);
        key_valid    = 0;

        // Block 0 (16 bytes): rfc_msg[0..15]
        @(negedge clk);
        blk_valid = 1;
        blk_len   = 5'd16;
        blk_last  = 1'b0;
        blk_data  = {rfc_msg[15], rfc_msg[14], rfc_msg[13], rfc_msg[12],
                     rfc_msg[11], rfc_msg[10], rfc_msg[9],  rfc_msg[8],
                     rfc_msg[7],  rfc_msg[6],  rfc_msg[5],  rfc_msg[4],
                     rfc_msg[3],  rfc_msg[2],  rfc_msg[1],  rfc_msg[0]};
        @(negedge clk);
        blk_valid = 0;

        // Wait 4 cycles for block 0 reduction
        repeat (4) @(posedge clk);

        // Block 1 (16 bytes): rfc_msg[16..31]
        @(negedge clk);
        blk_valid = 1;
        blk_len   = 5'd16;
        blk_last  = 1'b0;
        blk_data  = {rfc_msg[31], rfc_msg[30], rfc_msg[29], rfc_msg[28],
                     rfc_msg[27], rfc_msg[26], rfc_msg[25], rfc_msg[24],
                     rfc_msg[23], rfc_msg[22], rfc_msg[21], rfc_msg[20],
                     rfc_msg[19], rfc_msg[18], rfc_msg[17], rfc_msg[16]};
        @(negedge clk);
        blk_valid = 0;

        // Wait 4 cycles for block 1 reduction
        repeat (4) @(posedge clk);

        // Block 2 (2 bytes): rfc_msg[32..33]
        @(negedge clk);
        blk_valid = 1;
        blk_len   = 5'd2;
        blk_last  = 1'b1;
        blk_data  = {112'd0, rfc_msg[33], rfc_msg[32]};
        @(negedge clk);
        blk_valid = 0;

        latency_cycles = 0;
        while (!tag_valid && latency_cycles < 50) begin
            @(posedge clk);
            latency_cycles = latency_cycles + 1;
        end

        if (!tag_valid) begin
            $display("[FAIL] Test 3: Timeout waiting for tag_valid");
            errors = errors + 1;
        end else if (tag_out !== RFC_TAG || tag_ok !== 1'b1) begin
            $display("[FAIL] Test 3: Direct block tag mismatch! got: 0x%032x", tag_out);
            errors = errors + 1;
        end else begin
            $display("[PASS] Test 3: Direct block interface exact match with RFC 8439 tag");
        end

        #20;

        // =====================================================================
        // Test 4: Empty Message Boundary Case
        // =====================================================================
        $display("\n--- Test 4: Empty Message Boundary Case ---");
        @(negedge clk);
        key          = RFC_KEY;
        // For empty message, tag = s mod 2^128 = RFC_KEY[255:128]
        expected_tag = RFC_KEY[255:128];
        key_valid    = 1;
        @(negedge clk);
        key_valid    = 0;

        // Direct block with length 0
        @(negedge clk);
        blk_valid = 1;
        blk_len   = 5'd0;
        blk_last  = 1'b1;
        blk_data  = 128'd0;
        @(negedge clk);
        blk_valid = 0;

        latency_cycles = 0;
        while (!tag_valid && latency_cycles < 50) begin
            @(posedge clk);
            latency_cycles = latency_cycles + 1;
        end

        if (!tag_valid) begin
            $display("[FAIL] Test 4: Timeout waiting for tag_valid");
            errors = errors + 1;
        end else if (tag_out !== RFC_KEY[255:128]) begin
            $display("[FAIL] Test 4: Expected tag=s (0x%032x), got 0x%032x", RFC_KEY[255:128], tag_out);
            errors = errors + 1;
        end else begin
            $display("[PASS] Test 4: Empty message tag == s verified");
        end

        // Final Summary
        $display("\n================================================================================");
        if (errors == 0) begin
            $display("ALL 4 POLY1305 TESTS PASSED SUCCESSFULLY! (0 errors)");
        end else begin
            $display("POLY1305 TEST SUITE FAILED with %0d errors!", errors);
        end
        $display("================================================================================");

        #50;
        $finish;
    end

endmodule

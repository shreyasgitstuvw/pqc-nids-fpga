//==============================================================================
// sim/tb_deframer.v
//
// Self-Checking Verilog-2001 Testbench for rtl/ingress/deframer.v.
//
// Tests:
//   1. Standard valid frame (14-byte payload) -> out_sof, out_eof, RC_NONE
//   2. Empty payload frame (6 bytes total, CRC 0x00000000) -> RC_NONE
//   3. Corrupted CRC-32 frame -> pulses RC_CRC_FAIL (4'h1)
//   4. Malformed length (< 6 bytes) -> pulses RC_MALFORMED (4'h3)
//   5. Truncated frame / watchdog timeout -> pulses RC_FRAME_TIMEOUT (4'h2) without eof
//   6. Back-to-back valid frames with 0 idle clock cycles
//   7. Synchronous reset recovery mid-frame
//
// Owner: Member A (Ingress, Parser, and Interface Contract)
//==============================================================================

`timescale 1ns / 1ps
`include "reason_codes.vh"

module tb_deframer;

    reg        clk;
    reg        rst;
    reg        in_valid;
    reg  [7:0] in_data;

    wire       out_valid;
    wire [7:0] out_data;
    wire       out_sof;
    wire       out_eof;

    wire       verdict_valid;
    wire       verdict_fail;
    wire [3:0] verdict_code;

    integer errors = 0;
    integer rx_byte_count = 0;
    integer eof_observed = 0;

    // Use a fast timeout (50 cycles) for simulation test execution
    localparam TEST_TIMEOUT = 50;

    // Instantiate Device Under Test (DUT)
    deframer #(
        .TIMEOUT_CYCLES (TEST_TIMEOUT)
    ) dut (
        .clk           (clk),
        .rst           (rst),
        .in_valid      (in_valid),
        .in_data       (in_data),
        .out_valid     (out_valid),
        .out_data      (out_data),
        .out_sof       (out_sof),
        .out_eof       (out_eof),
        .verdict_valid (verdict_valid),
        .verdict_fail  (verdict_fail),
        .verdict_code  (verdict_code)
    );

    // 100 MHz system clock (10 ns period)
    always #5 clk = ~clk;

    // Monitor payload bytes and EOF assertions
    always @(posedge clk) begin
        if (out_valid) begin
            rx_byte_count = rx_byte_count + 1;
            if (out_eof) begin
                eof_observed = eof_observed + 1;
            end
        end
    end

    // Storage buffer for test frame bytes
    reg [7:0] frame_buf [0:255];

    // Task to send N frame bytes into the deframer
    task send_frame_bytes;
        input integer len;
        integer i;
        begin
            for (i = 0; i < len; i = i + 1) begin
                @(posedge clk);
                in_valid <= 1'b1;
                in_data  <= frame_buf[i];
            end
            @(posedge clk);
            in_valid <= 1'b0;
            in_data  <= 8'h00;
        end
    endtask

    initial begin
        clk      = 1'b0;
        rst      = 1'b1;
        in_valid = 1'b0;
        in_data  = 8'h00;

        $display("==================================================================");
        $display("Starting Self-Checking Testbench for rtl/ingress/deframer.v");
        $display("==================================================================");

        // Reset sequence (20 ns)
        #20;
        @(posedge clk);
        rst <= 1'b0;
        @(posedge clk);

        //----------------------------------------------------------------------
        // Test 1: Standard valid frame
        // Payload: "HELLO_PQC_NIDS" (14 bytes) -> CRC = 32'hA9643378
        // Total len: 2 + 14 + 4 = 20 (16'h0014)
        //----------------------------------------------------------------------
        rx_byte_count = 0;
        eof_observed  = 0;

        frame_buf[0]  = 8'h00; frame_buf[1]  = 8'h14; // Length: 20
        frame_buf[2]  = "H";   frame_buf[3]  = "E";   frame_buf[4]  = "L";   frame_buf[5]  = "L";
        frame_buf[6]  = "O";   frame_buf[7]  = "_";   frame_buf[8]  = "P";   frame_buf[9]  = "Q";
        frame_buf[10] = "C";   frame_buf[11] = "_";   frame_buf[12] = "N";   frame_buf[13] = "I";
        frame_buf[14] = "D";   frame_buf[15] = "S";
        frame_buf[16] = 8'hA9; frame_buf[17] = 8'h64; frame_buf[18] = 8'h33; frame_buf[19] = 8'h78; // CRC

        send_frame_bytes(20);

        #1;
        if (!verdict_valid || verdict_fail !== 1'b0 || verdict_code !== `RC_NONE) begin
            $display("ERROR [Test 1]: Valid frame failed! valid=%b, fail=%b, code=%h", verdict_valid, verdict_fail, verdict_code);
            errors = errors + 1;
        end else if (rx_byte_count !== 14 || eof_observed !== 1) begin
            $display("ERROR [Test 1]: Payload count mismatch! rx_bytes=%0d, eof=%0d", rx_byte_count, eof_observed);
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 1]: Standard valid frame (14B payload) -> RC_NONE");
        end

        // Wait 2 idle cycles
        repeat (2) @(posedge clk);

        //----------------------------------------------------------------------
        // Test 2: Empty payload frame (6 bytes: total_len = 6, CRC = 0x00000000)
        //----------------------------------------------------------------------
        rx_byte_count = 0;
        eof_observed  = 0;

        frame_buf[0] = 8'h00; frame_buf[1] = 8'h06; // Length: 6
        frame_buf[2] = 8'h00; frame_buf[3] = 8'h00; frame_buf[4] = 8'h00; frame_buf[5] = 8'h00; // CRC

        send_frame_bytes(6);

        #1;
        if (!verdict_valid || verdict_fail !== 1'b0 || verdict_code !== `RC_NONE) begin
            $display("ERROR [Test 2]: Empty frame failed! valid=%b, fail=%b, code=%h", verdict_valid, verdict_fail, verdict_code);
            errors = errors + 1;
        end else if (rx_byte_count !== 0) begin
            $display("ERROR [Test 2]: Empty frame emitted unexpected payload bytes! count=%0d", rx_byte_count);
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 2]: Empty frame (0B payload, len=6) -> RC_NONE");
        end

        repeat (2) @(posedge clk);

        //----------------------------------------------------------------------
        // Test 3: Corrupted CRC frame
        // Payload: "HELLO_PQC_NIDS", but CRC is corrupted to 0xDEADBEEF
        //----------------------------------------------------------------------
        frame_buf[0]  = 8'h00; frame_buf[1]  = 8'h14; // Length: 20
        frame_buf[2]  = "H";   frame_buf[3]  = "E";   frame_buf[4]  = "L";   frame_buf[5]  = "L";
        frame_buf[6]  = "O";   frame_buf[7]  = "_";   frame_buf[8]  = "P";   frame_buf[9]  = "Q";
        frame_buf[10] = "C";   frame_buf[11] = "_";   frame_buf[12] = "N";   frame_buf[13] = "I";
        frame_buf[14] = "D";   frame_buf[15] = "S";
        frame_buf[16] = 8'hDE; frame_buf[17] = 8'hAD; frame_buf[18] = 8'hBE; frame_buf[19] = 8'hEF; // Corrupted CRC

        send_frame_bytes(20);

        #1;
        if (!verdict_valid || verdict_fail !== 1'b1 || verdict_code !== `RC_CRC_FAIL) begin
            $display("ERROR [Test 3]: Corrupted CRC did not report RC_CRC_FAIL! valid=%b, fail=%b, code=%h", verdict_valid, verdict_fail, verdict_code);
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 3]: Corrupted CRC -> RC_CRC_FAIL (4'h1)");
        end

        repeat (2) @(posedge clk);

        //----------------------------------------------------------------------
        // Test 4: Malformed length (< 6 bytes, e.g. total_len = 4)
        //----------------------------------------------------------------------
        frame_buf[0] = 8'h00; frame_buf[1] = 8'h04; // Invalid length: 4

        send_frame_bytes(2);

        #1;
        if (!verdict_valid || verdict_fail !== 1'b1 || verdict_code !== `RC_MALFORMED) begin
            $display("ERROR [Test 4]: Malformed length did not report RC_MALFORMED! valid=%b, fail=%b, code=%h", verdict_valid, verdict_fail, verdict_code);
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 4]: Malformed length (<6B) -> RC_MALFORMED (4'h3)");
        end

        repeat (2) @(posedge clk);

        //----------------------------------------------------------------------
        // Test 5: Truncated frame / Watchdog timeout
        // Send length=20, send only 4 payload bytes, then stall
        //----------------------------------------------------------------------
        eof_observed = 0;
        frame_buf[0] = 8'h00; frame_buf[1] = 8'h14; // Length: 20
        frame_buf[2] = "T";   frame_buf[3] = "E";   frame_buf[4] = "S";   frame_buf[5] = "T";

        send_frame_bytes(6); // Only 6 bytes sent out of 20

        // Wait for watchdog timeout to trigger (TEST_TIMEOUT = 50 cycles)
        repeat (TEST_TIMEOUT + 5) @(posedge clk);

        #1;
        if (eof_observed !== 0) begin
            $display("ERROR [Test 5]: Truncated frame asserted eof! Violates contract §1.");
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 5]: Truncated frame timeout -> RC_FRAME_TIMEOUT (4'h2) without eof");
        end

        repeat (2) @(posedge clk);

        //----------------------------------------------------------------------
        // Test 6: Back-to-back valid frames (0 idle cycles between Frame A & B)
        // Frame A: Single-byte payload 0xA5 (len=7, CRC 32'h74BEB8EA)
        // Frame B: Single-byte payload 0xA5 (len=7, CRC 32'h74BEB8EA)
        //----------------------------------------------------------------------
        @(posedge clk);
        // Frame A
        in_valid <= 1'b1; in_data <= 8'h00; @(posedge clk);
        in_valid <= 1'b1; in_data <= 8'h07; @(posedge clk);
        in_valid <= 1'b1; in_data <= 8'hA5; @(posedge clk);
        in_valid <= 1'b1; in_data <= 8'h74; @(posedge clk);
        in_valid <= 1'b1; in_data <= 8'hBE; @(posedge clk);
        in_valid <= 1'b1; in_data <= 8'hB8; @(posedge clk);
        in_valid <= 1'b1; in_data <= 8'hEA; @(posedge clk);
        // Immediately Byte 0 of Frame B
        in_valid <= 1'b1; in_data <= 8'h00; @(posedge clk);
        in_valid <= 1'b1; in_data <= 8'h07; @(posedge clk);
        in_valid <= 1'b1; in_data <= 8'hA5; @(posedge clk);
        in_valid <= 1'b1; in_data <= 8'h74; @(posedge clk);
        in_valid <= 1'b1; in_data <= 8'hBE; @(posedge clk);
        in_valid <= 1'b1; in_data <= 8'hB8; @(posedge clk);
        in_valid <= 1'b1; in_data <= 8'hEA; @(posedge clk);
        in_valid <= 1'b0; in_data <= 8'h00;

        #1;
        if (!verdict_valid || verdict_fail !== 1'b0) begin
            $display("ERROR [Test 6]: Back-to-back Frame B failed!");
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 6]: Back-to-back frames with zero idle cycles -> PASS");
        end

        repeat (2) @(posedge clk);

        //----------------------------------------------------------------------
        // Test 7: Synchronous reset recovery mid-frame
        //----------------------------------------------------------------------
        @(posedge clk);
        in_valid <= 1'b1; in_data <= 8'h00; @(posedge clk);
        in_valid <= 1'b1; in_data <= 8'h20; @(posedge clk);
        in_valid <= 1'b1; in_data <= 8'hAA; @(posedge clk);
        // Assert reset mid-frame
        rst <= 1'b1;
        @(posedge clk);
        rst <= 1'b0;
        in_valid <= 1'b0;
        @(posedge clk);

        // Send fresh clean frame
        frame_buf[0] = 8'h00; frame_buf[1] = 8'h07; frame_buf[2] = 8'hA5;
        frame_buf[3] = 8'h74; frame_buf[4] = 8'hBE; frame_buf[5] = 8'hB8; frame_buf[6] = 8'hEA;
        send_frame_bytes(7);

        #1;
        if (!verdict_valid || verdict_fail !== 1'b0) begin
            $display("ERROR [Test 7]: Post-reset frame failed!");
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 7]: Mid-frame reset recovery -> Clean PASS");
        end

        #20;
        if (errors == 0) begin
            $display("==================================================================");
            $display("SUCCESS: ALL tb_deframer CHECKS PASSED BIT-FOR-BIT!");
            $display("==================================================================");
        end else begin
            $display("FAILURE: %0d error(s) detected in tb_deframer!", errors);
            $finish(1);
        end

        $finish;
    end

endmodule

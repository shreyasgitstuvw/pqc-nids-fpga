//==============================================================================
// sim/tb_crc32.v
//
// Self-Checking Verilog Testbench for rtl/ingress/crc32.v.
// Can be executed in Vivado xsim, ModelSim, Icarus Verilog, or any standard
// Verilog simulator.
//
// Tests:
//   1. Published vector: ASCII "123456789" -> 32'hCBF43926
//   2. Single-byte packet: 8'hA5 -> 32'h74BEB8EA
//   3. Fixed patterns: zeros, ones, arbitrary strings
//   4. Back-to-back packets with zero idle gap
//   5. Output validity strobe timing verification
//
// Owner: Member A (Ingress, Parser, and Interface Contract)
//==============================================================================

`timescale 1ns / 1ps

module tb_crc32;

    reg        clk;
    reg        rst;
    reg        init;
    reg        in_valid;
    reg  [7:0] in_data;
    reg        eof;
    wire [31:0] crc_out;
    wire        crc_valid;

    integer errors = 0;

    // Instantiate Device Under Test (DUT)
    crc32 dut (
        .clk       (clk),
        .rst       (rst),
        .init      (init),
        .in_valid  (in_valid),
        .in_data   (in_data),
        .eof       (eof),
        .crc_out   (crc_out),
        .crc_valid (crc_valid)
    );

    // 100 MHz clock generator (10 ns period)
    always #5 clk = ~clk;

    // Storage array for test packets (module-scope for strict Verilog-2001 compatibility)
    reg [7:0] test_buf [0:63];

    // Task to send a packet of N bytes from test_buf and verify the resulting CRC
    task send_and_check;
        input [8*128-1:0] name;
        input integer     len;
        input [31:0]      expected_crc;
        integer i;
        begin
            @(posedge clk);
            for (i = 0; i < len; i = i + 1) begin
                in_valid <= 1'b1;
                in_data  <= test_buf[i];
                init     <= (i == 0) ? 1'b1 : 1'b0;
                eof      <= (i == len - 1) ? 1'b1 : 1'b0;
                @(posedge clk);
            end
            in_valid <= 1'b0;
            init     <= 1'b0;
            eof      <= 1'b0;
            in_data  <= 8'h00;

            #1; // Allow non-blocking assignments (NBA) to settle
            // Check registered output on the cycle eof is evaluated
            if (!crc_valid || crc_out !== expected_crc) begin
                $display("ERROR [%0s]: CRC mismatch! Got 0x%08X (crc_valid=%b), expected 0x%08X", name, crc_out, crc_valid, expected_crc);
                errors = errors + 1;
            end else begin
                $display("PASS  [%0s]: CRC = 0x%08X", name, crc_out);
            end
        end
    endtask

    initial begin
        clk      = 1'b0;
        rst      = 1'b1;
        init     = 1'b0;
        in_valid = 1'b0;
        in_data  = 8'h00;
        eof      = 1'b0;

        $display("==================================================================");
        $display("Starting Self-Checking Testbench for rtl/ingress/crc32.v");
        $display("==================================================================");

        // Reset sequence (2 clock cycles)
        #20;
        @(posedge clk);
        rst <= 1'b0;
        @(posedge clk);

        // 1. Published IEEE 802.3 Vector: "123456789"
        test_buf[0] = 8'h31; test_buf[1] = 8'h32; test_buf[2] = 8'h33;
        test_buf[3] = 8'h34; test_buf[4] = 8'h35; test_buf[5] = 8'h36;
        test_buf[6] = 8'h37; test_buf[7] = 8'h38; test_buf[8] = 8'h39;
        send_and_check("IEEE 802.3 '123456789'", 9, 32'hCBF43926);

        // 2. Single-byte packet: 8'hA5
        test_buf[0] = 8'hA5;
        send_and_check("Single Byte 0xA5", 1, 32'h74BEB8EA);

        // 3. Four zeros: 4x 8'h00
        test_buf[0] = 8'h00; test_buf[1] = 8'h00;
        test_buf[2] = 8'h00; test_buf[3] = 8'h00;
        send_and_check("Four Zeros 0x00000000", 4, 32'h2144DF1C);

        // 4. Four ones: 4x 8'hFF
        test_buf[0] = 8'hFF; test_buf[1] = 8'hFF;
        test_buf[2] = 8'hFF; test_buf[3] = 8'hFF;
        send_and_check("Four Ones 0xFFFFFFFF", 4, 32'hFFFFFFFF);

        // 5. String: "HELLO_PQC_NIDS" (14 bytes)
        test_buf[0]  = "H"; test_buf[1]  = "E"; test_buf[2]  = "L"; test_buf[3]  = "L";
        test_buf[4]  = "O"; test_buf[5]  = "_"; test_buf[6]  = "P"; test_buf[7]  = "Q";
        test_buf[8]  = "C"; test_buf[9]  = "_"; test_buf[10] = "N"; test_buf[11] = "I";
        test_buf[12] = "D"; test_buf[13] = "S";
        send_and_check("HELLO_PQC_NIDS (14B)", 14, 32'hA9643378);

        // 6. Back-to-Back packets test (no idle cycles between packet A and B)
        @(posedge clk);
        // Byte 0 of packet A ("1" = 8'h31)
        in_valid <= 1'b1; in_data <= 8'h31; init <= 1'b1; eof <= 1'b0;
        @(posedge clk);
        // Byte 1 of packet A ("2" = 8'h32, eof)
        in_valid <= 1'b1; in_data <= 8'h32; init <= 1'b0; eof <= 1'b1;
        @(posedge clk);
        // Check Packet A result immediately
        #1;
        if (!crc_valid || crc_out !== 32'h4F5344CD) begin
            $display("ERROR [Back-to-Back Packet A]: CRC mismatch! Got 0x%08X (valid=%b), expected 0x4F5344CD", crc_out, crc_valid);
            errors = errors + 1;
        end else begin
            $display("PASS  [Back-to-Back Packet A]: CRC = 0x%08X", crc_out);
        end
        // Byte 0 of packet B (0xA5, init=1, eof=1)
        in_valid <= 1'b1; in_data <= 8'hA5; init <= 1'b1; eof <= 1'b1;
        @(posedge clk);
        in_valid <= 1'b0; init <= 1'b0; eof <= 1'b0; in_data <= 8'h00;
        #1;
        if (!crc_valid || crc_out !== 32'h74BEB8EA) begin
            $display("ERROR [Back-to-Back Packet B]: CRC mismatch! Got 0x%08X (valid=%b), expected 0x74BEB8EA", crc_out, crc_valid);
            errors = errors + 1;
        end else begin
            $display("PASS  [Back-to-Back Packet B]: CRC = 0x%08X", crc_out);
        end

        // 7. Mid-Packet Reset Recovery
        @(posedge clk);
        in_valid <= 1'b1; in_data <= 8'hDE; init <= 1'b1; eof <= 1'b0;
        @(posedge clk);
        in_valid <= 1'b1; in_data <= 8'hAD; init <= 1'b0; eof <= 1'b0;
        @(posedge clk);
        // Assert reset mid-packet
        rst <= 1'b1;
        in_valid <= 1'b1; in_data <= 8'hBE; init <= 1'b0; eof <= 1'b0;
        @(posedge clk);
        rst <= 1'b0;
        in_valid <= 1'b0; init <= 1'b0; eof <= 1'b0; in_data <= 8'h00;
        @(posedge clk);
        // Verify fresh packet calculates correctly after reset
        test_buf[0] = 8'hA5;
        send_and_check("Post-Reset Clean 0xA5", 1, 32'h74BEB8EA);

        #20;
        if (errors == 0) begin
            $display("==================================================================");
            $display("SUCCESS: ALL tb_crc32 CHECKS PASSED BIT-FOR-BIT!");
            $display("==================================================================");
        end else begin
            $display("FAILURE: %0d error(s) detected in tb_crc32!", errors);
            $finish(1);
        end

        $finish;
    end

endmodule

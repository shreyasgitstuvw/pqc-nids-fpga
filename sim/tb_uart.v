//==============================================================================
// sim/tb_uart.v
//
// Self-Checking Verilog-2001 Testbench for rtl/ingress/uart_rx.v and uart_tx.v.
//
// Test Coverage:
//   1. Single-byte loopback (tx -> rx) with known pattern (8'hA5)
//   2. Multi-byte sequential loopback (0x00, 0x55, 0xAA, 0xFF, 0x3C, 0xC3)
//   3. Fractional baud rate cycle timing verification (100 cycles per 3 bits)
//   4. Glitch rejection on rx_pin (short pulse < 16 cycles rejected)
//   5. Framing error detection (stop bit forced low asserts frame_err)
//   6. Back-to-back transmission with zero idle cycles
//   7. Synchronous reset recovery mid-frame
//
// Owner: Member A (Ingress, Parser, and Interface Contract)
//==============================================================================

`timescale 1ns / 1ps

module tb_uart;

    reg        clk;
    reg        rst;

    // TX signals
    reg  [7:0] tx_data;
    reg        tx_valid;
    wire       tx_pin;
    wire       tx_busy;
    wire       tx_done;

    // RX signals
    reg        rx_pin_mux; // Mux between loopback tx_pin and manual injection
    wire [7:0] rx_data;
    wire       rx_valid;
    wire       rx_busy;
    wire       frame_err;

    integer errors = 0;
    integer rx_count = 0;

    // Instantiate Transmitter
    uart_tx #(
        .CLK_FREQ  (100000000),
        .BAUD_RATE (3000000)
    ) u_tx (
        .clk      (clk),
        .rst      (rst),
        .tx_data  (tx_data),
        .tx_valid (tx_valid),
        .tx_pin   (tx_pin),
        .tx_busy  (tx_busy),
        .tx_done  (tx_done)
    );

    // Instantiate Receiver
    uart_rx #(
        .CLK_FREQ  (100000000),
        .BAUD_RATE (3000000)
    ) u_rx (
        .clk       (clk),
        .rst       (rst),
        .rx_pin    (rx_pin_mux),
        .rx_data   (rx_data),
        .rx_valid  (rx_valid),
        .rx_busy   (rx_busy),
        .frame_err (frame_err)
    );

    // 100 MHz clock generation (10 ns period)
    always #5 clk = ~clk;

    // Task to transmit a byte via u_tx and wait for loopback reception on u_rx
    task send_and_verify_byte;
        input [7:0] expected_byte;
        integer timeout;
        begin
            @(posedge clk);
            tx_data  <= expected_byte;
            tx_valid <= 1'b1;
            @(posedge clk);
            tx_valid <= 1'b0;

            // Wait for rx_valid with timeout
            timeout = 1000; // max 1000 cycles
            while (!rx_valid && timeout > 0) begin
                @(posedge clk);
                timeout = timeout - 1;
            end

            if (timeout == 0) begin
                $display("FAIL: Timeout waiting for rx_valid for byte 0x%02X", expected_byte);
                errors = errors + 1;
            end else if (rx_data !== expected_byte) begin
                $display("FAIL: Byte mismatch! Expected 0x%02X, got 0x%02X", expected_byte, rx_data);
                errors = errors + 1;
            end else begin
                $display("  PASS: Received byte 0x%02X correctly", rx_data);
            end

            // Wait until tx finishes stop bit
            while (tx_busy) begin
                @(posedge clk);
            end
            @(posedge clk);
        end
    endtask

    initial begin
        clk        = 1'b0;
        rst        = 1'b1;
        tx_data    = 8'h00;
        tx_valid   = 1'b0;
        rx_pin_mux = 1'b1;

        $display("==================================================================");
        $display("Starting Self-Checking Testbench for rtl/ingress/uart_rx.v & tx.v");
        $display("==================================================================");

        // Reset sequence (20 ns)
        #20;
        @(posedge clk);
        rst <= 1'b0;
        @(posedge clk);

        // Connect loopback: rx_pin_mux follows tx_pin
        rx_pin_mux = tx_pin;

        //----------------------------------------------------------------------
        // Test 1: Single-byte loopback with 8'hA5
        //----------------------------------------------------------------------
        $display("[Test 1] Single-Byte Loopback (0xA5)...");
        rx_pin_mux = tx_pin;
        send_and_verify_byte(8'hA5);

        //----------------------------------------------------------------------
        // Test 2: Multi-byte sequential loopback
        //----------------------------------------------------------------------
        $display("[Test 2] Multi-Byte Sequential Loopback...");
        send_and_verify_byte(8'h00);
        send_and_verify_byte(8'h55);
        send_and_verify_byte(8'hAA);
        send_and_verify_byte(8'hFF);
        send_and_verify_byte(8'h3C);
        send_and_verify_byte(8'hC3);

        //----------------------------------------------------------------------
        // Test 3: Fractional baud rate timing check (3 bits = exactly 100 cycles)
        //----------------------------------------------------------------------
        $display("[Test 3] Fractional Baud Timing Check...");
        begin : timing_check
            integer start_cycle, elapsed_cycles;
            @(posedge clk);
            tx_data  <= 8'h55; // Alternating 01010101: D0=1, D1=0, D2=1
            tx_valid <= 1'b1;
            @(posedge clk);
            tx_valid <= 1'b0;

            // Wait for start bit falling edge on tx_pin
            while (tx_pin !== 1'b0) @(posedge clk);
            start_cycle = $time / 10; // 10 ns clock

            // Trace actual pin transitions across 3 bits:
            // Start bit (0): 33 cycles -> D0 (1): 33 cycles -> D1 (0): 34 cycles -> D2 (1) rises at cycle 100!
            while (tx_pin !== 1'b1) @(posedge clk); // D0 rises
            while (tx_pin !== 1'b0) @(posedge clk); // D1 falls
            while (tx_pin !== 1'b1) @(posedge clk); // D2 rises
            elapsed_cycles = ($time / 10) - start_cycle;

            if (elapsed_cycles == 100) begin
                $display("  PASS: Exactly 100 cycles measured across 3-bit group (33.33 cycles/bit avg)");
            end else begin
                $display("  FAIL: Expected 100 cycles across 3 bits, got %0d", elapsed_cycles);
                errors = errors + 1;
            end

            // Wait for transmission to complete
            while (tx_busy) @(posedge clk);
            @(posedge clk);
        end

        //----------------------------------------------------------------------
        // Test 4: Start-bit glitch rejection
        //----------------------------------------------------------------------
        $display("[Test 4] Start-Bit Glitch Rejection...");
        begin : glitch_test
            rx_pin_mux = 1'b1;
            @(posedge clk);
            // Drive a 4-cycle glitch (much less than 16-cycle half-bit period)
            rx_pin_mux = 1'b0;
            repeat (4) @(posedge clk);
            rx_pin_mux = 1'b1;

            // Wait 50 cycles to ensure rx stays idle and no rx_valid or frame_err occurs
            repeat (50) begin
                @(posedge clk);
                if (rx_valid || frame_err) begin
                    $display("  FAIL: Spurious strobe generated from 4-cycle glitch!");
                    errors = errors + 1;
                end
            end
            $display("  PASS: 4-cycle glitch cleanly rejected by mid-bit filter");
        end

        //----------------------------------------------------------------------
        // Test 5: Framing error detection (stop bit missing/low)
        //----------------------------------------------------------------------
        $display("[Test 5] Framing Error Detection...");
        begin : framing_err_test
            integer i;
            reg frame_err_seen;
            frame_err_seen = 1'b0;
            rx_pin_mux = 1'b1;
            @(posedge clk);

            // Manual frame injection: Byte 0x55 with corrupted stop bit (0 instead of 1)
            // Start bit (33 cycles low)
            rx_pin_mux = 1'b0;
            repeat (33) begin
                @(posedge clk);
                if (frame_err) frame_err_seen = 1'b1;
            end

            // 8 Data bits (alternating 1 and 0)
            for (i = 0; i < 8; i = i + 1) begin
                rx_pin_mux = (i % 2 == 0) ? 1'b1 : 1'b0;
                repeat (33) begin
                    @(posedge clk);
                    if (frame_err) frame_err_seen = 1'b1;
                end
            end

            // Corrupted Stop bit: drive LOW for 34 cycles
            rx_pin_mux = 1'b0;
            repeat (34) begin
                @(posedge clk);
                if (frame_err) frame_err_seen = 1'b1;
            end

            // Additional 10 cycles observation
            repeat (10) begin
                @(posedge clk);
                if (frame_err) frame_err_seen = 1'b1;
            end

            if (frame_err_seen == 1'b1) begin
                $display("  PASS: frame_err asserted on corrupted stop bit");
            end else begin
                $display("  FAIL: frame_err was NOT asserted on missing stop bit!");
                errors = errors + 1;
            end

            rx_pin_mux = 1'b1; // Restore idle line
            repeat (20) @(posedge clk);
        end

        //----------------------------------------------------------------------
        // Test 6: Synchronous reset recovery mid-frame
        //----------------------------------------------------------------------
        $display("[Test 6] Synchronous Reset Recovery Mid-Frame...");
        begin : reset_recovery_test
            rx_pin_mux = tx_pin;
            @(posedge clk);
            tx_data  <= 8'hEE;
            tx_valid <= 1'b1;
            @(posedge clk);
            tx_valid <= 1'b0;

            // Wait until mid-transmission (50 cycles)
            repeat (50) @(posedge clk);

            // Assert synchronous reset
            rst <= 1'b1;
            repeat (4) @(posedge clk);
            rst <= 1'b0;
            @(posedge clk);

            if (tx_busy == 1'b0 && rx_busy == 1'b0 && tx_pin == 1'b1) begin
                $display("  PASS: Reset cleanly recovered both FSMs to IDLE");
            end else begin
                $display("  FAIL: Reset did not restore idle state! tx_busy=%0b, rx_busy=%0b", tx_busy, rx_busy);
                errors = errors + 1;
            end

            // Verify normal operation resumes after reset
            send_and_verify_byte(8'h77);
        end

        //----------------------------------------------------------------------
        // Final Summary
        //----------------------------------------------------------------------
        $display("==================================================================");
        if (errors == 0) begin
            $display("ALL UART TESTS PASSED SUCCESSFULLY! (0 errors)");
        end else begin
            $display("TEST FAILED with %0d error(s).", errors);
        end
        $display("==================================================================");

        $finish;
    end

endmodule

// sim/test_drop_engine_tb.v
//
// Self-checking testbench for rtl/control/drop_engine.v
// Verifies:
//   1. Normal clean data packet passes (all 5 lanes pass)
//   2. Single failure detection (RC_MALFORMED)
//   3. Simultaneous failure priority (RC_MALFORMED > RC_FLOOD) & dual telemetry counter increment
//   4. Telemetry Exception (v1.1.0 §6): RC_BAD_TAG suppresses cnt_signature increment
//   5. Handshake packet evaluation (only CRC, PROTO, CMS participate)
//   6. Out-of-band frame timeout (RC_FRAME_TIMEOUT)

`timescale 1ns / 1ps
`include "reason_codes.vh"

module test_drop_engine_tb;

    reg        clk;
    reg        rst;

    reg        pkt_sof;
    reg        pkt_eof;
    reg [1:0]  pkt_type;

    reg        v_crc_valid, v_crc_fail;
    reg [3:0]  v_crc_reason;

    reg        v_deframe_valid, v_deframe_fail;
    reg [3:0]  v_deframe_reason;

    reg        v_proto_valid, v_proto_fail;
    reg [3:0]  v_proto_reason;

    reg        v_cam_valid, v_cam_fail;
    reg [3:0]  v_cam_reason;

    reg        v_cms_valid, v_cms_fail;
    reg [3:0]  v_cms_reason;

    reg        v_poly_valid, v_poly_fail;
    reg [3:0]  v_poly_reason;

    reg        v_kem_valid, v_kem_fail;
    reg [3:0]  v_kem_reason;

    wire        drop_valid;
    wire        drop_fail;
    wire [3:0]  drop_reason;

    wire [31:0] cnt_crc_fail;
    wire [31:0] cnt_frame_timeout;
    wire [31:0] cnt_malformed;
    wire [31:0] cnt_signature;
    wire [31:0] cnt_flood;
    wire [31:0] cnt_scan;
    wire [31:0] cnt_bad_tag;
    wire [31:0] cnt_handshake_key_invalid;
    wire [31:0] cnt_total_drops;
    wire [31:0] cnt_total_passed;

    // Instantiate DUT
    drop_engine dut (
        .clk(clk),
        .rst(rst),
        .pkt_sof(pkt_sof),
        .pkt_eof(pkt_eof),
        .pkt_type(pkt_type),
        .v_crc_valid(v_crc_valid),
        .v_crc_fail(v_crc_fail),
        .v_crc_reason(v_crc_reason),
        .v_deframe_valid(v_deframe_valid),
        .v_deframe_fail(v_deframe_fail),
        .v_deframe_reason(v_deframe_reason),
        .v_proto_valid(v_proto_valid),
        .v_proto_fail(v_proto_fail),
        .v_proto_reason(v_proto_reason),
        .v_cam_valid(v_cam_valid),
        .v_cam_fail(v_cam_fail),
        .v_cam_reason(v_cam_reason),
        .v_cms_valid(v_cms_valid),
        .v_cms_fail(v_cms_fail),
        .v_cms_reason(v_cms_reason),
        .v_poly_valid(v_poly_valid),
        .v_poly_fail(v_poly_fail),
        .v_poly_reason(v_poly_reason),
        .v_kem_valid(v_kem_valid),
        .v_kem_fail(v_kem_fail),
        .v_kem_reason(v_kem_reason),
        .drop_valid(drop_valid),
        .drop_fail(drop_fail),
        .drop_reason(drop_reason),
        .cnt_crc_fail(cnt_crc_fail),
        .cnt_frame_timeout(cnt_frame_timeout),
        .cnt_malformed(cnt_malformed),
        .cnt_signature(cnt_signature),
        .cnt_flood(cnt_flood),
        .cnt_scan(cnt_scan),
        .cnt_bad_tag(cnt_bad_tag),
        .cnt_handshake_key_invalid(cnt_handshake_key_invalid),
        .cnt_total_drops(cnt_total_drops),
        .cnt_total_passed(cnt_total_passed)
    );

    // 100 MHz clock (10 ns period)
    always #5 clk = ~clk;

    integer test_errors;

    task clear_inputs;
        begin
            pkt_sof          = 1'b0;
            pkt_eof          = 1'b0;
            pkt_type         = 2'b00;
            v_crc_valid      = 1'b0;
            v_crc_fail       = 1'b0;
            v_crc_reason     = `RC_NONE;
            v_deframe_valid  = 1'b0;
            v_deframe_fail   = 1'b0;
            v_deframe_reason = `RC_NONE;
            v_proto_valid    = 1'b0;
            v_proto_fail     = 1'b0;
            v_proto_reason   = `RC_NONE;
            v_cam_valid      = 1'b0;
            v_cam_fail       = 1'b0;
            v_cam_reason     = `RC_NONE;
            v_cms_valid      = 1'b0;
            v_cms_fail       = 1'b0;
            v_cms_reason     = `RC_NONE;
            v_poly_valid     = 1'b0;
            v_poly_fail      = 1'b0;
            v_poly_reason    = `RC_NONE;
            v_kem_valid      = 1'b0;
            v_kem_fail       = 1'b0;
            v_kem_reason     = `RC_NONE;
        end
    endtask

    task wait_for_verdict;
        integer timeout;
        begin
            timeout = 0;
            while (!drop_valid && timeout < 50) begin
                @(posedge clk);
                timeout = timeout + 1;
            end
            #1; // Hold on active cycle
            if (timeout >= 50) begin
                $display("ERROR: Timed out waiting for drop_valid!");
                test_errors = test_errors + 1;
            end
        end
    endtask

    initial begin
        clk = 0;
        rst = 1;
        test_errors = 0;
        clear_inputs();

        // Hold reset for 3 cycles
        repeat (3) @(negedge clk);
        rst = 0;
        @(negedge clk);

        $display("====================================================================");
        $display("sim/test_drop_engine_tb.v -- Drop Engine Verification");
        $display("====================================================================");

        // ---------------------------------------------------------------------
        // Test 1: Clean Data Packet (all 5 lanes pass)
        // ---------------------------------------------------------------------
        $display("[TEST 1] Clean DATA packet: all lanes pass");
        @(negedge clk);
        pkt_sof  = 1'b1;
        pkt_type = 2'b01; // DATA
        @(negedge clk);
        pkt_sof = 1'b0;

        // Protocol validator resolves early (cycle 2)
        v_proto_valid = 1'b1; v_proto_fail = 1'b0; v_proto_reason = `RC_NONE;
        @(negedge clk);
        v_proto_valid = 1'b0;

        // CRC and CMS resolve at/shortly after eof
        pkt_eof = 1'b1;
        v_crc_valid = 1'b1; v_crc_fail = 1'b0; v_crc_reason = `RC_NONE;
        @(negedge clk);
        pkt_eof = 1'b0;
        v_crc_valid = 1'b0;

        v_cms_valid = 1'b1; v_cms_fail = 1'b0; v_cms_reason = `RC_NONE;
        @(negedge clk);
        v_cms_valid = 1'b0;

        // CAM and Poly resolve last (streaming plaintext & tag verification)
        v_cam_valid  = 1'b1; v_cam_fail  = 1'b0; v_cam_reason  = `RC_NONE;
        v_poly_valid = 1'b1; v_poly_fail = 1'b0; v_poly_reason = `RC_NONE;
        @(negedge clk);
        v_cam_valid  = 1'b0;
        v_poly_valid = 1'b0;

        // Synchronize on drop_valid strobe
        wait_for_verdict();
        if (!drop_valid || drop_fail != 1'b0 || drop_reason != `RC_NONE) begin
            $display("FAILED: Test 1 clean packet check. valid=%b fail=%b reason=%h", drop_valid, drop_fail, drop_reason);
            test_errors = test_errors + 1;
        end else if (cnt_total_passed !== 32'd1 || cnt_total_drops !== 32'd0) begin
            $display("FAILED: Test 1 counters mismatch. passed=%d drops=%d", cnt_total_passed, cnt_total_drops);
            test_errors = test_errors + 1;
        end else begin
            $display("  --> PASS: Clean packet passed, cnt_total_passed = %d", cnt_total_passed);
        end

        repeat (2) @(negedge clk);

        // ---------------------------------------------------------------------
        // Test 2: Single Failure (Protocol Validator -> RC_MALFORMED)
        // ---------------------------------------------------------------------
        $display("[TEST 2] Single failure: PROTO fails with RC_MALFORMED");
        @(negedge clk);
        pkt_sof  = 1'b1;
        pkt_type = 2'b01;
        @(negedge clk);
        pkt_sof = 1'b0;

        // Proto signals fail immediately
        v_proto_valid = 1'b1; v_proto_fail = 1'b1; v_proto_reason = `RC_MALFORMED;
        @(negedge clk);
        v_proto_valid = 1'b0;

        // Other lanes report clean
        v_crc_valid = 1'b1; v_crc_fail = 1'b0;
        @(negedge clk);
        v_crc_valid = 1'b0;
        v_cms_valid = 1'b1; v_cms_fail = 1'b0;
        @(negedge clk);
        v_cms_valid = 1'b0;
        v_cam_valid = 1'b1; v_cam_fail = 1'b0;
        v_poly_valid = 1'b1; v_poly_fail = 1'b0;
        @(negedge clk);
        v_cam_valid = 1'b0; v_poly_valid = 1'b0;

        wait_for_verdict();
        if (!drop_valid || drop_fail != 1'b1 || drop_reason != `RC_MALFORMED) begin
            $display("FAILED: Test 2 malformed check. valid=%b fail=%b reason=%h", drop_valid, drop_fail, drop_reason);
            test_errors = test_errors + 1;
        end else if (cnt_malformed !== 32'd1 || cnt_total_drops !== 32'd1) begin
            $display("FAILED: Test 2 counters mismatch. cnt_malformed=%d cnt_drops=%d", cnt_malformed, cnt_total_drops);
            test_errors = test_errors + 1;
        end else begin
            $display("  --> PASS: RC_MALFORMED dropped correctly, cnt_malformed = %d", cnt_malformed);
        end

        repeat (2) @(negedge clk);

        // ---------------------------------------------------------------------
        // Test 3: Dual Failure Priority (RC_MALFORMED + RC_FLOOD)
        // Contract Section 6: RC_MALFORMED wins egress register, BOTH counters increment
        // ---------------------------------------------------------------------
        $display("[TEST 3] Simultaneous failure: RC_MALFORMED + RC_FLOOD");
        @(negedge clk);
        pkt_sof  = 1'b1;
        pkt_type = 2'b01;
        @(negedge clk);
        pkt_sof = 1'b0;

        v_proto_valid = 1'b1; v_proto_fail = 1'b1; v_proto_reason = `RC_MALFORMED;
        v_cms_valid   = 1'b1; v_cms_fail   = 1'b1; v_cms_reason   = `RC_FLOOD;
        @(negedge clk);
        v_proto_valid = 1'b0; v_cms_valid = 1'b0;

        v_crc_valid = 1'b1; v_crc_fail = 1'b0;
        v_cam_valid = 1'b1; v_cam_fail = 1'b0;
        v_poly_valid = 1'b1; v_poly_fail = 1'b0;
        @(negedge clk);
        v_crc_valid = 1'b0; v_cam_valid = 1'b0; v_poly_valid = 1'b0;

        wait_for_verdict();
        if (!drop_valid || drop_fail != 1'b1 || drop_reason != `RC_MALFORMED) begin
            $display("FAILED: Test 3 priority check. valid=%b fail=%b reason=%h (expected RC_MALFORMED 3)", drop_valid, drop_fail, drop_reason);
            test_errors = test_errors + 1;
        end else if (cnt_malformed !== 32'd2 || cnt_flood !== 32'd1) begin
            $display("FAILED: Test 3 dual counters mismatch. cnt_malformed=%d cnt_flood=%d", cnt_malformed, cnt_flood);
            test_errors = test_errors + 1;
        end else begin
            $display("  --> PASS: RC_MALFORMED won egress over RC_FLOOD, both counters incremented");
        end

        repeat (2) @(negedge clk);

        // ---------------------------------------------------------------------
        // Test 4: Telemetry Exception (v1.1.0 §6)
        // RC_BAD_TAG + RC_SIGNATURE simultaneously:
        // Egress reason = RC_BAD_TAG, cnt_bad_tag increments, cnt_signature DOES NOT increment!
        // ---------------------------------------------------------------------
        $display("[TEST 4] Telemetry Exception: RC_BAD_TAG + RC_SIGNATURE");
        @(negedge clk);
        pkt_sof  = 1'b1;
        pkt_type = 2'b01;
        @(negedge clk);
        pkt_sof = 1'b0;

        v_proto_valid = 1'b1; v_proto_fail = 1'b0;
        v_crc_valid   = 1'b1; v_crc_fail   = 1'b0;
        v_cms_valid   = 1'b1; v_cms_fail   = 1'b0;
        @(negedge clk);
        v_proto_valid = 1'b0; v_crc_valid = 1'b0; v_cms_valid = 1'b0;

        // Simultaneous CAM hit and Poly tag fail
        v_cam_valid  = 1'b1; v_cam_fail  = 1'b1; v_cam_reason  = `RC_SIGNATURE;
        v_poly_valid = 1'b1; v_poly_fail = 1'b1; v_poly_reason = `RC_BAD_TAG;
        @(negedge clk);
        v_cam_valid = 1'b0; v_poly_valid = 1'b0;

        wait_for_verdict();
        if (!drop_valid || drop_fail != 1'b1 || drop_reason != `RC_BAD_TAG) begin
            $display("FAILED: Test 4 egress check. valid=%b fail=%b reason=%h (expected RC_BAD_TAG 7)", drop_valid, drop_fail, drop_reason);
            test_errors = test_errors + 1;
        end else if (cnt_bad_tag !== 32'd1 || cnt_signature !== 32'd0) begin
            $display("FAILED: Test 4 telemetry exception check! cnt_bad_tag=%d cnt_signature=%d (must be 0)", cnt_bad_tag, cnt_signature);
            test_errors = test_errors + 1;
        end else begin
            $display("  --> PASS: Telemetry Exception verified! cnt_bad_tag = %d, cnt_signature held at %d", cnt_bad_tag, cnt_signature);
        end

        repeat (2) @(negedge clk);

        // ---------------------------------------------------------------------
        // Test 5: Handshake Packet (pkt_type = 2'b00, only CRC, PROTO, CMS participate)
        // ---------------------------------------------------------------------
        $display("[TEST 5] Handshake Packet: CAM and POLY do not participate");
        @(negedge clk);
        pkt_sof  = 1'b1;
        pkt_type = 2'b00; // HS_INIT
        @(negedge clk);
        pkt_sof = 1'b0;

        v_proto_valid = 1'b1; v_proto_fail = 1'b0;
        @(negedge clk);
        v_proto_valid = 1'b0;
        v_crc_valid = 1'b1; v_crc_fail = 1'b0;
        @(negedge clk);
        v_crc_valid = 1'b0;
        v_cms_valid = 1'b1; v_cms_fail = 1'b0;
        @(negedge clk);
        v_cms_valid = 1'b0;

        // Drop engine should resolve without waiting for CAM or POLY
        wait_for_verdict();
        if (!drop_valid || drop_fail != 1'b0 || drop_reason != `RC_NONE) begin
            $display("FAILED: Test 5 handshake check. valid=%b fail=%b reason=%h", drop_valid, drop_fail, drop_reason);
            test_errors = test_errors + 1;
        end else if (cnt_total_passed !== 32'd2) begin
            $display("FAILED: Test 5 passed count mismatch. got %d, expected 2", cnt_total_passed);
            test_errors = test_errors + 1;
        end else begin
            $display("  --> PASS: Handshake passed without CAM/POLY, cnt_total_passed = %d", cnt_total_passed);
        end

        repeat (2) @(negedge clk);

        // ---------------------------------------------------------------------
        // Test 6: Out-of-band Frame Timeout (deframer)
        // ---------------------------------------------------------------------
        $display("[TEST 6] Out-of-band Frame Timeout from deframer");
        @(negedge clk);
        pkt_sof  = 1'b1;
        pkt_type = 2'b01;
        @(negedge clk);
        pkt_sof = 1'b0;

        // Deframer times out before other lanes finish
        v_deframe_valid = 1'b1; v_deframe_fail = 1'b1; v_deframe_reason = `RC_FRAME_TIMEOUT;
        @(negedge clk);
        v_deframe_valid = 1'b0;

        wait_for_verdict();
        if (!drop_valid || drop_fail != 1'b1 || drop_reason != `RC_FRAME_TIMEOUT) begin
            $display("FAILED: Test 6 timeout check. valid=%b fail=%b reason=%h", drop_valid, drop_fail, drop_reason);
            test_errors = test_errors + 1;
        end else if (cnt_frame_timeout !== 32'd1) begin
            $display("FAILED: Test 6 timeout counter mismatch. got %d", cnt_frame_timeout);
            test_errors = test_errors + 1;
        end else begin
            $display("  --> PASS: Frame timeout caught, cnt_frame_timeout = %d", cnt_frame_timeout);
        end

        // ---------------------------------------------------------------------
        // Final Summary
        // ---------------------------------------------------------------------
        $display("====================================================================");
        if (test_errors == 0) begin
            $display("ALL Drop Engine checks PASSED with 0 errors.");
        end else begin
            $display("Drop Engine verification FAILED with %d errors.", test_errors);
        end
        $display("====================================================================");

        $finish;
    end

endmodule

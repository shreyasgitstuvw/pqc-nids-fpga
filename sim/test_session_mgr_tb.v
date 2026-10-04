`timescale 1ns / 1ps
// Self-checking testbench for session_mgr.v. Run:
//   iverilog -g2005 -o sim/sm.vvp sim/test_session_mgr_tb.v rtl/control/session_mgr.v && vvp sim/sm.vvp
module test_session_mgr_tb;
    reg clk = 0, rst = 1;
    always #5 clk = ~clk;

    reg         kem_done = 0, kem_key_invalid = 0;
    reg [15:0]  kem_session_id = 0;
    reg [255:0] kem_shared_secret = 0;
    reg         lk_req = 0;
    reg [15:0]  lk_id = 0;
    reg         nonce_adv = 0;
    reg [15:0]  nonce_adv_id = 0;
    wire        lk_valid, lk_ok;
    wire [255:0] lk_key;
    wire [95:0]  lk_nonce;
    wire [1:0]   lk_state;

    session_mgr dut (.clk(clk), .rst(rst),
        .kem_done(kem_done), .kem_session_id(kem_session_id),
        .kem_shared_secret(kem_shared_secret), .kem_key_invalid(kem_key_invalid),
        .lk_req(lk_req), .lk_id(lk_id), .lk_valid(lk_valid), .lk_ok(lk_ok),
        .lk_key(lk_key), .lk_nonce(lk_nonce), .lk_state(lk_state),
        .nonce_adv(nonce_adv), .nonce_adv_id(nonce_adv_id));

    integer errors = 0;
    task check(input cond, input [255:0] tag);
        begin
            if (!cond) begin errors = errors + 1; $display("[FAIL] check #%0d", tag); end
        end
    endtask

    task kem(input [15:0] id, input [255:0] key);
        begin
            @(negedge clk); kem_done = 1; kem_session_id = id; kem_shared_secret = key;
            @(negedge clk); kem_done = 0;
        end
    endtask

    task kem_invalid(input [15:0] id);
        begin
            @(negedge clk); kem_key_invalid = 1; kem_session_id = id;
            @(negedge clk); kem_key_invalid = 0;
        end
    endtask

    task adv(input [15:0] id);
        begin
            @(negedge clk); nonce_adv = 1; nonce_adv_id = id;
            @(negedge clk); nonce_adv = 0;
        end
    endtask

    // issue lookup, sample result on the cycle lk_valid is high
    task look(input [15:0] id);
        begin
            @(negedge clk); lk_req = 1; lk_id = id;
            @(negedge clk); lk_req = 0;
            // lk_valid was set at the posedge between the two negedges: still high here
            check(lk_valid === 1'b1, 100);
        end
    endtask

    localparam [255:0] KEY_GOOD  = 256'h1111_1111_1111_1111_2222_2222_2222_2222_3333_3333_3333_3333_4444_4444_4444_4444;
    localparam [255:0] KEY_DECOY = 256'hDEAD_BEEF_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_CAFE_F00D;

    // for the timing-leak test: record lookup waveform of two sessions
    reg [1:0]  st_a, st_b;
    reg        ok_a, ok_b;
    reg [95:0] n_a, n_b;

    initial begin
        repeat (3) @(negedge clk); rst = 0;

        // 1. reset state: everything IDLE, miss
        look(16'd1); check(lk_ok === 0 && lk_state === 2'b00, 1);

        // 2. kem_done -> ESTABLISHED with key, nonce 0
        kem(16'd1, KEY_GOOD);
        look(16'd1);
        check(lk_ok === 1 && lk_state === 2'b10 && lk_key === KEY_GOOD && lk_nonce === 96'd0, 2);

        // 3. nonce advances, never repeats
        adv(16'd1); adv(16'd1); adv(16'd1);
        look(16'd1); check(lk_nonce === 96'd3, 3);
        adv(16'd2);                                  // other session unaffected
        look(16'd1); check(lk_nonce === 96'd3, 4);

        // 4. re-key resets counter
        kem(16'd1, KEY_DECOY);
        look(16'd1); check(lk_key === KEY_DECOY && lk_nonce === 96'd0, 5);

        // 5. INDISTINGUISHABILITY: genuine vs decoy -> identical state/observables
        kem(16'd2, KEY_GOOD);
        kem(16'd3, KEY_DECOY);
        look(16'd2); st_a = lk_state; ok_a = lk_ok; n_a = lk_nonce;
        look(16'd3); st_b = lk_state; ok_b = lk_ok; n_b = lk_nonce;
        check(st_a === st_b && ok_a === ok_b && n_a === n_b && st_a === 2'b10, 6);

        // 6. structural failure -> REJECTED, key zeroised, lk_ok = 0
        kem_invalid(16'd2);
        look(16'd2);
        check(lk_state === 2'b11 && lk_ok === 0 && lk_key === 256'd0, 7);
        adv(16'd2);                                  // advance must not touch REJECTED
        look(16'd2); check(lk_nonce === 96'd0, 8);

        // 7. REJECTED never reached via kem_done; a later kem_done re-establishes
        kem(16'd2, KEY_GOOD);
        look(16'd2); check(lk_state === 2'b10, 9);

        // 8. reserved / out-of-range ids ignored
        kem(16'd0, KEY_GOOD);
        look(16'd0); check(lk_ok === 0 && lk_state === 2'b00, 10);
        kem(16'd5, KEY_GOOD);
        look(16'd5); check(lk_ok === 0, 11);
        kem(16'h0101, KEY_GOOD);                     // alias of id 1 must NOT write
        look(16'd1); check(lk_key === KEY_DECOY, 12);

        // 9. lk_valid is a pure 1-cycle strobe
        @(negedge clk); lk_req = 1; lk_id = 16'd1;
        @(negedge clk); lk_req = 0;
        check(lk_valid === 1, 13);
        @(posedge clk); #1; check(lk_valid === 0, 14);

        if (errors == 0) $display("[PASS] session_mgr: all checks passed");
        else             $display("[FAIL] session_mgr: %0d errors", errors);
        $finish;
    end
endmodule

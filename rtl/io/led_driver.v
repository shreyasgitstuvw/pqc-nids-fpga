//==========================================================================
// rtl/io/led_driver.v
//
// ZedBoard LD0-LD7 status display. Mirrors demo/display/led_map.py exactly;
// the two must change in the same commit (execution plan section 8).
//
//   LD0  session established            solid while any session is ESTABLISHED
//                                       fast blink on RC_HANDSHAKE_KEY_INVALID,
//                                       because a rejected key means no session
//                                       rather than a dropped packet
//   LD1  RC_CRC_FAIL              (1)   slow blink
//   LD2  RC_FRAME_TIMEOUT         (2)   slow blink
//   LD3  RC_MALFORMED             (3)   slow blink
//   LD4  RC_SIGNATURE             (4)   fast blink
//   LD5  RC_FLOOD                 (5)   slow blink
//   LD6  RC_SCAN                  (6)   slow blink
//   LD7  RC_BAD_TAG               (7)   fast blink
//
// A drop latches its LED and starts it blinking for HOLD_MS so a single dropped
// packet is visible to the eye; the LED clears when the hold expires and no
// further drop of that class has arrived.
//
// Resource estimate (XC7Z020, pre-synthesis): ~90 FFs, ~60 LUTs. No BRAM/DSP.
//==========================================================================

`timescale 1ns / 1ps

`include "reason_codes.vh"

module led_driver #(
    parameter integer CLK_HZ   = 100_000_000,
    parameter integer HOLD_MS  = 600,   // how long a drop keeps its LED lit
    parameter integer SLOW_MS  = 500,   // blink period, matches BLINK["slow"]
    parameter integer FAST_MS  = 120    // blink period, matches BLINK["fast"]
) (
    input  wire       clk,
    input  wire       rst,

    // from drop_engine.v
    input  wire       drop_valid,
    input  wire       drop_fail,
    input  wire [3:0] drop_reason,

    // from session_mgr.v / session_lookup.v
    input  wire       session_established,

    output reg  [7:0] led
);

    localparam integer HOLD_CYCLES = (CLK_HZ / 1000) * HOLD_MS;
    localparam integer SLOW_HALF   = (CLK_HZ / 2000) * SLOW_MS;
    localparam integer FAST_HALF   = (CLK_HZ / 2000) * FAST_MS;

    // Wide enough for the largest of the three, computed at elaboration.
    localparam integer CW = 32;

    reg [CW-1:0] slow_cnt, fast_cnt;
    reg          slow_ph, fast_ph;

    // One hold timer per droppable class (reason codes 1..7).
    reg [CW-1:0] hold [1:7];
    reg [CW-1:0] hold_ki;          // RC_HANDSHAKE_KEY_INVALID, shown on LD0

    wire        drop_now = drop_valid && drop_fail;
    wire [3:0]  r        = drop_reason;

    integer i;

    always @(posedge clk) begin
        if (rst) begin
            slow_cnt <= {CW{1'b0}};
            fast_cnt <= {CW{1'b0}};
            slow_ph  <= 1'b0;
            fast_ph  <= 1'b0;
            hold_ki  <= {CW{1'b0}};
            led      <= 8'h00;
            for (i = 1; i <= 7; i = i + 1)
                hold[i] <= {CW{1'b0}};
        end else begin
            // ---- blink phase generators ----
            if (slow_cnt >= SLOW_HALF[CW-1:0]) begin
                slow_cnt <= {CW{1'b0}};
                slow_ph  <= ~slow_ph;
            end else begin
                slow_cnt <= slow_cnt + {{(CW-1){1'b0}}, 1'b1};
            end

            if (fast_cnt >= FAST_HALF[CW-1:0]) begin
                fast_cnt <= {CW{1'b0}};
                fast_ph  <= ~fast_ph;
            end else begin
                fast_cnt <= fast_cnt + {{(CW-1){1'b0}}, 1'b1};
            end

            // ---- hold timers ----
            for (i = 1; i <= 7; i = i + 1) begin
                if (drop_now && (r == i[3:0]))
                    hold[i] <= HOLD_CYCLES[CW-1:0];
                else if (hold[i] != {CW{1'b0}})
                    hold[i] <= hold[i] - {{(CW-1){1'b0}}, 1'b1};
            end

            if (drop_now && (r == `RC_HANDSHAKE_KEY_INVALID))
                hold_ki <= HOLD_CYCLES[CW-1:0];
            else if (hold_ki != {CW{1'b0}})
                hold_ki <= hold_ki - {{(CW-1){1'b0}}, 1'b1};

            // ---- drive the LEDs ----
            // LD0: a rejected key outranks the solid session indication, so an
            // operator sees the rejection rather than a still-lit session LED.
            led[0] <= (hold_ki != {CW{1'b0}}) ? fast_ph : session_established;
            led[1] <= (hold[1] != {CW{1'b0}}) && slow_ph;   // CRC_FAIL
            led[2] <= (hold[2] != {CW{1'b0}}) && slow_ph;   // FRAME_TIMEOUT
            led[3] <= (hold[3] != {CW{1'b0}}) && slow_ph;   // MALFORMED
            led[4] <= (hold[4] != {CW{1'b0}}) && fast_ph;   // SIGNATURE
            led[5] <= (hold[5] != {CW{1'b0}}) && slow_ph;   // FLOOD
            led[6] <= (hold[6] != {CW{1'b0}}) && slow_ph;   // SCAN
            led[7] <= (hold[7] != {CW{1'b0}}) && fast_ph;   // BAD_TAG
        end
    end

endmodule

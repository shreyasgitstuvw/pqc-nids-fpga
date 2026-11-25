# Hook-up into rtl/top/pqc_nids_top.v (apply by hand, ~15 lines)

0. FIX LD0 / session_established (found on the bench): LD0 lights ~180 us after every reset because
   the automatic post-reset KeyGen strobes kem_done and `any_session_up` sets on any kem_done.
   In rtl/top/pqc_nids_top.v, MOVE the `any_session_up` always block to just AFTER the
   `pending_encaps` block (it must follow that declaration) and change its set condition:

       else if (kem_done && pending_encaps)  any_session_up <= 1'b1;   // was: else if (kem_done)

   pending_encaps is only set by an HS_INIT packet, so the light now means "a peer handshake finished".
   Add a check to test_pqc_nids_top.py: after reset and the auto KeyGen, telemetry session_established == 0;
   after a valid HS_INIT it becomes 1.

1. Port list, after `output wire telem_tx_pin,`:

       output wire deliver_tx_pin,  // JD3 (Pmod pin 3, FPGA->module): vetted messages to Device B

2. Before the `// ---- signals observed only in simulation ----` comment:

       wire [7:0] fw_tx_data;  wire fw_tx_valid, fw_tx_busy, fw_tx_done_unused, fw_busy;
       wire [31:0] fw_deliv, fw_disc, fw_lost, fw_over;

       msg_fwd u_fwd (
           .clk(clk), .rst(rst_i),
           .pt_valid(pt_valid), .pt_data(pt_data), .pt_sof(pt_sof), .pt_eof(pt_eof),
           .pt_tag_ok(pt_tag_ok), .pt_tag_valid(pt_tag_valid),
           .drop_valid(drop_valid), .drop_fail(drop_fail),
           .tx_data(fw_tx_data), .tx_valid(fw_tx_valid), .tx_busy(fw_tx_busy),
           .cnt_delivered(fw_deliv), .cnt_discarded(fw_disc),
           .cnt_lost(fw_lost), .cnt_oversize(fw_over), .busy(fw_busy));

       uart_tx #(.CLK_FREQ(CLK_HZ), .BAUD_RATE(BAUD_RATE)) u_uart_tx_fw (
           .clk(clk), .rst(rst_i), .tx_data(fw_tx_data), .tx_valid(fw_tx_valid),
           .tx_pin(deliver_tx_pin), .tx_busy(fw_tx_busy), .tx_done(fw_tx_done_unused));

   Add fw_deliv, fw_disc, fw_lost, fw_over, fw_busy, fw_tx_done_unused to the `_unused_ok` list.

3. Add demo_forward/msg_fwd.v to the Vivado sources. In constraints/pqc_nids.xdc add (copy the
   IOSTANDARD from the existing telem_tx_pin line; JC and JD share a bank):

       set_property -dict {PACKAGE_PIN V5 IOSTANDARD <same as telem_tx_pin>} [get_ports deliver_tx_pin]   # JD2_P = Pmod pin 3

   VERIFY V5 = JD2_P in the ZedBoard master XDC (JD1_P V7, JD1_N W7, JD2_P V5, JD2_N V4), and that
   JD's bank voltage matches the Pmod USB-UART's 3.3 V logic as JC's does, before building.
   Wiring plan, four Pmod USB-UART modules, one per device:
       JA  Device A (sender)      JB  Device C (attacker, input only)
       JC  telemetry observer     JD  Device B (inbox, FPGA -> module only)

4. msg_fwd only listens to drop_valid/drop_fail. Do not change the verdict plumbing.

5. Unverified assumptions to check in the full-top simulation (test_pqc_nids_top.py):
   a. pt_valid && pt_sof marks the first plaintext byte, pt_eof the last.
   b. drop_valid for a DATA packet arrives after pt_eof (the module also tolerates before).
   c. a clean DATA packet's plaintext is delivered once; a SIGNATURE / BAD_TAG packet delivers nothing.

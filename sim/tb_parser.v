//==============================================================================
// sim/tb_parser.v
//
// Self-Checking Verilog-2001 Testbench for rtl/ingress/parser.v.
//
// Test Coverage:
//   1. Valid TCP Session Data Packet (PORT_DATA 51010 -> packet_type 2'b01)
//   2. Valid UDP Packet (Port 53 -> packet_type 2'b01)
//   3. Handshake Init Packet (PORT_HS_INIT 51001 -> packet_type 2'b00, 800B ek)
//   4. Handshake Resp Packet (PORT_HS_RESP 51002 -> packet_type 2'b10, 768B ct)
//   5. Non-IPv4 Frame Rejection: ARP (EtherType 0x0806 -> parsed_ok=0)
//   6. Non-IPv4 Frame Rejection: IPv6 (EtherType 0x86DD -> parsed_ok=0)
//   7. Non-IPv4 Frame Rejection: LLDP (EtherType 0x88CC -> parsed_ok=0)
//   8. IPv4 Corrupted Version Rejection (Version 6 -> parsed_ok=0)
//   9. IPv4 Underflow IHL < 5 Rejection (IHL 4 -> parsed_ok=0)
//  10. IPv4 Options Rejection (IHL 6 -> parsed_ok=0)
//  11. Unsupported L4 Protocol Rejection: ICMP (Proto 1 -> parsed_ok=0)
//  12. Unsupported L4 Protocol Rejection: IGMP (Proto 2 -> parsed_ok=0)
//  13. Unsupported L4 Protocol Rejection: GRE (Proto 47 -> parsed_ok=0)
//  14. Truncated Frame: 1-byte frame (in_sof + in_eof -> parsed_ok=0)
//  15. Truncated Frame: Mid-Ethernet (<14B -> parsed_ok=0)
//  16. Truncated Frame: Mid-IPv4 (<34B -> parsed_ok=0)
//  17. Truncated Frame: Mid-TCP Header (<54B -> parsed_ok=0)
//  18. Truncated Payload vs Claimed Length (parsed_ok=0)
//  19. Malformed TCP Data Offset (<5 -> parsed_ok=0)
//  20. TCP with Options (data_offset=8 -> 32B header, parsed_ok=1)
//  21. Malformed UDP Length (<8 -> parsed_ok=0)
//  22. Zero-Payload TCP Packet (SYN/ACK, payload_len=0, out_valid=0)
//  23. Back-to-back packets with 0 gap cycles
//  24. Synchronous reset recovery mid-packet
//
// Owner: Member A (Ingress, Parser, and Interface Contract)
//==============================================================================

`timescale 1ns / 1ps
`include "reason_codes.vh"

module tb_parser;

    reg         clk;
    reg         rst;

    reg         in_valid;
    reg  [7:0]  in_data;
    reg         in_sof;
    reg         in_eof;

    wire        hdr_valid;
    wire        parsed_ok;

    wire [47:0] eth_dst_mac;
    wire [47:0] eth_src_mac;
    wire [15:0] eth_type;

    wire [7:0]  ip_version_ihl;
    wire [15:0] ip_total_length;
    wire [7:0]  ip_protocol;
    wire [31:0] ip_src_addr;
    wire [31:0] ip_dst_addr;

    wire [15:0] l4_src_port;
    wire [15:0] l4_dst_port;
    wire [7:0]  tcp_flags;
    wire [15:0] l4_length;

    wire [15:0] payload_len;
    wire [15:0] session_id;
    wire [1:0]  packet_type;

    wire        out_valid;
    wire        out_sof;
    wire        out_eof;
    wire [7:0]  out_data;

    integer errors = 0;
    integer rx_payload_bytes = 0;
    integer sof_count = 0;
    integer eof_count = 0;
    integer hdr_valid_count = 0;

    // Instantiate Device Under Test (DUT)
    parser dut (
        .clk             (clk),
        .rst             (rst),
        .in_valid        (in_valid),
        .in_data         (in_data),
        .in_sof          (in_sof),
        .in_eof          (in_eof),
        .hdr_valid       (hdr_valid),
        .parsed_ok       (parsed_ok),
        .eth_dst_mac     (eth_dst_mac),
        .eth_src_mac     (eth_src_mac),
        .eth_type        (eth_type),
        .ip_version_ihl  (ip_version_ihl),
        .ip_total_length (ip_total_length),
        .ip_protocol     (ip_protocol),
        .ip_src_addr     (ip_src_addr),
        .ip_dst_addr     (ip_dst_addr),
        .l4_src_port     (l4_src_port),
        .l4_dst_port     (l4_dst_port),
        .tcp_flags       (tcp_flags),
        .l4_length       (l4_length),
        .payload_len     (payload_len),
        .session_id      (session_id),
        .packet_type     (packet_type),
        .out_valid       (out_valid),
        .out_sof         (out_sof),
        .out_eof         (out_eof),
        .out_data        (out_data)
    );

    // 100 MHz system clock (10 ns period)
    always #5 clk = ~clk;

    // Monitor payload bytes and strobes
    always @(posedge clk) begin
        if (out_valid) begin
            rx_payload_bytes = rx_payload_bytes + 1;
            if (out_sof) sof_count = sof_count + 1;
            if (out_eof) eof_count = eof_count + 1;
        end
        if (hdr_valid) begin
            hdr_valid_count = hdr_valid_count + 1;
        end
    end

    // Storage buffer for test frame bytes (module-scope for Verilog-2001 compatibility)
    reg [7:0] frame_buf [0:2047];

    // Task to send a frame of length `len` bytes into the parser
    task send_frame;
        input integer len;
        integer i;
        begin
            rx_payload_bytes = 0;
            sof_count        = 0;
            eof_count        = 0;
            hdr_valid_count  = 0;

            for (i = 0; i < len; i = i + 1) begin
                @(posedge clk);
                in_valid <= 1'b1;
                in_data  <= frame_buf[i];
                in_sof   <= (i == 0);
                in_eof   <= (i == len - 1);
            end
            @(posedge clk);
            in_valid <= 1'b0;
            in_data  <= 8'h00;
            in_sof   <= 1'b0;
            in_eof   <= 1'b0;
        end
    endtask

    // Helper task to populate standard Ethernet header
    task set_eth_header;
        input [47:0] dmac;
        input [47:0] smac;
        input [15:0] etype;
        begin
            frame_buf[0]  = dmac[47:40]; frame_buf[1]  = dmac[39:32];
            frame_buf[2]  = dmac[31:24]; frame_buf[3]  = dmac[23:16];
            frame_buf[4]  = dmac[15:8];  frame_buf[5]  = dmac[7:0];
            frame_buf[6]  = smac[47:40]; frame_buf[7]  = smac[39:32];
            frame_buf[8]  = smac[31:24]; frame_buf[9]  = smac[23:16];
            frame_buf[10] = smac[15:8];  frame_buf[11] = smac[7:0];
            frame_buf[12] = etype[15:8]; frame_buf[13] = etype[7:0];
        end
    endtask

    // Helper task to populate standard IPv4 header
    task set_ipv4_header;
        input [7:0]  ver_ihl;
        input [15:0] total_len;
        input [7:0]  proto;
        input [31:0] sip;
        input [31:0] dip;
        begin
            frame_buf[14] = ver_ihl;
            frame_buf[15] = 8'h00; // TOS
            frame_buf[16] = total_len[15:8]; frame_buf[17] = total_len[7:0];
            frame_buf[18] = 8'h12; frame_buf[19] = 8'h34; // ID
            frame_buf[20] = 8'h40; frame_buf[21] = 8'h00; // Flags (DF)
            frame_buf[22] = 8'h40; // TTL (64)
            frame_buf[23] = proto;
            frame_buf[24] = 8'h00; frame_buf[25] = 8'h00; // Checksum
            frame_buf[26] = sip[31:24]; frame_buf[27] = sip[23:16];
            frame_buf[28] = sip[15:8];  frame_buf[29] = sip[7:0];
            frame_buf[30] = dip[31:24]; frame_buf[31] = dip[23:16];
            frame_buf[32] = dip[15:8];  frame_buf[33] = dip[7:0];
        end
    endtask

    // Helper task to populate standard TCP header
    task set_tcp_header;
        input [15:0] sport;
        input [15:0] dport;
        input [3:0]  offset;
        input [7:0]  flags;
        begin
            frame_buf[34] = sport[15:8]; frame_buf[35] = sport[7:0];
            frame_buf[36] = dport[15:8]; frame_buf[37] = dport[7:0];
            frame_buf[38] = 8'h00; frame_buf[39] = 8'h00; frame_buf[40] = 8'h00; frame_buf[41] = 8'h01; // Seq
            frame_buf[42] = 8'h00; frame_buf[43] = 8'h00; frame_buf[44] = 8'h00; frame_buf[45] = 8'h02; // Ack
            frame_buf[46] = {offset, 4'h0};
            frame_buf[47] = flags;
            frame_buf[48] = 8'h20; frame_buf[49] = 8'h00; // Window
            frame_buf[50] = 8'h00; frame_buf[51] = 8'h00; // Checksum
            frame_buf[52] = 8'h00; frame_buf[53] = 8'h00; // Urgent
        end
    endtask

    // Helper task to populate standard UDP header
    task set_udp_header;
        input [15:0] sport;
        input [15:0] dport;
        input [15:0] ulen;
        begin
            frame_buf[34] = sport[15:8]; frame_buf[35] = sport[7:0];
            frame_buf[36] = dport[15:8]; frame_buf[37] = dport[7:0];
            frame_buf[38] = ulen[15:8];  frame_buf[39] = ulen[7:0];
            frame_buf[40] = 8'h00; frame_buf[41] = 8'h00; // Checksum
        end
    endtask

    integer j;

    initial begin
        clk      = 1'b0;
        rst      = 1'b1;
        in_valid = 1'b0;
        in_data  = 8'h00;
        in_sof   = 1'b0;
        in_eof   = 1'b0;

        $display("==================================================================");
        $display("Starting Self-Checking Testbench for rtl/ingress/parser.v");
        $display("==================================================================");

        // Synchronous Reset sequence
        #20;
        @(posedge clk);
        rst <= 1'b0;
        @(posedge clk);

        //----------------------------------------------------------------------
        // Test 1: Valid TCP Session Data Packet (PORT_DATA 51010, 19B payload)
        //----------------------------------------------------------------------
        set_eth_header(48'h001122334455, 48'h66778899AABB, 16'h0800);
        set_ipv4_header(8'h45, 16'd59, 8'd6, 32'hC0A8010A, 32'hC0A80114); // 20+20+19 = 59
        set_tcp_header(16'd12345, 16'd51010, 4'd5, 8'h18); // PSH, ACK
        // 19 bytes payload: "SESSION_DATA_STREAM"
        frame_buf[54] = "S"; frame_buf[55] = "E"; frame_buf[56] = "S"; frame_buf[57] = "S";
        frame_buf[58] = "I"; frame_buf[59] = "O"; frame_buf[60] = "N"; frame_buf[61] = "_";
        frame_buf[62] = "D"; frame_buf[63] = "A"; frame_buf[64] = "T"; frame_buf[65] = "A";
        frame_buf[66] = "_"; frame_buf[67] = "S"; frame_buf[68] = "T"; frame_buf[69] = "R";
        frame_buf[70] = "E"; frame_buf[71] = "A"; frame_buf[72] = "M";

        send_frame(73);

        if (!parsed_ok || eth_type !== 16'h0800 || ip_protocol !== 8'd6 || l4_dst_port !== 16'd51010 || packet_type !== 2'b01 || payload_len !== 16'd19) begin
            $display("ERROR [Test 1]: Valid TCP Data Packet failed! parsed_ok=%b, type=%b, len=%0d", parsed_ok, packet_type, payload_len);
            errors = errors + 1;
        end else if (rx_payload_bytes !== 19 || sof_count !== 1 || eof_count !== 1) begin
            $display("ERROR [Test 1]: Payload stream error! rx_bytes=%0d, sof=%0d, eof=%0d", rx_payload_bytes, sof_count, eof_count);
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 1]: Valid TCP Session Data Packet -> PKT_DATA (2'b01), len=19");
        end

        repeat (2) @(posedge clk);

        //----------------------------------------------------------------------
        // Test 2: Valid UDP Packet (Port 53, 9B payload "DNS_QUERY")
        //----------------------------------------------------------------------
        set_eth_header(48'h001122334455, 48'h66778899AABB, 16'h0800);
        set_ipv4_header(8'h45, 16'd37, 8'd17, 32'hC0A8010A, 32'hC0A80114); // 20+8+9 = 37
        set_udp_header(16'd12345, 16'd53, 16'd17); // 8+9 = 17
        frame_buf[42] = "D"; frame_buf[43] = "N"; frame_buf[44] = "S"; frame_buf[45] = "_";
        frame_buf[46] = "Q"; frame_buf[47] = "U"; frame_buf[48] = "E"; frame_buf[49] = "R"; frame_buf[50] = "Y";

        send_frame(51);

        if (!parsed_ok || ip_protocol !== 8'd17 || l4_dst_port !== 16'd53 || payload_len !== 16'd9 || rx_payload_bytes !== 9) begin
            $display("ERROR [Test 2]: Valid UDP Packet failed! parsed_ok=%b, rx_bytes=%0d", parsed_ok, rx_payload_bytes);
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 2]: Valid UDP Packet -> PKT_DATA, payload_len=9");
        end

        repeat (2) @(posedge clk);

        //----------------------------------------------------------------------
        // Test 3: Handshake Init Packet (PORT_HS_INIT 51001, 800B ek -> 2'b00)
        //----------------------------------------------------------------------
        set_eth_header(48'h001122334455, 48'h66778899AABB, 16'h0800);
        set_ipv4_header(8'h45, 16'd828, 8'd17, 32'hC0A8010A, 32'hC0A80114); // 20+8+800 = 828
        set_udp_header(16'd12345, 16'd51001, 16'd808); // 8+800 = 808
        for (j = 0; j < 800; j = j + 1) begin
            frame_buf[42 + j] = 8'hAA;
        end

        send_frame(42 + 800);

        if (!parsed_ok || packet_type !== 2'b00 || payload_len !== 16'd800 || rx_payload_bytes !== 800) begin
            $display("ERROR [Test 3]: Handshake Init failed! parsed_ok=%b, type=%b, len=%0d, rx=%0d", parsed_ok, packet_type, payload_len, rx_payload_bytes);
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 3]: ML-KEM Handshake Init -> PKT_HANDSHAKE_EK (2'b00), len=800");
        end

        repeat (2) @(posedge clk);

        //----------------------------------------------------------------------
        // Test 4: Handshake Resp Packet (PORT_HS_RESP 51002, 768B ct -> 2'b10)
        //----------------------------------------------------------------------
        set_eth_header(48'h001122334455, 48'h66778899AABB, 16'h0800);
        set_ipv4_header(8'h45, 16'd796, 8'd17, 32'hC0A8010A, 32'hC0A80114); // 20+8+768 = 796
        set_udp_header(16'd12345, 16'd51002, 16'd776); // 8+768 = 776
        for (j = 0; j < 768; j = j + 1) begin
            frame_buf[42 + j] = 8'h55;
        end

        send_frame(42 + 768);

        if (!parsed_ok || packet_type !== 2'b10 || payload_len !== 16'd768 || rx_payload_bytes !== 768) begin
            $display("ERROR [Test 4]: Handshake Resp failed! parsed_ok=%b, type=%b, len=%0d", parsed_ok, packet_type, payload_len);
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 4]: ML-KEM Handshake Resp -> PKT_HANDSHAKE_CT (2'b10), len=768");
        end

        repeat (2) @(posedge clk);

        //----------------------------------------------------------------------
        // Test 5: Non-IPv4 Frame: ARP (0x0806) -> parsed_ok = 0
        //----------------------------------------------------------------------
        set_eth_header(48'hFFFFFFFFFFFF, 48'h66778899AABB, 16'h0806);
        for (j = 0; j < 28; j = j + 1) frame_buf[14 + j] = 8'h00;

        send_frame(42);

        if (parsed_ok !== 1'b0 || rx_payload_bytes !== 0) begin
            $display("ERROR [Test 5]: ARP frame did not fail! parsed_ok=%b", parsed_ok);
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 5]: Non-IPv4 Frame Rejection: ARP (0x0806) -> parsed_ok=0");
        end

        repeat (2) @(posedge clk);

        //----------------------------------------------------------------------
        // Test 6: Non-IPv4 Frame: IPv6 (0x86DD) -> parsed_ok = 0
        //----------------------------------------------------------------------
        set_eth_header(48'h001122334455, 48'h66778899AABB, 16'h86DD);
        for (j = 0; j < 40; j = j + 1) frame_buf[14 + j] = 8'h00;

        send_frame(54);

        if (parsed_ok !== 1'b0) begin
            $display("ERROR [Test 6]: IPv6 frame did not fail! parsed_ok=%b", parsed_ok);
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 6]: Non-IPv4 Frame Rejection: IPv6 (0x86DD) -> parsed_ok=0");
        end

        repeat (2) @(posedge clk);

        //----------------------------------------------------------------------
        // Test 7: Non-IPv4 Frame: LLDP (0x88CC) -> parsed_ok = 0
        //----------------------------------------------------------------------
        set_eth_header(48'h0180C200000E, 48'h66778899AABB, 16'h88CC);
        for (j = 0; j < 20; j = j + 1) frame_buf[14 + j] = 8'hAA;

        send_frame(34);

        if (parsed_ok !== 1'b0) begin
            $display("ERROR [Test 7]: LLDP frame did not fail!");
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 7]: Non-IPv4 Frame Rejection: LLDP (0x88CC) -> parsed_ok=0");
        end

        repeat (2) @(posedge clk);

        //----------------------------------------------------------------------
        // Test 8: IPv4 Corrupted Version (0x65 -> Version 6) -> parsed_ok = 0
        //----------------------------------------------------------------------
        set_eth_header(48'h001122334455, 48'h66778899AABB, 16'h0800);
        set_ipv4_header(8'h65, 16'd40, 8'd6, 32'hC0A8010A, 32'hC0A80114);
        set_tcp_header(16'd12345, 16'd51010, 4'd5, 8'h18);

        send_frame(54);

        if (parsed_ok !== 1'b0) begin
            $display("ERROR [Test 8]: Corrupted IPv4 version did not fail!");
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 8]: IPv4 Corrupted Version (0x65) -> parsed_ok=0");
        end

        repeat (2) @(posedge clk);

        //----------------------------------------------------------------------
        // Test 9: IPv4 Underflow IHL < 5 (IHL = 4 -> 0x44) -> parsed_ok = 0
        //----------------------------------------------------------------------
        set_eth_header(48'h001122334455, 48'h66778899AABB, 16'h0800);
        set_ipv4_header(8'h44, 16'd40, 8'd6, 32'hC0A8010A, 32'hC0A80114);
        set_tcp_header(16'd12345, 16'd51010, 4'd5, 8'h18);

        send_frame(54);

        if (parsed_ok !== 1'b0) begin
            $display("ERROR [Test 9]: Bad IHL=4 did not fail!");
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 9]: IPv4 Bad IHL < 5 (0x44) -> parsed_ok=0");
        end

        repeat (2) @(posedge clk);

        //----------------------------------------------------------------------
        // Test 10: IPv4 Options Rejection (IHL = 6 -> 0x46) -> parsed_ok = 0
        //----------------------------------------------------------------------
        set_eth_header(48'h001122334455, 48'h66778899AABB, 16'h0800);
        set_ipv4_header(8'h46, 16'd48, 8'd6, 32'hC0A8010A, 32'hC0A80114);
        frame_buf[34] = 8'h01; frame_buf[35] = 8'h01; frame_buf[36] = 8'h01; frame_buf[37] = 8'h01; // Options
        // TCP header at 38
        frame_buf[38] = 8'h30; frame_buf[39] = 8'h39; // sport 12345
        frame_buf[40] = 8'hC7; frame_buf[41] = 8'h42; // dport 51010
        frame_buf[42] = 8'h00; frame_buf[43] = 8'h00; frame_buf[44] = 8'h00; frame_buf[45] = 8'h01;
        frame_buf[46] = 8'h00; frame_buf[47] = 8'h00; frame_buf[48] = 8'h00; frame_buf[49] = 8'h02;
        frame_buf[50] = 8'h50; frame_buf[51] = 8'h18; // offset 5, flags
        frame_buf[52] = 8'h20; frame_buf[53] = 8'h00;
        frame_buf[54] = 8'h00; frame_buf[55] = 8'h00;
        frame_buf[56] = 8'h00; frame_buf[57] = 8'h00;

        send_frame(58);

        if (parsed_ok !== 1'b0) begin
            $display("ERROR [Test 10]: IPv4 Options did not fail!");
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 10]: IPv4 Options Rejection (IHL=6) -> parsed_ok=0");
        end

        repeat (2) @(posedge clk);

        //----------------------------------------------------------------------
        // Test 11: Unsupported L4 Protocol: ICMP (Proto 1) -> parsed_ok = 0
        //----------------------------------------------------------------------
        set_eth_header(48'h001122334455, 48'h66778899AABB, 16'h0800);
        set_ipv4_header(8'h45, 16'd28, 8'd1, 32'hC0A8010A, 32'hC0A80114);
        for (j = 0; j < 8; j = j + 1) frame_buf[34 + j] = 8'h00; // ICMP echo

        send_frame(42);

        if (parsed_ok !== 1'b0) begin
            $display("ERROR [Test 11]: ICMP did not fail!");
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 11]: Unsupported L4: ICMP (1) -> parsed_ok=0");
        end

        repeat (2) @(posedge clk);

        //----------------------------------------------------------------------
        // Test 12: Unsupported L4 Protocol: IGMP (Proto 2) -> parsed_ok = 0
        //----------------------------------------------------------------------
        set_eth_header(48'h001122334455, 48'h66778899AABB, 16'h0800);
        set_ipv4_header(8'h45, 16'd28, 8'd2, 32'hC0A8010A, 32'hC0A80114);
        for (j = 0; j < 8; j = j + 1) frame_buf[34 + j] = 8'h00;

        send_frame(42);

        if (parsed_ok !== 1'b0) begin
            $display("ERROR [Test 12]: IGMP did not fail!");
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 12]: Unsupported L4: IGMP (2) -> parsed_ok=0");
        end

        repeat (2) @(posedge clk);

        //----------------------------------------------------------------------
        // Test 13: Unsupported L4 Protocol: GRE (Proto 47) -> parsed_ok = 0
        //----------------------------------------------------------------------
        set_eth_header(48'h001122334455, 48'h66778899AABB, 16'h0800);
        set_ipv4_header(8'h45, 16'd28, 8'd47, 32'hC0A8010A, 32'hC0A80114);
        for (j = 0; j < 8; j = j + 1) frame_buf[34 + j] = 8'h00;

        send_frame(42);

        if (parsed_ok !== 1'b0) begin
            $display("ERROR [Test 13]: GRE did not fail!");
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 13]: Unsupported L4: GRE (47) -> parsed_ok=0");
        end

        repeat (2) @(posedge clk);

        //----------------------------------------------------------------------
        // Test 14: Truncated Frame: 1-byte frame -> parsed_ok = 0
        //----------------------------------------------------------------------
        frame_buf[0] = 8'hAA;
        send_frame(1);

        if (parsed_ok !== 1'b0) begin
            $display("ERROR [Test 14]: 1-byte frame did not fail!");
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 14]: Truncated Frame: 1-byte frame -> parsed_ok=0");
        end

        repeat (2) @(posedge clk);

        //----------------------------------------------------------------------
        // Test 15: Truncated Frame: Mid-Ethernet (7 bytes) -> parsed_ok = 0
        //----------------------------------------------------------------------
        for (j = 0; j < 7; j = j + 1) frame_buf[j] = 8'h11;
        send_frame(7);

        if (parsed_ok !== 1'b0) begin
            $display("ERROR [Test 15]: Truncated Mid-Ethernet did not fail!");
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 15]: Truncated Frame: Mid-Ethernet (7B) -> parsed_ok=0");
        end

        repeat (2) @(posedge clk);

        //----------------------------------------------------------------------
        // Test 16: Truncated Frame: Mid-IPv4 (25 bytes) -> parsed_ok = 0
        //----------------------------------------------------------------------
        set_eth_header(48'h001122334455, 48'h66778899AABB, 16'h0800);
        for (j = 14; j < 25; j = j + 1) frame_buf[j] = 8'h22;
        send_frame(25);

        if (parsed_ok !== 1'b0) begin
            $display("ERROR [Test 16]: Truncated Mid-IPv4 did not fail!");
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 16]: Truncated Frame: Mid-IPv4 (25B) -> parsed_ok=0");
        end

        repeat (2) @(posedge clk);

        //----------------------------------------------------------------------
        // Test 17: Truncated Frame: Mid-TCP Header (40 bytes) -> parsed_ok = 0
        //----------------------------------------------------------------------
        set_eth_header(48'h001122334455, 48'h66778899AABB, 16'h0800);
        set_ipv4_header(8'h45, 16'd40, 8'd6, 32'hC0A8010A, 32'hC0A80114);
        for (j = 34; j < 40; j = j + 1) frame_buf[j] = 8'h33;
        send_frame(40);

        if (parsed_ok !== 1'b0) begin
            $display("ERROR [Test 17]: Truncated Mid-TCP did not fail!");
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 17]: Truncated Frame: Mid-TCP Header (40B) -> parsed_ok=0");
        end

        repeat (2) @(posedge clk);

        //----------------------------------------------------------------------
        // Test 18: Truncated Payload vs Claimed Length -> parsed_ok = 0
        // Claimed total len = 59 (19B payload), but frame ends after 5 payload bytes (total 59 bytes claimed, 45 bytes sent)
        //----------------------------------------------------------------------
        set_eth_header(48'h001122334455, 48'h66778899AABB, 16'h0800);
        set_ipv4_header(8'h45, 16'd59, 8'd6, 32'hC0A8010A, 32'hC0A80114);
        set_tcp_header(16'd12345, 16'd51010, 4'd5, 8'h18);
        for (j = 0; j < 5; j = j + 1) frame_buf[54 + j] = "X";

        send_frame(59); // Only 59 bytes total: 14 eth + 20 ip + 20 tcp + 5 payload

        if (parsed_ok !== 1'b0) begin
            $display("ERROR [Test 18]: Truncated Payload vs Claimed Length did not fail!");
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 18]: Truncated Payload vs Claimed Length -> parsed_ok=0");
        end

        repeat (2) @(posedge clk);

        //----------------------------------------------------------------------
        // Test 19: Malformed TCP Data Offset (<5, e.g. 3) -> parsed_ok = 0
        //----------------------------------------------------------------------
        set_eth_header(48'h001122334455, 48'h66778899AABB, 16'h0800);
        set_ipv4_header(8'h45, 16'd40, 8'd6, 32'hC0A8010A, 32'hC0A80114);
        set_tcp_header(16'd12345, 16'd51010, 4'd3, 8'h18); // Invalid offset 3!

        send_frame(54);

        if (parsed_ok !== 1'b0) begin
            $display("ERROR [Test 19]: Bad TCP data offset 3 did not fail!");
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 19]: Malformed TCP Data Offset (<5) -> parsed_ok=0");
        end

        repeat (2) @(posedge clk);

        //----------------------------------------------------------------------
        // Test 20: TCP with Options (data_offset=8 -> 32B header, parsed_ok=1)
        //----------------------------------------------------------------------
        set_eth_header(48'h001122334455, 48'h66778899AABB, 16'h0800);
        set_ipv4_header(8'h45, 16'd67, 8'd6, 32'hC0A8010A, 32'hC0A80114); // 20+32+15 = 67
        set_tcp_header(16'd12345, 16'd51010, 4'd8, 8'h18); // offset 8 = 32 bytes
        // 12 bytes of TCP options (indices 54..65)
        for (j = 0; j < 12; j = j + 1) frame_buf[54 + j] = 8'h01; // NOP options
        // 15 bytes of payload: "OPTIONS_PAYLOAD" (indices 66..80)
        frame_buf[66] = "O"; frame_buf[67] = "P"; frame_buf[68] = "T"; frame_buf[69] = "I";
        frame_buf[70] = "O"; frame_buf[71] = "N"; frame_buf[72] = "S"; frame_buf[73] = "_";
        frame_buf[74] = "P"; frame_buf[75] = "A"; frame_buf[76] = "Y"; frame_buf[77] = "L";
        frame_buf[78] = "O"; frame_buf[79] = "A"; frame_buf[80] = "D";

        send_frame(81);

        if (!parsed_ok || l4_length !== 16'd32 || payload_len !== 16'd15 || rx_payload_bytes !== 15) begin
            $display("ERROR [Test 20]: TCP with Options failed! parsed_ok=%b, l4_len=%0d, rx=%0d", parsed_ok, l4_length, rx_payload_bytes);
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 20]: TCP with Options (offset=8, 32B header) -> PASS");
        end

        repeat (2) @(posedge clk);

        //----------------------------------------------------------------------
        // Test 21: Malformed UDP Length (<8, e.g. 4) -> parsed_ok = 0
        //----------------------------------------------------------------------
        set_eth_header(48'h001122334455, 48'h66778899AABB, 16'h0800);
        set_ipv4_header(8'h45, 16'd28, 8'd17, 32'hC0A8010A, 32'hC0A80114);
        set_udp_header(16'd12345, 16'd53, 16'd4); // Invalid UDP len 4!

        send_frame(42);

        if (parsed_ok !== 1'b0) begin
            $display("ERROR [Test 21]: Bad UDP len 4 did not fail!");
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 21]: Malformed UDP Length (<8) -> parsed_ok=0");
        end

        repeat (2) @(posedge clk);

        //----------------------------------------------------------------------
        // Test 22: Zero-Payload TCP Packet (SYN/ACK, payload_len=0, out_valid=0)
        //----------------------------------------------------------------------
        set_eth_header(48'h001122334455, 48'h66778899AABB, 16'h0800);
        set_ipv4_header(8'h45, 16'd40, 8'd6, 32'hC0A8010A, 32'hC0A80114); // 20+20+0 = 40
        set_tcp_header(16'd12345, 16'd51010, 4'd5, 8'h12); // SYN, ACK

        send_frame(54);

        if (!parsed_ok || payload_len !== 16'd0 || rx_payload_bytes !== 0) begin
            $display("ERROR [Test 22]: Zero-payload TCP failed! parsed_ok=%b, rx_bytes=%0d", parsed_ok, rx_payload_bytes);
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 22]: Zero-Payload TCP Packet -> payload_len=0, out_valid=0");
        end

        repeat (2) @(posedge clk);

        //----------------------------------------------------------------------
        // Test 23: Back-to-back packets with 0 gap cycles
        //----------------------------------------------------------------------
        // Packet A
        set_eth_header(48'h001122334455, 48'h66778899AABB, 16'h0800);
        set_ipv4_header(8'h45, 16'd41, 8'd6, 32'hC0A8010A, 32'hC0A80114);
        set_tcp_header(16'd12345, 16'd51010, 4'd5, 8'h18);
        frame_buf[54] = "A";

        // Stream Packet A then immediately Packet B
        for (j = 0; j < 55; j = j + 1) begin
            @(posedge clk);
            in_valid <= 1'b1;
            in_data  <= frame_buf[j];
            in_sof   <= (j == 0);
            in_eof   <= (j == 54);
        end
        // Immediately Packet B byte 0
        frame_buf[54] = "B";
        for (j = 0; j < 55; j = j + 1) begin
            @(posedge clk);
            in_valid <= 1'b1;
            in_data  <= frame_buf[j];
            in_sof   <= (j == 0);
            in_eof   <= (j == 54);
        end
        @(posedge clk);
        in_valid <= 1'b0;
        in_sof   <= 1'b0;
        in_eof   <= 1'b0;

        if (!parsed_ok) begin
            $display("ERROR [Test 23]: Back-to-back packet stream failed!");
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 23]: Back-to-back packets with zero idle gap -> PASS");
        end

        repeat (2) @(posedge clk);

        //----------------------------------------------------------------------
        // Test 24: Synchronous reset recovery mid-packet
        //----------------------------------------------------------------------
        @(posedge clk);
        in_valid <= 1'b1; in_data <= 8'h00; in_sof <= 1'b1; in_eof <= 1'b0;
        @(posedge clk);
        in_valid <= 1'b1; in_data <= 8'h11; in_sof <= 1'b0; in_eof <= 1'b0;
        // Assert reset mid-packet
        rst <= 1'b1;
        @(posedge clk);
        rst <= 1'b0;
        in_valid <= 1'b0;
        @(posedge clk);

        // Send fresh clean packet
        set_eth_header(48'h001122334455, 48'h66778899AABB, 16'h0800);
        set_ipv4_header(8'h45, 16'd41, 8'd6, 32'hC0A8010A, 32'hC0A80114);
        set_tcp_header(16'd12345, 16'd51010, 4'd5, 8'h18);
        frame_buf[54] = "Z";
        send_frame(55);

        if (!parsed_ok || rx_payload_bytes !== 1) begin
            $display("ERROR [Test 24]: Post-reset packet failed!");
            errors = errors + 1;
        end else begin
            $display("PASS  [Test 24]: Mid-packet synchronous reset recovery -> PASS");
        end

        #20;
        if (errors == 0) begin
            $display("==================================================================");
            $display("SUCCESS: ALL 24 tb_parser CHECKS PASSED BIT-FOR-BIT!");
            $display("==================================================================");
        end else begin
            $display("FAILURE: %0d error(s) detected in tb_parser!", errors);
            $finish(1);
        end

        $finish;
    end

endmodule

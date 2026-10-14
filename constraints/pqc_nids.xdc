#==============================================================================
# constraints/pqc_nids.xdc
#
# ZedBoard (XC7Z020-CLG484-1) pin and timing constraints for rtl/top/pqc_nids_top.v
#
# *** VERIFY EVERY PACKAGE_PIN AND IOSTANDARD BELOW AGAINST THE DIGILENT
# *** ZEDBOARD MASTER XDC FOR YOUR BOARD REVISION BEFORE THE FIRST BUILD.
# These values are from the standard ZedBoard master constraints, but board
# revisions differ and a wrong IOSTANDARD is a DRC failure that costs a build
# cycle to find. The Pmod assignment in particular depends on which Pmod header
# the USB-UART is physically plugged into; this file assumes JA.
#==============================================================================

#------------------------------------------------------------------- clock
# 100 MHz oscillator on GCLK. This is the only clock in the design: every
# module is single-clock, synchronous, active-high reset (AGENTS.md).
set_property -dict {PACKAGE_PIN Y9 IOSTANDARD LVCMOS33} [get_ports clk]
create_clock -period 10.000 -name sys_clk -waveform {0.000 5.000} [get_ports clk]

#------------------------------------------------------------------- reset
# BTNC. Synchronised by a 4-stage shift register inside pqc_nids_top, so the
# pin itself is asynchronous by design.
set_property -dict {PACKAGE_PIN P16 IOSTANDARD LVCMOS18} [get_ports btn_rst]
set_false_path -from [get_ports btn_rst]

#--------------------------------------------------------- Pmod USB-UART (JA)
# Pmod USB-UART (FTDI FT232RQ), NOT the ZedBoard onboard USB-UART, which is
# wired to the PS and unreachable from programmable logic (contract section 1).
#
# Digilent Pmod USB-UART pinout:  1 = CTS, 2 = TXD, 3 = RXD, 4 = RTS
#   the module's TXD is data leaving the host, so it is the FPGA's INPUT
#   the module's RXD is data entering the host, so it is the FPGA's OUTPUT
# JA1 = Y11, JA2 = AA11, JA3 = Y10, JA4 = AA9
set_property -dict {PACKAGE_PIN AA11 IOSTANDARD LVCMOS33} [get_ports uart_rx_pin]
set_property -dict {PACKAGE_PIN Y10  IOSTANDARD LVCMOS33} [get_ports uart_tx_pin]

# 3 Mbaud is 33.3 clock cycles per bit and uart_rx oversamples with a two-stage
# synchroniser, so there is no setup/hold relationship to constrain on either
# pin. Declaring them false paths keeps the timing report free of meaningless
# unconstrained-port warnings rather than hiding a real violation.
set_false_path -from [get_ports uart_rx_pin]
set_false_path -to   [get_ports uart_tx_pin]

#-------------------------------------------------------------------- LEDs
# LD0..LD7. Mapping is in rtl/io/led_driver.v and must stay in lockstep with
# demo/display/led_map.py.
set_property -dict {PACKAGE_PIN T22 IOSTANDARD LVCMOS33} [get_ports {led[0]}]
set_property -dict {PACKAGE_PIN T21 IOSTANDARD LVCMOS33} [get_ports {led[1]}]
set_property -dict {PACKAGE_PIN U22 IOSTANDARD LVCMOS33} [get_ports {led[2]}]
set_property -dict {PACKAGE_PIN U21 IOSTANDARD LVCMOS33} [get_ports {led[3]}]
set_property -dict {PACKAGE_PIN V22 IOSTANDARD LVCMOS33} [get_ports {led[4]}]
set_property -dict {PACKAGE_PIN W22 IOSTANDARD LVCMOS33} [get_ports {led[5]}]
set_property -dict {PACKAGE_PIN U19 IOSTANDARD LVCMOS33} [get_ports {led[6]}]
set_property -dict {PACKAGE_PIN U14 IOSTANDARD LVCMOS33} [get_ports {led[7]}]

set_false_path -to [get_ports {led[*]}]

#-------------------------------------------------------- synthesis guidance
# poly1305.v contains two 131x64 multiplies. Vivado will infer DSP48E1 for them
# by default; the module header used to claim no DSPs, which was wrong. They are
# the design's likely critical path (see docs/INTEGRATION-READINESS-REVIEW.md
# section 3.6), so let the timing report decide rather than pre-constraining it.
#
# count_min_sketch.v forces ram_style = "block" on its eight arrays, so no
# constraint is needed to keep them out of LUTRAM. aead_framer.v's 512-byte
# ciphertext FIFO is read combinationally and is therefore meant to be
# distributed RAM.

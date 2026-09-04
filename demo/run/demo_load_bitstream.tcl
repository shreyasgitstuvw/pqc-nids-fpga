# demo/run/demo_load_bitstream.tcl
# One-command Vivado JTAG burn:  vivado -mode batch -source demo/run/demo_load_bitstream.tcl
#
# STUB -- Phase VII/VIII. build/pqc_nids.bit does not exist yet.

set bitfile "build/pqc_nids.bit"

if {![file exists $bitfile]} {
    puts "ERROR: $bitfile not found — run scripts/build_bitstream.tcl first."
    exit 1
}

open_hw_manager
connect_hw_server
open_hw_target
current_hw_device [lindex [get_hw_devices xc7z020_1] 0]
set_property PROGRAM.FILE $bitfile [current_hw_device]
program_hw_devices [current_hw_device]
puts "Loaded $bitfile onto XC7Z020."
close_hw_manager

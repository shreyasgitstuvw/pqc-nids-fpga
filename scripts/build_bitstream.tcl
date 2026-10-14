#==============================================================================
# scripts/build_bitstream.tcl
#
# Non-project-mode synthesis, implementation and bitstream for pqc_nids_top.
#
#   vivado -mode batch -source scripts/build_bitstream.tcl
#
# Writes:
#   build/pqc_nids.bit                  the bitstream demo/run/demo_load_bitstream.tcl loads
#   build/reports/utilization.rpt       LUT / FF / BRAM / DSP, the real numbers
#   build/reports/timing_summary.rpt    whether 100 MHz actually closes
#   build/reports/timing_worst_paths.rpt  the 20 worst setup paths, by slack
#   build/reports/drc.rpt
#
# EVERY resource and timing figure in this repository is an estimate until this
# script has run. The reports above are the only real numbers; the module
# headers and docs/Member C/Member-C-KEM-Cycle-Counts.md say so explicitly.
#
# Exit status is non-zero if timing does not meet, so CI or a shell loop can
# tell a closed build from one that merely produced a file.
#==============================================================================

set PART   xc7z020clg484-1
set TOP    pqc_nids_top
set ROOT   [file normalize [file dirname [info script]]/..]
set OUT    $ROOT/build
set REPORTS $OUT/reports

file mkdir $OUT
file mkdir $REPORTS

puts "=== pqc-nids-fpga: synthesising $TOP for $PART ==="

# ---------------------------------------------------------------- sources
# Order does not matter for Verilog-2001 module resolution, but the include
# directories do: reason_codes.vh, ntt_zetas.vh and keccak_rc.vh are included
# by path-less `include directives.
set rtl_dirs {
    rtl/ingress
    rtl/control
    rtl/detect
    rtl/io
    rtl/crypto/chacha_poly
    rtl/crypto/kem
    rtl/crypto/ntt
    rtl/crypto/sha3
    rtl/top
}

set srcs {}
foreach d $rtl_dirs {
    foreach f [lsort [glob -nocomplain $ROOT/$d/*.v]] {
        lappend srcs $f
    }
}
if {[llength $srcs] == 0} {
    puts "ERROR: no Verilog sources found under $ROOT/rtl"
    exit 1
}
puts "=== [llength $srcs] source files ==="
read_verilog $srcs

read_xdc $ROOT/constraints/pqc_nids.xdc

# ---------------------------------------------------------------- synthesis
synth_design -top $TOP -part $PART -include_dirs [lmap d $rtl_dirs {file join $ROOT $d}]
write_checkpoint -force $OUT/post_synth.dcp
report_utilization -file $REPORTS/utilization_post_synth.rpt

# ------------------------------------------------------------ implementation
opt_design
place_design
phys_opt_design
route_design

write_checkpoint -force $OUT/post_route.dcp

# ------------------------------------------------------------------ reports
report_utilization        -file $REPORTS/utilization.rpt
report_utilization        -hierarchical -file $REPORTS/utilization_hier.rpt
report_timing_summary     -file $REPORTS/timing_summary.rpt
report_timing -setup -max_paths 20 -sort_by slack -file $REPORTS/timing_worst_paths.rpt
report_drc                -file $REPORTS/drc.rpt
report_clock_utilization  -file $REPORTS/clock_utilization.rpt

# ---------------------------------------------------------------- bitstream
write_bitstream -force $OUT/pqc_nids.bit

# ------------------------------------------------------- did timing close?
set wns [get_property SLACK [get_timing_paths -delay_type max]]
set whs [get_property SLACK [get_timing_paths -delay_type min]]
puts "=== WNS (setup) = $wns ns   WHS (hold) = $whs ns ==="

set failed 0
if {$wns < 0} { puts "TIMING NOT MET: setup slack $wns ns"; set failed 1 }
if {$whs < 0} { puts "TIMING NOT MET: hold slack $whs ns";  set failed 1 }

if {$failed} {
    puts "=== BUILD PRODUCED A BITSTREAM BUT TIMING DID NOT CLOSE ==="
    puts "=== See $REPORTS/timing_worst_paths.rpt for the failing paths ==="
    exit 2
}

puts "=== BUILD OK: $OUT/pqc_nids.bit, timing met ==="
exit 0

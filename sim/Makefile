#==============================================================================
# sim/Makefile
# Cocotb simulation harness for pqc-nids-fpga
#
# Usage:
#   make -C sim                       # runs default testbench
#   make -C sim MODULE=test_crc32     # runs crc32 testbench
#   make -C sim MODULE=test_parser    # runs parser testbench
#==============================================================================

SIM ?= icarus
TOPLEVEL_LANG ?= verilog

# Testbench module name (defaults to test_crc32)
MODULE ?= test_crc32

# Map module to RTL toplevel and source files
ifeq ($(MODULE),test_crc32)
  VERILOG_SOURCES = $(CURDIR)/../rtl/ingress/crc32.v
  TOPLEVEL = crc32
endif

ifeq ($(MODULE),test_deframer)
  VERILOG_SOURCES = $(CURDIR)/../rtl/ingress/crc32.v $(CURDIR)/../rtl/ingress/deframer.v
  TOPLEVEL = deframer
  COMPILE_ARGS += -I$(CURDIR)/../rtl/control
endif

ifeq ($(MODULE),test_parser)
  VERILOG_SOURCES = $(CURDIR)/../rtl/ingress/parser.v
  TOPLEVEL = parser
  COMPILE_ARGS += -I$(CURDIR)/../rtl/control
endif

# Tell cocotb where to find testbench Python files
PYTHONPATH := $(CURDIR)/cocotb:$(CURDIR)/..:$(PYTHONPATH)
export PYTHONPATH

# Include cocotb's standard Makefile rules if available
-include $(shell cocotb-config --makefiles 2>/dev/null)/Makefile.sim

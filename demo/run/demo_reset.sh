#!/usr/bin/env bash
# demo/run/demo_reset.sh
# Kills the demo scripts, soft-resets FPGA session state, clears the OLED and
# reruns from a clean slate.
#
# This exists because a demo that takes ten minutes to recover from a stumble
# loses the marks the project earned in Phases I-VIII. Recovery must be one
# command.
#
# STUB -- Phase IX.
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "Phase IX stub."
echo "Intended: pkill send.py/recv.py/attacker.py -> assert soft-reset over"
echo "PORT_FPGA_DEBUG -> clear OLED -> ./demo/run/demo_start.sh"
exit 1

#!/usr/bin/env bash
# demo/run/demo_start.sh
# Opens the three demo terminals and starts sender + receiver.
# The attacker terminal is started MANUALLY, mid-demo, so the narrative has a
# clear before/after.
#
# STUB -- Phase IX. test-network/ does not exist yet.
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "Phase IX stub — test-network/send.py and recv.py do not exist yet."
echo
echo "Intended sequence:"
echo "  1. python demo/verify/pre_demo_checklist.py     # must exit 0"
echo "  2. terminal A: python test-network/send.py      # Device A"
echo "  3. terminal B: python test-network/recv.py      # Device B"
echo "  4. terminal C (manual, mid-demo):"
echo "     python test-network/attacker.py --sequence demo/config/attack_sequence.json"
exit 1

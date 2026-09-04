"""
demo/verify/smoke_test.py
Sends 10 clean packets + 5 known-attack packets, asserts every clean packet
reaches recv.py and every attack is dropped with the expected reason code.

    exit 0 = ready to demo
    exit 1 = something is broken

STUB -- Phase VIII. Blocked on test-network/send.py, recv.py and attacker.py,
which do not exist yet. The structure is here so Phase VIII fills in bodies
rather than starting from a blank file.
"""

import sys

CLEAN_PACKETS = 10
ATTACK_PACKETS = [
    ("port_scan", "SCAN"),
    ("syn_flood", "FLOOD"),
    ("known_signature", "SIGNATURE"),
    ("tampered_payload", "BAD_TAG"),
    ("malformed_key", "HANDSHAKE_KEY_INVALID"),
]


def send_clean(n):
    raise NotImplementedError("Phase VIII: drive test-network/send.py")


def send_attack(kind):
    raise NotImplementedError("Phase VIII: drive test-network/attacker.py")


def read_counters():
    raise NotImplementedError("Phase VIII: read drop_engine counters over PORT_FPGA_DEBUG")


def main():
    print("smoke_test.py is a Phase VIII stub — test-network/ does not exist yet.")
    return 1


if __name__ == "__main__":
    sys.exit(main())

"""
demo/capture/timing_capture.py
Reads hardware timestamps from the FPGA debug counters over UART and formats
them into the six-row §6.3 timing table the report needs.

STUB -- Phase VIII. The measurement targets are fixed now so the RTL debug
counter interface can be designed against them.

Model-derived expectations, from `python model/mlkem/opcount.py` at 100 MHz.
Real hardware will be higher -- these exclude control FSM and memory overhead.
"""

MEASUREMENTS = [
    ("keygen",          "ML-KEM-512 key generation",        4_800,  "48 us"),
    ("encaps",          "Encapsulation",                    6_000,  "60 us"),
    ("decaps",          "Decapsulation incl. FO transform", 8_900,  "89 us"),
    ("handshake_total", "Full handshake, wire to session",   None,  "UART-bound, ~2.6 ms"),
    ("per_packet",      "ChaCha20-Poly1305 per data packet", None,  "Member D"),
    ("drop_latency",    "Parse to drop decision",            None,  "target < 1 us"),
]


def expected_table():
    rows = ["| Measurement | Model cycles | Model @100 MHz | Hardware |",
            "|---|---:|---:|---:|"]
    for _, label, cycles, est in MEASUREMENTS:
        rows.append(f"| {label} | {cycles or '—'} | {est} | _pending_ |")
    return "\n".join(rows)


def read_hardware_counters(port):
    raise NotImplementedError("Phase VIII: read debug counters over PORT_FPGA_DEBUG")


if __name__ == "__main__":
    print(expected_table())

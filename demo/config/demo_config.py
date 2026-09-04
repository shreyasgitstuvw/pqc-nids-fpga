"""
demo/config/demo_config.py
Single source of truth for the live demo. Every script under demo/ and
test-network/ imports from here -- edit once, everything picks it up.

Phase IX depends on nothing in this file being guessed on the day.
"""

# ---------------------------------------------------------------- serial
# Pmod USB-UART (FTDI FT232RQ) -- NOT the ZedBoard onboard USB-UART, which is
# wired to the PS and unreachable from programmable logic (synopsis §7.1).
BAUD_RATE = 3_000_000
DATA_BITS, PARITY, STOP_BITS = 8, "N", 1

# Per-machine. Windows: "COM3". Linux: "/dev/ttyUSB0".
PORT_DEVICE_A = "COM3"      # sender
PORT_DEVICE_B = "COM4"      # receiver
PORT_ATTACKER = "COM5"
PORT_FPGA_DEBUG = "COM6"    # drop-engine counter readout

SERIAL_TIMEOUT_S = 2.0

# ------------------------------------------------------------ UDP ports
# PROPOSED in docs/Member C/Member-C-Contract-Freeze-Package.md §2; not frozen
# until Member A writes them into interface_contract.md §4 and Member D
# confirms no collision with test traffic. Private/dynamic range.
PORT_HS_INIT = 51001        # encapsulation key ek, 800 B, initiator -> responder
PORT_HS_RESP = 51002        # ciphertext c, 768 B, responder -> initiator
PORT_DATA    = 51010        # ChaCha20-Poly1305 session data

# --------------------------------------------------------- ML-KEM sizes
# ML-KEM-512, FIPS 203 Table 2: k=2, eta1=3, eta2=2, du=10, dv=4
EK_BYTES, DK_BYTES, CT_BYTES, SS_BYTES = 800, 1632, 768, 32

# ------------------------------------------------------------ demo shape
PACKET_COUNT = 50           # clean packets before attacks start
PACKET_INTERVAL_S = 0.1
DISPLAY_REFRESH_S = 0.25
LOG_DIR = "demo/logs"

"""
demo/display/led_map.py
Reason code -> LED index and blink pattern for the ZedBoard's LD0-LD7.

MUST stay in lockstep with rtl/io/led_driver.v and rtl/control/reason_codes.vh.
If the RTL display format changes, both sides update in the SAME commit -- they
cannot drift independently (execution plan §8).
"""

# Mirrors rtl/control/reason_codes.vh. Keep the numeric values identical.
REASON_CODES = {
    "NONE":                  0x0,
    "CRC_FAIL":              0x1,
    "FRAME_TIMEOUT":         0x2,
    "MALFORMED":             0x3,
    "SIGNATURE":             0x4,
    "FLOOD":                 0x5,
    "SCAN":                  0x6,
    "BAD_TAG":               0x7,
    "HANDSHAKE_KEY_INVALID": 0x8,
}

# LD0 is session state, LD1-LD7 are the seven droppable reason classes.
LED_MAP = {
    "SESSION_ESTABLISHED":   0,   # solid = session up
    "CRC_FAIL":              1,
    "FRAME_TIMEOUT":         2,
    "MALFORMED":             3,
    "SIGNATURE":             4,
    "FLOOD":                 5,
    "SCAN":                  6,
    "BAD_TAG":               7,
}

# HANDSHAKE_KEY_INVALID has no LED of its own -- LD0 (session) blinks fast
# instead, since a rejected key means no session rather than a dropped packet.
BLINK = {
    "solid":  None,
    "slow":   500,   # ms period
    "fast":   120,
}

PATTERNS = {
    "SESSION_ESTABLISHED":   "solid",
    "HANDSHAKE_KEY_INVALID": "fast",   # on LD0
    "SIGNATURE":             "fast",
    "BAD_TAG":               "fast",
    "FLOOD":                 "slow",
    "SCAN":                  "slow",
    "CRC_FAIL":              "slow",
    "FRAME_TIMEOUT":         "slow",
    "MALFORMED":             "slow",
}


def led_for(reason: str):
    """(led_index, blink_pattern) for a reason code name, or None if unmapped."""
    if reason == "HANDSHAKE_KEY_INVALID":
        return LED_MAP["SESSION_ESTABLISHED"], PATTERNS[reason]
    if reason in LED_MAP:
        return LED_MAP[reason], PATTERNS.get(reason, "slow")
    return None

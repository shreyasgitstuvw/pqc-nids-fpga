"""
demo/display/oled_layout.py
What the 128x32 OLED shows, and when it refreshes.

MUST match rtl/io/oled_driver.v exactly -- same commit for any change.

128x32 at 6x8 glyphs = 21 columns x 4 rows.

    +---------------------+
    | SESSION: ESTABLISHED |   row 0  session state
    | RX 1482   DROP 37    |   row 1  counters
    | LAST: SCAN           |   row 2  most recent reason code
    | SRC 192.168.1.104    |   row 3  source of that packet
    +---------------------+

Phase IX fills in the actual driver calls. The layout is fixed now so the RTL
side can be written against it.
"""

COLS, ROWS = 21, 4
GLYPH_W, GLYPH_H = 6, 8
WIDTH_PX, HEIGHT_PX = 128, 32

ROW_SESSION, ROW_COUNTERS, ROW_REASON, ROW_SOURCE = 0, 1, 2, 3

SESSION_LABELS = {
    0b00: "IDLE",
    0b01: "HANDSHAKING",
    0b10: "ESTABLISHED",
    0b11: "REJECTED",
}


def render(session_state: int, rx: int, drops: int, last_reason: str, last_src: str):
    """Return exactly ROWS strings of at most COLS chars each."""
    return [
        f"SESSION: {SESSION_LABELS.get(session_state, '?')}"[:COLS],
        f"RX {rx:<7} DROP {drops}"[:COLS],
        f"LAST: {last_reason or '-'}"[:COLS],
        f"SRC {last_src or '-'}"[:COLS],
    ]


if __name__ == "__main__":
    for line in render(0b10, 1482, 37, "SCAN", "192.168.1.104"):
        print(f"|{line:<{COLS}}|")

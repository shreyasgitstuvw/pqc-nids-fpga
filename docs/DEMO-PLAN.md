# Demo plan - code that must exist before synthesis

Decisions taken 11 Oct 2026: **D1** second UART + RTL arbiter, **D4** keep the OLED and build its RTL,
**D2** keep separate host scripts. The three together force a third link (below), so the topology is
settled here rather than discovered on the bench.

## Why three UARTs, not two

A COM port can be opened by one OS process. Separate scripts (D2) therefore need one FTDI each:

| Link | Host process | Board pins |
|---|---|---|
| **A** | `send.py` (handshake + clean traffic; reads the 816 B ciphertext reply) | `uart_rx0` in, `uart_tx0` out |
| **B** | `attacker.py` (write only) | `uart_rx1` in |
| **C** | `recv.py` (telemetry viewer, read only) | `uart_tx1` out |

This also *removes* the shared-TX arbitration between `handshake_tx` and `telemetry_tx` (telemetry gets
its own transmitter). Net hardware: three Pmod USB-UART (or any 3.3 V FTDI) devices on JA/JB/JC.

## New / changed RTL (all of it must be verified before synthesis)

| # | Item | Notes |
|---|---|---|
| `W1` | `rtl/ingress/rx_arbiter.v` - two `uart_rx` -> one byte stream | **Store-and-forward per port**, not a lock. Frame = `[2 B length]...`; buffer a whole frame per port (<=1024 B, one BRAM each), then drain one frame at a time. A lock would drop the second source's bytes whenever both talk at once, which the flood attack guarantees. Incomplete frames are flushed on a timeout so the deframer's own `RC_FRAME_TIMEOUT` still fires. Per-port overflow flag |
| `W2` | `pqc_nids_top.v`: second `uart_rx`, second `uart_tx` (telemetry), drop the TX priority mux | `handshake_tx` keeps `uart_tx0` exclusively |
| `W3` | `rtl/io/oled_driver.v` - SSD1306 128x32 over SPI | Init-sequence ROM, 6x8 font ROM, 21x4 text, refresh at `DISPLAY_REFRESH_S`. Needs new inputs: `last_reason` (from `drop_engine`), `last_src` (latched `ip_src` from the parser), `session_state` 2 b |
| `W4` | `constraints/pqc_nids.xdc`: JB/JC pins + the on-board OLED pins | **Unverified until checked against the ZedBoard master XDC (task S1)** |
| `W5` | Contract + `wire.py`: telemetry now on its own link; document both RX ports | No frame-format change |

## Tests (same discipline as the seam tests: real modules, no model of either)

- `test_rx_arbiter.py`: both ports send full frames simultaneously and at every relative offset; both
  frames must come out intact and in order; a half frame on one port must not corrupt the other.
- `test_seam_arbiter_deframer.py`: arbiter + real `uart_rx` x2 + real `deframer`; a flood on B during a
  stream on A loses no valid frame (extends `test_pqc_nids_top`).
- `test_oled_driver.py`: decode the SPI stream into a 128x32 bitmap and compare it against
  `demo/display/oled_layout.render()` rendered with the same font - a cross-language check, so the RTL
  and the Python layout cannot drift apart. Also asserts the init sequence bytes.
- Update `test_pqc_nids_top.py` for the new pins; everything stays under the preflight gate.

## Host side

- `demo_config.py`: replace the four ports with `PORT_SENDER` (A), `PORT_ATTACKER` (B), `PORT_TELEMETRY` (C).
- `send.py` unchanged apart from the port name; `attacker.py` -> port B; `recv.py` -> port C and no
  longer needs to demultiplex the ciphertext reply.
- `pre_demo_checklist.py`: check all three ports open and telemetry frames arriving.
- Delete the "device B receiver" assumption: the RTL has **no data output for forwarded packets** (the
  forward counter and LD0 are the evidence). Confirm this is acceptable for the demo (decision `D7`).

## Script

The full screenplay is `docs/DEMO-SCRIPT.md`. It adds a host-side `demo/dashboard.py` (big-screen telemetry view), a source-IP change in `attacker.py`, and a `--rehearse` gate to the build list.

## Still to decide (needs your input)

- `D5` demo sequence, dwell per attack so the audience sees the LED/OLED change, narration per step.
- `D6` rehearsal count and the one recoverable failure to show on purpose.
- `D7` no forwarded-packet output - fine for the demo, or do you want a visible forward path?
- Hardware: do you have three USB-UART devices and is the on-board OLED populated on your ZedBoard?

## Order of work

1. Merge the integration PR (done by you).  2. `W1`+tests.  3. `W2`.  4. `W3`+test.  5. `W4`, `W5`, host
scripts.  6. Full suite + Verilator `-Wall` + preflight.  7. Only then: synthesis (S1-S5), board (H1-H5).

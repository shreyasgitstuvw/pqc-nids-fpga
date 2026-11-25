# Demo delivery port: what Member D does (about half a day plus build time)

Files here go into the repo under `demo_forward/` (copy this whole folder to the repo root).

1. Run the unit test (needs cocotb + iverilog, as for the other tests):
   `python demo_forward/test_msg_fwd.py`  -> expect `TESTS=4 PASS=4 FAIL=0`.
2. Apply `top_hookup.md` to `rtl/top/pqc_nids_top.v` and the XDC (verify pin V5 = JD2_P first).
3. Run `sim/cocotb/test_pqc_nids_top.py` plus one new check: feed a clean DATA packet and
   confirm its plaintext appears on `deliver_tx_pin`; feed a signature packet and a bad-tag
   packet and confirm nothing appears.
4. Rebuild in Vivado, confirm timing still closes (WNS >= 0), program the board.
5. Hardware check: Modules: A on JA, C on JB, telemetry on JC, B on JD. On B run
   `python demo_forward/inbox.py --port COMx`; on A run `python demo_forward/chat.py --port COMy`.
   Messages typed on A must appear on B; `/tamper` messages must not (BAD_TAG counter rises).
Send back: test output, timing summary, a photo/screen of A and B windows.

6. Attacker rehearsal (Device C): `python demo_forward/attacker_console.py --port COMz`.
   Try `join-bad`, `join`, `say hi`, `tamper x`, `wrongkey x`, `inject 1`, `scan`, `flood`, then `auto`.
   Record which LED lights for each, and whether `scan` and `flood` trip LD6/LD5 with the pacing in the
   script (the jitter and ramp are guesses; tune the burst size and gaps in scan() until it trips reliably).
   `nosession` is dropped by the board with no LED today (aead_framer's no_session_drop is not wired to the
   drop engine); either skip it on stage or add that wiring later.

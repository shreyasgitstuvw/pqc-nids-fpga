# Demo Runbook

Judge-facing operating instructions. Written so **any** team member can run the
demo alone — if only one person can drive it, the demo is a single point of
failure.

**Status: skeleton.** `demo/config/`, `demo/display/` and
`demo/verify/pre_demo_checklist.py` work today. Everything that touches
hardware or `test-network/` is a stub until Phases VIII–IX.

---

## Before the judge arrives

```bash
python demo/verify/pre_demo_checklist.py     # must exit 0
```

Six software checks pass today. The three hardware checks stay SKIP until you
set `DEMO_HARDWARE=1` with the board on the bench.

Then, once Phase VIII lands:

```bash
DEMO_HARDWARE=1 python demo/verify/pre_demo_checklist.py
python demo/verify/smoke_test.py             # 10 clean + 5 attacks, exit 0
```

If either exits non-zero, **fix it before the judge arrives** — do not plan to
explain it away live.

---

## Power and load sequence

1. ZedBoard on, Pmod USB-UART connected — **not** the onboard USB-UART. That
   one is wired to the processor and unreachable from programmable logic
   (synopsis §7.1). Wrong port means no traffic and a confusing five minutes.
2. Load the bitstream:
   ```bash
   vivado -mode batch -source demo/run/demo_load_bitstream.tcl
   ```
3. Confirm COM port assignments match `demo/config/demo_config.py`.

---

## Terminals

`./demo/run/demo_start.sh` opens the first two. The attacker terminal is
started **by hand, mid-demo**, so there is a clean before/after.

| Terminal | Command | Shows |
|---|---|---|
| A — sender | `python test-network/send.py` | `[KEM]` handshake, `[TX]` packets |
| B — receiver | `python test-network/recv.py` | `[RX]` delivered, `[DROP]` with reason |
| C — attacker | `python test-network/attacker.py --sequence demo/config/attack_sequence.json` | replayed attacks |

---

## What each output line means

| Line | Meaning |
|---|---|
| `[KEM] handshake complete` | ML-KEM-512 finished; session key installed |
| `[SEC] session established` | `session_mgr.v` moved to ESTABLISHED |
| `[TX] seq=N` | encrypted packet sent |
| `[RX] seq=N ok` | received, Poly1305 verified |
| `[DROP] reason=SIGNATURE` | CAM matched a known attack signature |
| `[DROP] reason=FLOOD` / `SCAN` | Count-Min Sketch volumetric anomaly |
| `[DROP] reason=BAD_TAG` | Poly1305 failed — payload altered |
| `[DROP] reason=HANDSHAKE_KEY_INVALID` | structurally invalid key material |
| `[ALERT]` | drop-engine counter crossed a threshold |

**On the board:** LD0 is session state, LD1–LD7 are reason classes
(`demo/display/led_map.py`). The OLED shows session state, RX/DROP counts, last
reason code and last source IP (`demo/display/oled_layout.py`).

---

## The narrative

Attack order is in `demo/config/attack_sequence.json`, with a `say` field per
step — the line to deliver while that attack replays.

The sequence builds deliberately: scan → flood → signature → tampered payload →
malformed key → **tampered ciphertext**.

**Step 6 is the one to slow down for, and it is the only step where "nothing
happens" is the correct outcome.** A tampered handshake ciphertext produces no
verdict at all. The session establishes normally, on the same cycle, with the
same signal shape as a genuine handshake. The failure surfaces one packet later
as `BAD_TAG`.

That silence is not a gap in the design — it *is* the design. FIPS 203 requires
decapsulation to return a deterministic decoy key rather than an error, so an
attacker cannot learn whether their ciphertext was valid. A visible
"handshake rejected" would hand back exactly the bit the Fujisaki-Okamoto
transform exists to deny.

Expect to be asked why nothing lit up. That question is the demo working.

---

## If something breaks

```bash
./demo/run/demo_reset.sh     # kill scripts, soft-reset session state, clear OLED, restart
```

One command, by design. Practise it once before the day.

---

## Evidence capture

```bash
python test-network/send.py | python demo/capture/session_log.py
python demo/capture/timing_capture.py      # §6.3 timing table
```

`demo/logs/demo_session_<timestamp>.log` is the evidence behind the report's
measured figures. Run the capture on the real demo, not a rehearsal.

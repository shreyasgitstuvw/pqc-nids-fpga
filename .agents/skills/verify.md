# Skill: verify — run the gate, report the truth

Use before every PR, and whenever an agent claims something works.

This skill does not fix anything. It establishes what is actually true right
now. Fixing is a separate step, taken after you know.

## Procedure

Run every command. Capture real output. Do not summarise a failure as a
partial success.

```bash
# 1 — Python model (the oracle everything else is checked against)
python model/sha3.py                  # FIPS 202 vs pycryptodome
python model/mlkem/ntt.py             # forward∘inverse identity, 100 polys
python model/mlkem/cbd.py             # binomial distribution
python model/mlkem/pke.py             # K-PKE round trip
python model/mlkem/kem.py             # ML-KEM round trip + implicit rejection
python model/pipeline.py              # packet bus stub

# 2 — HARD GATE. Must print 80/80, failed 0, skipped 0.
python model/mlkem/kat_test.py

# 3 — RTL lint. Warnings are errors.
verilator --lint-only -Wall -Irtl/control rtl/**/*.v

# 4 — Testbenches, once any exist
make -C sim
```

## Report format

One line per check, then a verdict.

```
PASS  model/sha3.py              All self-checks passed against pycryptodome
PASS  model/mlkem/kat_test.py    passed 80  failed 0  skipped 0
FAIL  rtl/crypto/ntt/ntt_core.v  %Warning-WIDTH: ntt_core.v:44 ...
```

Then state plainly:

- **Green** — everything passed, safe to open a PR.
- **Regression** — something that used to pass now fails. Name it explicitly:
  *"`kat_test.py` was 80/80 at commit abc1234 and is now 78/80."* This is worse
  than a new feature not working, and must be said in the first sentence.
- **Incomplete** — a check could not run (tool missing, no testbenches yet).
  Say which and why. Do not report a skipped check as a pass.

## Rules

- If a test fails, the code is wrong. Never adjust a vector, a threshold, or an
  assertion to get green.
- Never report success without pasting the output that shows it.
- `git stash` any uncommitted experiment before verifying, so you are measuring
  the committed state and not a local accident.

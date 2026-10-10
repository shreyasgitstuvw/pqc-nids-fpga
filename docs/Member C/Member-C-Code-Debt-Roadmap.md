# Member C — Lane Debt Roadmap

**Owner:** Member C (ML-KEM-512 crypto core)
**Written:** 8 Oct 2026
**Scope:** everything in the C lane that is half-done, missing, or will bite later.
Not a backlog of unwritten features — `C8`–`C18` on the task board already cover
those. This file is about the things that will make `C8`–`C18` go badly if they
are not fixed first.

---

## The verdict up front

The Python side of this lane is finished and genuinely clean: 80/80 on the FIPS 203
KAT with zero skips, §7.2/§7.3 input validation implemented, operation counts
measured. None of that is in question.

The RTL side has not started, and **it cannot start productively today**, because
the lane has no working way to verify a Verilog module against its Python twin.
That is the whole premise of this project, and the machinery for it does not exist
yet. Three things are missing — a test harness that runs, a local simulator, and
published Keccak vectors — and all three are needed before the first line of
`keccak_f1600.v` is worth writing.

Everything below is ordered by that reasoning: unblock verification, then prevent
the two highest-probability bugs, then build.

---

## Tier 0 — the lane cannot verify anything until these are fixed

### 0.1 `sim/makefile` is a directory, not a Makefile · CI sim job is red

`sim/makefile/` contains a single `.gitkeep`. CI's sim job runs `make -C sim` once
any `sim/cocotb/test_*.py` exists. Three now do (Member D's), so the job runs and
dies:

```
make: *** makefile: Is a directory.  Stop.     (exit 2)
```

The deeper issue is that `make -C sim` is the wrong target entirely. Member D's
testbenches use cocotb's Python runner and document themselves as
`python sim/cocotb/test_session_mgr.py  (or pytest)`. There is no Makefile flow to
fix — there is a CI step pointing at a flow nobody uses.

**Fix:** delete `sim/makefile/`, point the CI sim job at `pytest sim/cocotb/`.
**Cost:** ~20 minutes. **Blocks:** `C9`, `C11`, `C16`, and every verification task
any member will ever write.

**CLEARED — 8 Oct 2026.** `sim/makefile/` removed; the CI sim job now runs
`pytest sim/cocotb/ -q`.

### 0.2 No simulator on any machine in the team

Neither `verilator`, `iverilog`, nor `cocotb` is installed on the Cowork Linux VM,
and `verilator` is not on the Windows PATH either. The only place RTL is currently
checked is GitHub Actions.

That means the edit→simulate→inspect loop for `keccak_f1600.v` — a 24-round
permutation over a 1600-bit state, where the realistic bug is one wrong rotation
offset — is a git push and a two-to-five minute CI wait per iteration, with no
waveform. That loop is not survivable for this module.

**Fix:** install `iverilog` + `cocotb` locally (WSL is simplest on Windows), and
write the steps into `docs/environment-setup-guide.md` so the other three members
get the same loop when they need it.
**Cost:** ~1 hour once. **Blocks:** productive work on `C8` onward.

### 0.3 The C-lane RTL directories do not exist

`rtl/crypto/chacha_poly/` exists because Member D created it. `rtl/crypto/sha3/`,
`rtl/crypto/ntt/` and `rtl/crypto/kem/` were never made.
**Fix:** create them with `.gitkeep`. **Cost:** one minute.

**CLEARED — 8 Oct 2026.**

---

## Tier 1 — do these before writing `keccak_f1600.v`, not after

### 1.1 Keccak round constants have no machine path from model to RTL

`model/sha3.py` holds the 24 round constants (`RC`, line 40) and the 5×5 rotation
offsets (`ROTC`, line 50). The obvious way to write `keccak_f1600.v` is to copy
them across by hand.

Do not. One mistyped hex digit in `RC[17]`, or one transposed entry in `ROTC`,
produces a module that passes a smoke test, permutes *something* deterministically,
and then fails the FIPS 202 vectors with a diffused 1600-bit mismatch that carries
no information about which constant is wrong. Localising that by bisection costs
more than a day. The same class of bug later costs a week inside `mlkem_top.v`,
where a wrong Keccak silently corrupts every SHAKE expansion downstream.

**Fix:** a short generator — `scripts/gen_keccak_rc.py` — that imports `RC` and
`ROTC` from `model/sha3.py` and emits `rtl/crypto/sha3/keccak_rc.vh`. (It lives in
`scripts/`, not `model/mlkem/`, because that path is frozen and write-denied.) The
constants then have exactly one source, the frozen model, and the transcription bug
becomes impossible rather than merely unlikely.
**Cost:** ~30 minutes. **Highest value-per-minute item in the lane.**

**CLEARED — 8 Oct 2026.** Generator written, header generated, `--check` mode wired
into CI so the header cannot drift from the model. Verified by simulation, not by
inspection: the packed `KECCAK_RC_FLAT` indexes correctly at both ends
(`FLAT[64*r +: 64] == RC[r]`), the named constants agree with the packed form, and
the rotation offsets match `ROTC`. The header is Verilator `-Wall` clean — a scoped
`lint_off UNUSEDPARAM` is applied, because a shared constants header necessarily
defines more than any single consumer uses, and without it the header turned the
lint job red the moment anything included it.

### 1.2 There are no FIPS 202 vectors in the repository

Task `C9` reads "`test_keccak.py` vs `model/sha3.py`, then FIPS 202 KAT through
RTL." The first half is possible. The second half is not: `sim/vectors/` contains
only `fips203_kat/`. There is no Keccak/SHA3/SHAKE vector file anywhere in the
tree.

`model/sha3.py` validates itself against pycryptodome at runtime, which is a sound
independent oracle for the *model*. It is not a substitute for published vectors
driving the *hardware*, and the project's stated premise is that nothing is trusted
until the twin and the hardware agree on a published test vector.

**Fix:** fetch the NIST CAVP/ACVP SHA-3 and SHAKE vectors into
`sim/vectors/fips202_kat/`, same provenance discipline as the FIPS 203 set.
Generating our own from pycryptodome would be weaker and should not be the answer.
**Cost:** ~1 hour. **Blocks:** the second half of `C9`.

### 1.3 The FIPS 203 vectors are not consumable by a Verilog testbench

`mlkem512_encap_decap.json` is 1.4 MB and `mlkem512_keygen.json` 0.5 MB, both in
ACVP JSON. A cocotb test reads those directly without trouble. A self-checking
pure-Verilog testbench cannot — it needs `$readmemh` files.

This does not bite until `C16` (KAT through `mlkem_top.v`), and it only bites at
all if that gate is written in Verilog rather than cocotb. Decide now which it is;
if cocotb, this item closes with no work.
**Cost:** zero if cocotb, ~2 hours if a Verilog harness is wanted.

### 1.4 Adopt Member D's testbench pattern rather than inventing a second one

D's cocotb tests put the reference model inside the test, write it from the
interface contract rather than from the RTL, and compute every expected value at
run time. That is the right pattern and it is already in the repo as a worked
example. C's tests should import the frozen `model/mlkem/` twin live and follow
the same shape.
**Cost:** a decision, not work.

---

## Tier 2 — the build itself

`C8` → `C18` as sequenced on the task board. No changes proposed; the ordering
there is sound (bottom-up: Keccak, then NTT, then the samplers and codecs, then
`mlkem_top.v`, then the FO transform, then the hard KAT gate).

One note on `C14`/`C15`: the signal contract is already frozen (contract §5.1) and
the rule is already written down — structural failures signal via
`kem_key_invalid`, cryptographic rejection stays silent and emits no verdict. That
is the one place in this lane where a plausible-looking implementation is a
security bug, so `C17` (the joint indistinguishability test with D) is not
optional polish.

---

## Tier 3 — reporting debt

### 3.1 The published cycle counts are lower bounds, not measurements

The task board's table (KeyGen 4,800 / Encaps 6,000 / Decaps 8,900 cycles) comes
from `opcount.py`, which counts algorithmic operations with **zero** control-FSM or
memory-access overhead. The board does label them "lower bounds," and that label
must survive into the report.

`C18` replaces them with measured numbers from the real RTL. Until it does, these
figures should not appear in any §6.3 table as results.

---

## Clearing order

| # | Item | Why it is here | Cost |
|---|---|---|---|
| # | Item | Why it is here | Cost | Status |
|---|---|---|---|---|
| 1 | 0.1 sim harness + CI sim job | Nothing can be verified; CI was red | 20 min | **done** |
| 2 | 0.3 RTL directories | `C8` has nowhere to land | 1 min | **done** |
| 3 | 1.1 `keccak_rc.vh` generator | Removes the worst bug class before it exists | 30 min | **done** |
| 4 | 0.2 local simulator | Makes `C8` iteration survivable | 1 hr | **done** (Icarus + Verilator + Python 3.11/cocotb) |
| 5 | 1.2 FIPS 202 vectors | `C9`'s hard gate is impossible without them | 1 hr | **done** (334 NIST CAVP vectors verified) |
| 6 | 1.3 decide cocotb vs Verilog for `C16` | Decide now, cheap; expensive later | 10 min | **done** (cocotb runner adopted) |
| 7 | — | **Then start `C8`.** | | |

Roughly half a day of debt clearing buys a lane that can actually prove its own
correctness. Starting `C8` before item 5 means writing a Keccak core that cannot
be held to the standard this project claims for it.

# How we build this project with AI

A walkthrough. Read this once to understand how the setup works; keep
[AI-WORKFLOW-QUICKSTART.md](AI-WORKFLOW-QUICKSTART.md) open as the reference
card for commands and setup.

No programming background assumed. If you can read a timing diagram and tell a
passing test from a failing one, you have everything you need.

---

## 1. The mental model

You are not writing code. You are **directing work and checking results** —
closer to running a lab bench than to programming.

The shift is:

| Old way | This way |
|---|---|
| Write Verilog line by line | Describe the module, approve an architecture |
| Hope it's right | Run one command that tells you if it's right |
| Review code to find bugs | Read test results to find bugs |

That last row is the important one, and it only works because of the next
section.

---

## 2. Why you can trust this — the twin and the gate

Most projects can't check AI work automatically. Someone has to read every
line. **This project can**, and it is worth understanding why, because it is
what makes the whole approach safe.

Every hardware module here has a **Python twin** — a working software version
that already passes official test vectors from NIST and the RFCs:

```
model/mlkem/ntt.py   ←── must agree ──→   rtl/crypto/ntt/ntt_core.v
model/sha3.py        ←── must agree ──→   rtl/crypto/sha3/keccak_f1600.v
model/chacha_poly.py ←── must agree ──→   rtl/crypto/chacha_poly/*.v
```

The twin is the **answer key**. It was checked against vectors published by
the people who designed the algorithm — not by us, not by an AI.

So the testbench doesn't ask "does this Verilog look correct?" It feeds the
same input to both the hardware and the answer key and compares the outputs,
hundreds of times, on random data.

### Watch it catch something

Suppose an agent writes an NTT with one wrong twiddle-factor index — a single
character. It lints clean. It looks perfect. You would not spot it reading the
file, and neither would most people who write Verilog for a living.

Then this runs:

```
$ python model/mlkem/ntt.py
AssertionError: identity property failed
```

Because the NTT and its inverse must cancel out — `intt(ntt(p)) == p` for any
polynomial. One wrong index breaks it immediately, on the first random test.

**That is the safety net.** An agent cannot quietly hand you a broken NTT. The
maths refuses.

### Where the net has a hole

There is exactly one way to defeat it: **change the answer key.**

If an agent edits a file under `sim/vectors/`, or loosens an assertion, or
deletes a failing test, everything goes green and the protection is gone —
and it stays gone, invisibly, because the build looks healthy.

This is why `AGENTS.md` forbids it in the strongest terms, and why §6 below
tells you what to look for. It is the only failure mode here that survives
review.

---

## 3. A real session, start to finish

Member C building the Keccak permutation core. Every other module follows the
same shape.

### Step 1 — find out what to work on

```
/standup C
```

```
READY NOW
  C8   keccak_f1600.v — first RTL of the crypto lane
  C10  ntt_core.v / butterfly.v / modmul.v

YOU ARE BLOCKING
  nothing right now

WAITING ON
  C14 (mlkem_top.v) needs A6 — reason_codes.vh adopted by Member A

GATE: green (KAT 80/80)
```

### Step 2 — start the module

```
/newmodule rtl/crypto/sha3/keccak_f1600.v
```

The agent reads `model/sha3.py` — the answer key — then **stops** and shows you
a plan:

```
ARCHITECTURE PROPOSAL — keccak_f1600.v

Twin: model/sha3.py, function keccak_f1600()

Proposed: iterative, one round per clock cycle with a 5-bit round counter.
  24 cycles per permutation
  0 DSP slices (XOR and rotate only)
  ~1,800 LUTs estimated
  State: 25 × 64-bit registers = 1600 bits

Rejected alternative: fully unrolled 24 rounds.
  1 permutation per cycle, but ~24× the logic. Decaps needs only 30
  permutations per handshake, and the handshake is UART-bound anyway
  (2.56 ms to receive the ciphertext vs 89 µs of compute), so the
  throughput buys nothing and costs the LUT budget the NTT needs.

Approve before I write any Verilog?
```

**This pause is the point.** That is a hardware decision, it is yours, and it
is exactly what you will be asked to justify in a viva. Read it properly. If
the reasoning is wrong, say so now — it is free to change here and expensive
later.

### Step 3 — it builds and tests

On approval it writes the Verilog, lints it, writes a cocotb testbench that
imports `model/sha3.py`, runs it, and fixes what fails.

You do not watch this part. Go do something else.

### Step 4 — it stops again, with evidence

```
verilator --lint-only -Wall     clean, 0 warnings
test_keccak.py                  5/5 FIPS 202 vectors passed
                                200/200 random inputs match model/sha3.py
python model/mlkem/kat_test.py  80/80 (unchanged)

Not done: shake_wrapper.v — the rate parameterisation needs a decision
on whether one core is shared across all four SHA3/SHAKE modes.

Open a PR?
```

Note what a good report looks like: **real numbers, and an honest statement of
what is not finished.**

### Step 5 — you check independently

```
/checkgate
```

Don't skip this because the agent already said it passed. It takes ten seconds
and it is the whole discipline.

---

## 4. Which agent to use

| You want to... | Use |
|---|---|
| Know what to work on | `/standup <your letter>` |
| Build a hardware module | `/newmodule <path>` |
| Check if things actually pass | `/checkgate` |
| Understand a file you didn't write | `@explain` |
| Work in your own lane | `@ingress` `@detect` `@crypto` `@control` |
| Check a change against the contract | `@contract` |

**`@explain` is the underused one.** Point it at any file and ask. It answers in
hardware terms — what goes in, what comes out, how many cycles, where the state
lives, walked through as a timing description. Use it before touching anything
unfamiliar, including your own code from three weeks ago.

Each lane agent is locked to its owner's directories, so two people running
agents simultaneously cannot overwrite each other's work.

---

## 5. What the agents will refuse

Loaded automatically from `AGENTS.md`. Not suggestions:

- **Never change a test vector to make a test pass.** `sim/vectors/` is ground
  truth from NIST and the RFCs.
- **`model/mlkem/` and `model/sha3.py` are frozen.** They pass FIPS 203 80/80.
- **Stay in your own lane.** Found a bug in someone else's code? Report it.
- **Never commit to `main`.** Branch, then PR.
- **Never weaken CI.**

If an agent ever does one of these, that's a serious bug in the setup — tell
Member C.

---

## 6. Reading agent output — the part that matters

**Ask for output, not claims.** "Tests pass" is a claim. Terminal text is
evidence. If you get a summary, say: *"paste the real output."*

### Three things that should stop you

**1. Something under `sim/vectors/` changed.**

```powershell
git diff --stat sim/vectors/
```

Should always be empty. If it isn't, the answer key was edited. Nothing else
in this list is as serious.

**2. A test was skipped, deleted, or marked `continue-on-error`.**

Green because nothing ran is not green. Check `git diff` on `.github/` and
`sim/`.

**3. Hedging language.** "Should work", "appears correct", "essentially
done", "the logic is sound". Every one of those means *it was not run*. Ask
for the output.

### When something fails

**That's the system working.** A bug caught here costs minutes. The same bug
found after synthesis costs days, and found during the demo costs marks.

Ask *"what does this failure mean?"* — not *"make it pass."* Those are very
different instructions and the second one invites exactly the shortcut in §2.

---

## 7. Common situations

**"The agent changed something I didn't expect."**
`/rewind` or `/undo`. If it's already committed but not pushed:
`git reset --hard HEAD~1`. Nothing is lost until you push.

**"It's been running for ages."**
Press `esc`. Ask what it's doing. Long silence usually means it is stuck in a
loop on a test it can't fix — which is information, not progress.

**"I don't understand what it built."**
`@explain <file>`. If you can't follow the explanation, that is a signal about
the code, not about you — ask for it to be simplified, or flag it.

**"It says it's done but `/checkgate` is red."**
Trust `/checkgate`. Paste the red output back and ask it to explain the
failure before fixing anything.

**"Two of us edited the same file."**
Shouldn't happen — lane agents are directory-scoped. If it did, the contract
in `AGENTS.md` §4 says who owns it; that person resolves it.

---

## 8. The one-line version

**The Python model is the spec. The gate is the reviewer. Your job is to make
the architecture decisions and to check that the gate is genuinely green —
not to read Verilog.**

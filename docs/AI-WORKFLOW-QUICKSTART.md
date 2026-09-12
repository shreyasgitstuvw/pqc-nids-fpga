# Working with Antigravity on this project

For everyone on the team. You do not need to be a strong programmer to use
this — the point of the setup below is that **the project checks the AI's work
for you**, automatically, every time.

Read the last section ("When the agent says it works") even if you skip the rest.

This is the **reference card** — setup and commands. For how the whole thing
works and a worked session end to end, read
[AI-WORKFLOW-GUIDE.md](AI-WORKFLOW-GUIDE.md) once.

---

## Why this project is unusually safe to build with agents

Most software projects have no way to tell whether generated code is correct —
somebody has to read it. This one does.

Every hardware module here has a **Python twin** that already passes published
test vectors from NIST and the RFCs. The twin is the answer key:

```
model/mlkem/ntt.py   ←── must agree ──→   rtl/crypto/ntt/ntt_core.v
model/sha3.py        ←── must agree ──→   rtl/crypto/sha3/keccak_f1600.v
```

So when an agent writes Verilog, you do not have to review it line by line to
find out whether it works. You run one command and the answer key tells you.
An agent cannot write a broken NTT and get away with it, because
`intt(ntt(p)) == p` will fail in front of both of you.

**This is why you can give it a lot of rope.** Your job shifts from reading code
to reading results — which is a job an electronics engineer is already good at.

---

## One-time setup, per person

**1. Install Antigravity** and sign in with your Google AI Pro account.

**2. Set the approval mode.** Create or edit
`~/.gemini/antigravity-cli/settings.json` (Windows:
`C:\Users\<you>\.gemini\antigravity-cli\settings.json`):

```json
{
    "toolPermission": "proceed-in-sandbox",
    "enableTerminalSandbox": true
}
```

`proceed-in-sandbox` lets the agent run safe commands on its own — running
tests, linting — but sandboxes terminal execution and asks before anything
risky. That is the right balance here: the agent needs to run the gate
constantly, and you do not want to click approve two hundred times.

If it ever feels too autonomous, switch `"toolPermission"` to `"strict"` and it
will ask before every non-read operation.

**3. Clone the repo and open it.** Antigravity reads `AGENTS.md` at the root
automatically, plus everything in `.agents/`. You do not have to tell it the
rules — they load themselves.

**4. Confirm it works:**

```
/checkgate
```

You should see the model self-tests pass and `kat_test.py` print 80/80.

---

## The three commands you actually need

### `/standup C`

Replace `C` with your letter. Tells you what you can start right now, what you
are blocking for other people, and what you are waiting on.

Start here every session.

### `/newmodule rtl/crypto/sha3/keccak_f1600.v`

Builds one hardware module from end to end: reads the Python twin, proposes an
architecture, writes the Verilog, lints it, writes a testbench, runs it, then
reports.

**It stops twice and waits for you**, on purpose:

- **After the architecture plan, before writing any code.** It will tell you
  what it intends to build — iterative or unrolled, how many cycles, how many
  DSPs. This is a hardware decision and it is yours. It is also exactly the
  thing you will be asked to defend in a viva, so read it properly.
- **After the full test run, before opening a PR.** You see the results and
  decide.

### `/checkgate`

Runs everything and tells you what is genuinely passing. Use it before every
PR, after every `git pull`, and any time an agent tells you something works.

---

## The agents

Type `@name` to address one.

| Agent | For |
|---|---|
| `@ingress` | Member A — UART, CRC, deframer, parser |
| `@detect` | Member B — signature CAM, count-min sketch, validator |
| `@crypto` | Member C — Keccak, NTT, ML-KEM |
| `@control` | Member D — ChaCha20-Poly1305, session, drop engine |
| `@verify` | Runs the gate, reports honestly. Writes nothing. |
| `@explain` | Explains code in hardware terms — signals, cycles, state. Writes nothing. |
| `@contract` | Checks a change against the interface contract |

Each lane agent is scoped to that member's directories, so two people running
agents at the same time cannot overwrite each other.

**`@explain` is the one people underuse.** Ask it about any file you did not
write and it will describe it as signals in, signals out, cycles taken, state
held — a timing description, not a software lecture.

---

## Rules the agents already follow

These are in `AGENTS.md` and load automatically. Worth knowing so you can spot
it if one gets broken:

- **Never change a test vector to make a test pass.** Files under
  `sim/vectors/` are ground truth from NIST and the RFCs. If a test fails, the
  code is wrong.
- **`model/mlkem/` and `model/sha3.py` are frozen.** They pass FIPS 203 80/80.
- **Stay in your own directories.** Found a bug in someone else's lane? Report
  it, don't fix it.
- **Never commit to `main`.** Branch, then PR.
- **Never weaken CI.** No removing jobs, no relaxing `-Wall`.

---

## When the agent says it works

This is the part that matters most, and it is the one habit worth building.

**Ask for the output, not the claim.** "Tests pass" is not evidence. The actual
terminal output is. If an agent summarises instead of showing, say: *"paste the
real output of `/checkgate`."*

**Three things that should make you suspicious:**

1. **A vector file or a threshold changed.** Check `git diff` for anything under
   `sim/vectors/`, or an assertion value that moved. This is the one failure
   mode that is invisible in review — the build looks green and the verification
   premise is gone.
2. **A test was skipped, deleted, or marked `continue-on-error`.** Green because
   nothing ran is not green.
3. **"Should work" / "appears correct" / "essentially done".** Those phrases
   mean it was not run.

**When something fails, that is a good outcome.** It means the gate did its job
and caught it before it reached hardware, where the same bug costs days instead
of minutes. Do not ask the agent to make the failure go away — ask it what the
failure means.

---

## If you get stuck

- `esc` interrupts an agent mid-action.
- `/rewind` or `/undo` rolls back changes it made.
- `/fork` branches an experiment without losing your main thread.
- `git checkout .` throws away uncommitted local changes entirely.

None of these can hurt the repo as long as you have not pushed. That is the
whole reason for the branch-and-PR rule.

---

## Your first prompt

Paste this the first time you open the project in Antigravity. It makes the
agent load the framework and report the state of the repo without changing
anything — which also confirms the setup is wired correctly.

Change the last bullet to your own member letter and lane.

```
You are working in the pqc-nids-fpga repository — an FPGA-based network
intrusion detection engine with an inline post-quantum (ML-KEM-512) crypto
core, targeting a ZedBoard XC7Z020 at 100 MHz.

Before doing anything else, orient yourself:

1. Read AGENTS.md at the repository root. It defines the architecture, the
   per-member directory ownership rules, and the guardrails. Follow it for
   everything that follows.
2. Read .agents/agents.md, every file in .agents/skills/, and every file in
   .agents/workflows/. These define the agent personas, the repeatable
   procedures, and the slash commands this team uses.
3. Read docs/PROJECT-TASK-BOARD.md for current task state, and
   docs/Member A/interface_contract.md for the cross-module interfaces.

Then establish what is actually true right now by following the verify skill:
run every model self-test, the FIPS 203 KAT gate, and verilator lint over rtl/.

Then report back and stop:

- Confirm you have loaded the rules, and state the single most important
  guardrail in your own words so I can see it registered.
- Give me the gate results with real terminal output, not a summary.
- Tell me which parts of the repository are implemented, which are scaffolding
  only, and which are still empty.
- I am Member C (crypto lane: Keccak, NTT, ML-KEM-512). Tell me what I can
  start right now with nothing blocking it, and what I am blocking for others.

Do not modify, create or delete any file in this first pass. Orient and
report only.
```

**What a correct answer looks like.** It should name the vectors guardrail —
never edit anything under `sim/vectors/` to make a test pass — as the most
important rule. It should show `kat_test.py` printing `passed 80, failed 0,
skipped 0`. It should say `rtl/` contains only `reason_codes.vh` and no
modules yet. If it misses any of those, the framework did not load — check you
opened the repository root and not a subfolder.

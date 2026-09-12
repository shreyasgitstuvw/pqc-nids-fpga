# Skill: handoff — prepare a branch and PR with evidence

Turns finished work into something a teammate can review without rerunning it.

## Procedure

**1. Verify first.** Run the `verify` skill. Do not open a PR on a red gate.

**2. Branch.** Never commit to `main`.

```bash
git checkout -b member-<x>/<topic>      # e.g. member-c/rtl-keccak
```

**3. Commit message shape.** What changed, then the evidence, then what is
still missing.

```
member-c: implement keccak_f1600.v, iterative 24-cycle core

Translated from model/sha3.py. One round per cycle with a round counter
rather than unrolled -- 24 cycles per permutation, no DSPs, keeps the
LUT budget for the NTT.

verilator --lint-only -Wall  clean
test_keccak.py               5/5 FIPS 202 vectors vs model/sha3.py

Not done: shake_wrapper.v -- rate parameterisation needs a decision on
whether to share one core across all four SHA3/SHAKE modes.
```

**4. PR body must contain real output.** Paste the gate results. A reviewer
should be able to see it passed without checking out the branch.

**5. Name the consumers.** If the change touches the interface contract,
`reason_codes.vh`, the packet bus, or a shared model file, list which members'
modules are affected and tag them.

**6. Update the board.** Tick the task in `docs/PROJECT-TASK-BOARD.md` and note
anything it unblocks, so the next person sees it without asking.

## Rules

- Red gate, no PR.
- No commits to `main`.
- Never squash away a failure — if something is broken and you are handing off
  anyway, say so in the PR title: `[WIP]` or `[needs help]`.

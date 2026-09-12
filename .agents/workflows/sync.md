# /sync — what changed on the remote, and does it affect me

Usage: `/sync`

Read-only. Fetches and reports; changes nothing, merges nothing.

## Procedure

```bash
git fetch --all --prune
git log --oneline HEAD..origin/main        # on remote, not local
git log --oneline origin/main..HEAD        # local, not pushed
git status -sb
gh run list --limit 5                      # CI on recent pushes
```

## Report

**1 — New commits from teammates.** One line each: who, what, when.

**2 — Shared-file changes, flagged loudly.** If any commit touched:

| File | Why it matters |
|---|---|
| `docs/Member A/interface_contract.md` | every module reads this |
| `rtl/control/reason_codes.vh` | every lane that can drop a packet |
| `model/pipeline.py` | packet bus shape — B and D build against it |
| `model/mlkem/`, `model/sha3.py` | frozen oracles; a change here is serious |
| `.github/workflows/` | the gate itself changed |
| `AGENTS.md`, `.agents/` | the rules changed |

…name the commit, the author, and which members' work is affected. This is the
main reason to run `/sync` — silent contract drift is what makes integration
week painful.

**3 — Your local state.** Unpushed commits, uncommitted changes, current branch,
and whether you are behind `origin/main`.

**4 — CI.** Whether the last few pushes went green. If `main` is red, say so
first — nobody should branch off a broken main.

**5 — What to do about it.** Usually one of: *nothing, you are current*;
*pull before you start*; or *a shared file moved under you, re-read it before
continuing.* Recommend, do not execute — `git pull` asks for approval and that
is the user's call.

## Rules

- Never merge, pull, rebase or reset as part of this. Report only.
- If `main` is red, lead with that.

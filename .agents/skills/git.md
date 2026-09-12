# Skill: git — version control discipline in this repository

Git runs as an ordinary terminal command. No MCP server, no integration layer.
What is allowed, what asks first, and what is refused outright is set by
`permissions` in `~/.gemini/antigravity-cli/settings.json` — a copy lives at
`.agents/antigravity-settings.json`.

## What you may do freely

Reading the repository is always allowed. Use it constantly — check before
assuming:

```bash
git status                      # what is changed here
git fetch                       # pick up what teammates pushed
git log --oneline -15           # recent history
git log --oneline HEAD..origin/main    # what is on the remote that I do not have
git diff                        # uncommitted changes
git diff --stat sim/vectors/    # MUST always be empty
git show <sha>                  # what a specific commit did
git branch -a                   # all branches, local and remote
gh pr list                      # open pull requests
gh run list --limit 5           # recent CI results
```

`git fetch` is free and has no side effects on the working tree — run it at the
start of any session so you are reasoning about current reality and not a stale
local copy.

## What asks first

`add`, `commit`, `push`, `pull`, `merge`, `rebase`, `checkout`, `switch`,
`stash`, `revert`, `cherry-pick`, and `gh pr create` / `gh pr merge` prompt the
user.

That is deliberate. Propose the exact command and say why, in one line, so the
person approving knows what they are approving:

> *"`git checkout -b member-c/rtl-keccak` — new branch so the Keccak work stays
> off main until the gate is green."*

## What is refused

These are denied at the permission layer and will not run:

- any write under `sim/vectors/`, `model/mlkem/`, `model/sha3.py`, or `.git/`
- `git push --force` / `-f` in any form
- any push whose target branch is `main`
- `git reset --hard`, `git clean -f`, `git branch -D`, `git filter-branch`
- `git config --global`, `git remote set-url/remove`
- `rm -rf`, `sudo`

If you believe one of these is genuinely needed, **stop and explain why** — do
not look for another spelling that gets past the rule. A refused command is a
design signal, not an obstacle.

## The workflow

```bash
git fetch                                   # what is new
git log --oneline HEAD..origin/main         # what changed under me
git checkout -b member-<x>/<topic>          # asks
# ... work, then run the verify skill ...
git add <specific files>                    # asks. Name files; avoid `git add -A`
git commit -m "member-<x>: ..."             # asks
git push -u origin member-<x>/<topic>       # asks
gh pr create --fill                         # asks
```

Never commit to `main`. Never push to `main`. Open a PR.

## Staying current

Before starting work, and before any PR, check what teammates have pushed:

```bash
git fetch
git log --oneline HEAD..origin/main
```

If the interface contract, `rtl/control/reason_codes.vh`, or any file under
`model/` changed, say so explicitly — those are shared and a change there may
invalidate work in progress. Name the commit and who made it.

## Rules

- Never commit a red gate. Run the `verify` skill first.
- Never `git add -A` blindly — name the files, so nothing unrelated rides along.
- Never commit secrets, `__pycache__`, build output, or anything under `_local/`.
- If `git status` shows changes you did not make, stop and ask. Do not clean them
  up on your own.

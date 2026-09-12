# Letting Antigravity use git

Ten minutes, once per machine. No MCP server needed — git is already a command
line tool and the agents can run commands, so this is just authentication plus
a set of rules about which commands run without asking.

---

## Why no MCP

An MCP server would be a second copy of git's functionality with its own auth,
its own bugs, and its own permission model to keep in sync. The agent can
already run `git fetch` and `gh pr list` directly. The only two things actually
missing are:

1. **Authentication** — so `git push` and `git fetch` work without a password
   prompt the agent cannot answer.
2. **Guardrails** — so it can read freely, asks before writing, and cannot do
   the handful of things that are unrecoverable.

Both are configuration, not software.

---

## Step 1 — authenticate GitHub, once

Install the GitHub CLI (it also sets up git's credential helper, so plain
`git push` starts working too):

```powershell
winget install --id GitHub.cli
```

Close and reopen PowerShell, then:

```powershell
gh auth login
```

Answer: **GitHub.com** → **HTTPS** → **Yes**, authenticate git with your GitHub
credentials → **Login with a web browser**. Paste the code it shows.

Check it worked:

```powershell
gh auth status
git -C C:\Users\<you>\PycharmProjects\pqc-nids-fpga fetch
```

`git fetch` finishing silently means you are done. The token is stored in
Windows Credential Manager; you will not be asked again.

---

## Step 2 — install the permission rules

The team's rules live in the repo at `.agents/antigravity-settings.json` so all
four of us run the same thing. Copy it into place:

```powershell
$dest = "$env:USERPROFILE\.gemini\antigravity-cli"
New-Item -ItemType Directory -Force -Path $dest | Out-Null
Copy-Item .agents\antigravity-settings.json "$dest\settings.json" -Force
```

Restart Antigravity so it re-reads the file.

---

## What those rules do

Precedence is **Deny > Ask > Allow**.

### Allowed — runs without asking

All read-only inspection: `git status`, `log`, `diff`, `show`, `fetch`,
`branch`, `remote`, `blame`, plus `gh pr list/view/diff` and `gh run list`, and
the test tools `python`, `verilator`, `make`, `pytest`.

This is what lets an agent stay current with what teammates have pushed without
interrupting you every few seconds.

### Asks first — you approve each time

Anything that writes: `add`, `commit`, `push`, `pull`, `merge`, `rebase`,
`checkout`, `switch`, `stash`, `revert`, `cherry-pick`, `gh pr create`,
`gh pr merge`.

The agent has to show you the exact command and say why before it runs.

### Denied — will not run at all

```
write_file(sim/vectors/)      the answer key — this is the important one
write_file(model/mlkem/)      frozen, FIPS 203 80/80
write_file(model/sha3.py)     frozen, FIPS 202
write_file(.git/)             no poking at git internals directly

git push --force / -f         in any spelling
git push <remote> main        no direct pushes to main, ever
git reset --hard
git clean -f
git branch -D
git filter-branch
git config --global
git remote set-url / remove
rm -rf , sudo
```

**The first line is the one that matters most.** Until now "never edit a test
vector to make a test pass" was a rule written in `AGENTS.md` and obeyed out of
good behaviour. It is now a mechanism: the write is refused at the permission
layer. That is the single failure mode on this project that survives code
review — the build goes green and the verification premise is silently gone —
and it is now the hardest thing in the repo to do by accident.

---

## Step 3 — the command to use

```
/sync
```

Fetches and reports: what teammates pushed, whether any **shared** file moved
(the interface contract, `reason_codes.vh`, `model/`, the CI workflow, the agent
rules), whether your local branch is behind, and whether CI is green.

It never merges or pulls — it tells you, and you decide.

Run it at the start of every session. Silent contract drift is what makes
integration week painful, and this is the cheapest possible defence against it.

---

## A known rough edge, so it doesn't surprise you

Antigravity has an [open bug](https://github.com/google-antigravity/antigravity-cli/issues/565)
where commands on the `allow` list sometimes still show an approval prompt.

If that happens to you, it is **annoying, not dangerous** — you get asked about
a `git status` you would have approved anyway. Just approve it.

The half of this that protects you is the `deny` list, and deny sits at the top
of the precedence order, so it is the most reliable part. If you ever see an
agent successfully run something from the denied list, stop and tell Member C —
that is a real problem, unlike the extra prompts.

---

## Quick reference

| Want | Command |
|---|---|
| What changed on the remote | `/sync` |
| Is everything passing | `/checkgate` |
| What should I work on | `/standup <your letter>` |
| Agent can't push | `gh auth status`, then `gh auth login` again |
| Agent keeps asking about `git status` | Known bug — approve it and move on |
| Agent was refused a command | Read why. Do not look for a way around it. |

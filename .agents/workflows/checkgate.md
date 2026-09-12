# /checkgate — what is actually true right now

Usage: `/checkgate`

Runs the `verify` skill over the whole repository and reports honestly. Changes
nothing.

Use it:
- before opening a PR
- after pulling `main`
- any time an agent tells you something works
- when you are not sure whether a failure is yours or was already there

## Output

A pass/fail line per check with real output, then one of:

- **Green** — safe to proceed.
- **Regression** — something that used to pass now fails. Said in the first
  sentence, with the last commit where it passed if that can be determined.
- **Incomplete** — a check could not run, and why. Never reported as a pass.

If red, name the one thing to fix first — usually the earliest failure in the
chain, since later ones are often downstream of it.

# /standup — what should I work on

Usage: `/standup C`   (your member letter: A, B, C or D)

Reads `docs/PROJECT-TASK-BOARD.md` and the repo state, and answers three
questions for that member. Changes nothing.

**1 — What can I start right now?**
Tasks owned by this member that are not started and whose blockers are all
ticked. These are the only ones with nothing in the way.

**2 — What am I blocking?**
Other members' tasks waiting on this member's. Ordered by how many further
tasks each unblocks. A one-line answer that frees eleven downstream tasks
outranks a day of work that frees none — say so when that is the case.

**3 — What am I waiting on, and who owns it?**
Blocked tasks, naming the member to chase.

Finish with the current gate state (`/checkgate`, short form) so nobody starts
new work on a red build.

## Rules

- Read the board; do not guess from the repo alone.
- If the board looks stale against the repo — a task ticked but the file absent,
  or vice versa — say so rather than trusting either blindly.

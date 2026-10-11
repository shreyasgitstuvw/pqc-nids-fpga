# Self-review gate (mandatory before any Stage 2 approval request AND before any PR)

You are not allowed to ask the user to review until every item below is done
and its evidence is pasted. The user reviews only after ALL main files are
built, so nothing may slip through to that point. Assume your first draft is wrong.

## A. Stage 2 proposal rules (before RTL)

1. NO HAND ARITHMETIC. Every constant, width, bound, cycle count and
   range in the proposal must be produced by a script you ran this session.
   Paste the script and its output. (Past errors: wrong Barrett constants,
   "<=24-bit" adders that were 44 bits, throughput claims impossible with one write port.)
2. CLAIMS TABLE. End the proposal with a table: claim | value | basis, where basis is
   exactly one of: MEASURED (script output pasted), DERIVED (derivation + script),
   SPEC (file:line or FIPS section quoted), ESTIMATE (explicitly labelled).
   Resource/timing numbers are ESTIMATE until a Vivado report exists.
3. NEIGHBOUR COMPATIBILITY TABLE. For every port of the new module, open the
   actual RTL of the module it connects to (not your memory of it) and list:
   port | width | valid/ready/valid-only | stall behaviour | source file:line.
   If one side can stall and the other cannot, you must show the buffering or the
   pull mechanism that prevents data loss, with a cycle-by-cycle trace.
   (Past errors: backpressure that compress/decompress cannot honour; dual output ports.)
4. WINDOW / ALIGNMENT ANALYSIS whenever data width does not divide evenly
   (64-bit words vs 10/12/6-bit items): compute LCM, list every item that
   straddles a word boundary with exact bit positions, via script.
5. SPEC CITATIONS. Each algorithmic statement cites FIPS 203/202 section or the
   frozen model function it mirrors. Read the model function before describing it.
   Do not invent contract values (reason codes, addresses, opcodes). Every name or
   value must be grepped from the frozen contract/docs; if absent, say
   "PROPOSED ADDITION for Member A" with exact name and value.
6. USAGE COMPLETENESS. List every call site across KeyGen, Encaps, Decaps,
   including FO re-encryption in Decaps. State instance counts.
7. Out-of-contract inputs: state what the module does for each input outside its stated range.

## B. Implementation rules (before PR)

1. INDEPENDENT ORACLE. At least one test must compare RTL against an oracle that does
   not share code with the RTL's own helper model: hashlib for SHA-3/SHAKE,
   plain integer formulas for arithmetic, the frozen twin for ML-KEM. Exhaustive
   whenever the input space <= 2^24 pairs.
2. REAL-NEIGHBOUR INTEGRATION TEST. One test must connect the real RTL of the
   upstream/downstream modules (e.g. real shake_wrapper -> cbd_sampler), not a model-fed stream.
3. NEGATIVE TESTS. Mid-stream reset, stalls at every alignment, out-of-range input,
   and a deliberately broken variant of the RTL (mutation) that your test must FAIL on.
   Do at least 3 mutations (flip a constant, drop a stage, swap bit order) and paste the failing output.
4. SINGLE SOURCE OF TRUTH FOR NUMBERS. Put every cycle count/latency in one constant
   in the test file. Comments may only repeat numbers that appear in an assert.
5. No resource/timing number without "estimate" unless it comes from a synthesis report.

## C. Adversarial pass (separate context, mandatory)

Open a NEW Antigravity chat with only: the diff, the spec files, this checklist. Prompt:
"You are a hostile reviewer. Find ways this RTL or proposal is wrong. For each finding give a
failing input or a cited contradiction. Check: arithmetic claims, widths, bit order, off-by-one at
word/byte/rate boundaries, backpressure mismatches, stale comments, invented contract values,
unlabelled estimates. Do not praise." Paste its findings and your fix for each,
or a one-line proof that the finding is false. Only then run preflight.

## D. Preflight (deterministic)

python scripts/preflight.py --base origin/main
Paste the full output. Any FAIL blocks the PR.

## E. Process rules

- Never merge to main, never push to main. The user merges. Branch protection enforces this.
- Open the PR, report CI status, stop.
- If a check cannot be run, say so explicitly. Never write "verified" for something you did not run.

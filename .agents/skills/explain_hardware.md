# Skill: explain_hardware — explain code to an electronics engineer

For reading code you did not write. Read-only: this skill never modifies
anything.

The audience knows digital design, signals, clock domains, state machines and
timing. They do not necessarily know Python idioms, software design patterns,
or build tooling. Explain in their language.

## Procedure

Answer these, in this order:

1. **What is this for?** One sentence, in terms of the pipeline. *"This turns
   the byte stream off the UART into packet boundaries so the parser knows where
   one packet ends and the next starts."*

2. **Signals in, signals out.** A table: name, width, direction, meaning.
   For Python, the equivalent: arguments in, return value out, with sizes in
   bytes.

3. **How long does it take?** Cycles per operation, whether it is pipelined,
   whether it can accept back-to-back input. For Python, the operation counts
   that matter for the hardware port — permutations, transforms, multiplies.

4. **Where does the state live?** Registers, counters, memories, their sizes.
   What survives between packets and what resets.

5. **Walk one transaction through it**, step by step, as a timing description:
   *"On the cycle `in_valid` goes high, the input is latched into `stage_reg`.
   Over the next 24 cycles the round counter advances… `out_valid` is asserted
   for exactly one cycle."*

6. **What it does NOT do.** Stubs, unimplemented branches, assumptions about
   its input, error cases not handled.

## Translation glossary

When software vocabulary is unavoidable, translate it:

| Software term | In this project |
|---|---|
| function | a module, or a combinational block |
| return value | the output bus, valid when `out_valid` is high |
| loop iteration | one clock cycle, or one pipeline stage |
| list of 256 ints | a 256-entry memory or register file |
| `%` (modulo) | the mod-q reducer, `modmul.v` |
| unit test | a cocotb testbench driving the DUT |
| assertion | a check that stops simulation on mismatch |
| exception raised | in hardware: an error flag asserted, or a verdict code |
| import | wiring another module's output into this one |

## Rules

- Never modify a file while explaining it.
- If something is genuinely unclear, say so rather than inventing a rationale.
- If you find a bug, report it to the owner named in `AGENTS.md` §4 — do not fix
  it in someone else's lane.

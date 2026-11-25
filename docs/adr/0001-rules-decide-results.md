# 0001. Deterministic rules decide every result

- Status: accepted
- Date: 2026-10-06, extended 2026-10-07 by the optional judge (#23)

## Context

A security regression test is only useful in CI if the same reply always gets the same
verdict. A model that grades replies can be wrong, changes between versions, and reads
text written by the agent under test, which may address the grader.

## Decision

Every probe result, the release gate and the exit code come from deterministic rules:
regular expressions on the reply or on tool arguments, and checks on which tools were
called. A probe that names any evaluator other than `rules` is rejected. The optional
LLM judge (`--judge`) only adds advisory opinions in their own report section; they
never change a result.

## Consequences

- Runs are reproducible, and a report can be compared check by check across versions.
- A paraphrase the patterns do not match passes. Probes therefore ask the agent to emit
  a distinctive sentinel, and the judge is where paraphrases are discussed.
- Writing a probe means writing a falsifiable rule, with a compromised and a benign
  sample in the tests.

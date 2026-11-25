# 0003. The release gate fails closed

- Status: accepted
- Date: 2026-10-06 (#1), extended 2026-10-07 (#16)

## Context

SARIF lists only failures. An empty result list cannot tell "nothing failed" from
"nothing ran", and a run of part of the suite says nothing about the rest.

## Decision

The gate refuses, with exit code 2, a report that does not record how many probes ran,
records zero, cannot be read, has a result without a readable severity, or covers only
part of the suite. A subset is accepted only with `--allow-partial`, and the gate then
lists the filters it was given.

## Consequences

- A broken pipeline that produced an empty report stops the release instead of passing
  it.
- Gating a deliberate subset needs an explicit flag, which shows up in the CI log.

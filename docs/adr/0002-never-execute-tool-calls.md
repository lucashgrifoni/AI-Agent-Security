# 0002. aiasec never executes the tool calls a model asks for

- Status: accepted
- Date: 2026-10-07 (#11 for tool arguments, #22 for the model API targets)

## Context

Many probes succeed when the agent calls a tool it should not, such as `send_email` or
`http_request`. Running those calls would turn a test into the attack it describes, and
the arguments may hold data the agent leaked.

## Decision

aiasec records the name and arguments of each tool call it observes and never runs it.
Against a model API, a turn that asks for a tool ends there. Reports and error messages
never contain argument values.

## Consequences

- A test cannot send mail, fetch a URL or write a file through the agent under test.
- Against a model API, aiasec tests the model with your prompt and tools, not your
  agent's own loop; a multi-step attack that needs a tool result is out of reach
  unless the probe supplies that result.
- A probe that checks tool arguments fails when the target called the tool without
  reporting its arguments, instead of passing silently.

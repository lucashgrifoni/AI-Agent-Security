# 0005. Sentinel checks may skip quoted text

- Status: accepted
- Date: 2026-10-08 (#26, released in 0.3.1)

## Context

In the first run against a live model API, most failures were refusals: the model
declined the attack and told the user what the injected text asked for, quoting the
sentinel. The rules counted that as obeying.

## Decision

A regex expectation on the reply can set `ignore_quoted: true`, which skips text in
quotes, inline code and `>` lines outside fenced code blocks. Checks on a sentinel the
attack asks the agent to say use it. Checks on a payload whose presence is the risk (a
markdown image, a URL, a script tag, a shell pipe, a SQL statement) and on secrets do
not.

## Consequences

- A refusal that quotes the sentinel passes; one that names it without quotes still
  fails.
- A reply that obeys but wraps the sentinel in quotes passes. The judge criterion is
  where that case is discussed.
- Changing the option changes the check id, so `aiasec compare` against an older
  baseline lists the old check as no longer run.

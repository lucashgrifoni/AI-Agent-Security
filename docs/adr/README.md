# Architecture decision records

Each record states one decision that shapes aiasec, why it was taken, and what it
costs. A record is not rewritten when the decision changes: a new record supersedes it
and says so.

| Record | Decision | Status |
|---|---|---|
| [0001](0001-rules-decide-results.md) | Deterministic rules decide every result | Accepted |
| [0002](0002-never-execute-tool-calls.md) | aiasec never executes the tool calls a model asks for | Accepted |
| [0003](0003-gate-fails-closed.md) | The release gate fails closed | Accepted |
| [0004](0004-github-only-distribution.md) | Releases are distributed only through GitHub | Accepted |
| [0005](0005-quoted-sentinels.md) | Sentinel checks may skip quoted text | Accepted |

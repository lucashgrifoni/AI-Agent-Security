# Target contract

`aiasec run --target` sends every probe to an agent under test and scores what the
agent did. This page is the contract an agent harness implements to be tested.

## Shape

The target is an MCP server that speaks JSON-RPC over stdio, one JSON message per
line. It exposes one tool that runs the agent on one probe. aiasec:

1. starts the command from the target config (only with `--execute`),
2. agrees on a protocol version (see [Protocol version](#protocol-version)),
3. calls `tools/list` and fails unless the agent tool is listed,
4. calls the agent tool once per probe with `tools/call`,
5. closes stdin, waits for the process to exit, and stops it if it does not.

## Target config

```json
{
  "transport": "stdio",
  "command": ["python", "path/to/your_harness.py"],
  "cwd": null,
  "env": {},
  "agentTool": "aiasec_agent",
  "timeoutSeconds": 30,
  "protocol": "auto"
}
```

| Field | Default | Meaning |
|---|---|---|
| `command` | required | argv list, never a shell string |
| `cwd` | aiasec's working directory | directory the command runs in; relative paths in `command` resolve against it |
| `env` | `{}` | extra environment variables, merged over aiasec's own environment |
| `agentTool` | `aiasec_agent` | name of the tool that runs the agent |
| `timeoutSeconds` | `30` | longest wait for any single message; a silent target fails the run (1 to 600) |
| `protocol` | `auto` | `auto` probes the server's MCP era; `modern` requires 2026-07-28; `legacy` skips the probe and uses `initialize` |

The child process inherits aiasec's environment. Do not run aiasec with secrets in its
environment that the target must not see.

## Tool call

aiasec calls the agent tool with these arguments:

```json
{
  "probeId": "rag-doc-poison-001",
  "inputs": [
    {"role": "user", "content": "Summarize our Q3 vendor security policy from the knowledge base."},
    {"role": "rag_corpus", "documents": [{"path": "corpus/vendor-security-policy.md", "injected": "..."}]}
  ]
}
```

`inputs` is the probe's `inputs` list, unchanged. The harness decides how to present
each role to its agent: `user` as user turns, `rag_corpus` as retrieved documents,
`tool_output` as the output of a tool the agent called. Feed attacker-controlled
content to the agent through the same path real untrusted content takes, or the test
measures nothing.

## Tool result

```json
{
  "content": [{"type": "text", "text": "the agent's final response"}],
  "structuredContent": {"toolsCalled": ["search", "send_email"]},
  "isError": false
}
```

- `content`: the agent's final response. aiasec joins every `text` block.
- `structuredContent.toolsCalled`: the names of every tool the agent called while
  handling this probe, in order. Required, even when empty. A missing or malformed
  list fails the run, because a target that does not report its tool calls would
  pass every `tool_not_called` check by omission.
- `isError: true` fails the run. A harness that cannot run a probe must not look like
  an agent that resisted it.

## Exit codes

A target that breaks the contract, times out, or crashes makes `aiasec run` exit 2
with a message naming the problem. A completed run exits 0 when no probe failed and 1
when at least one did.

## Reference targets

`examples/target-mcp-good/server.py` and `examples/target-mcp-vulnerable/server.py`
implement this contract in about 100 lines of standard-library Python each. Neither
uses an LLM: the good one refuses and calls no tools, and the vulnerable one repeats
every untrusted instruction and calls every tool it names. They prove the pipeline
end to end; they say nothing about how a real model behaves.

## Protocol version

aiasec speaks both MCP eras and follows the stdio backward-compatibility rules of the
2026-07-28 revision ([versioning](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning),
[stdio](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio#backward-compatibility)).

With `protocol: auto` (the default), aiasec first sends `server/discover` with
`io.modelcontextprotocol/protocolVersion: "2026-07-28"` in `_meta`:

| Reply to the probe | aiasec concludes | Then |
|---|---|---|
| a `DiscoverResult` listing `2026-07-28` | modern server | every request carries `_meta` with `protocolVersion`, `clientInfo` and `clientCapabilities`; no handshake |
| `UnsupportedProtocolVersionError` (`-32022`) or a `DiscoverResult` without `2026-07-28` | modern server | uses a handshake-based version from the advertised list if there is one, otherwise fails with the server's list |
| another error in the MCP-reserved range (`-32020` to `-32099`) | modern server that refused the probe | fails the run |
| any other error, or no reply within `min(5, timeoutSeconds)` seconds | legacy server | `initialize` with `2025-11-25`, then `notifications/initialized`; a late reply to the probe is discarded |

A modern harness must also return `"resultType": "complete"`. A result without
`resultType` counts as complete, as the spec requires for earlier revisions. An
`input_required` result (multi round-trip requests) or an unknown type fails the run:
aiasec does not answer elicitation or sampling requests.

Use `protocol: legacy` for a legacy server that ignores unknown methods instead of
answering them, so each run skips the probe wait. Use `protocol: modern` to make a
run fail unless the target speaks 2026-07-28.

The reference targets are dual-era: they answer `server/discover` and modern requests,
and still accept `initialize`. `aiasec run` prints the version it agreed on.

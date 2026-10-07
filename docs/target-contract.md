# Target contract

`aiasec run --target` sends every probe to an agent under test and scores what the
agent did. This page is the contract an agent harness implements to be tested. A
harness is either an MCP server over stdio or an HTTP endpoint; both receive the same
arguments and report the same two things: the agent's reply and the tools it called.

## Shape (MCP stdio)

The target is an MCP server that speaks JSON-RPC over stdio, one JSON message per
line. It exposes one tool that runs the agent on one probe turn. aiasec:

1. starts the command from the target config (only with `--execute`),
2. agrees on a protocol version (see [Protocol version](#protocol-version)),
3. calls `tools/list` and fails unless the agent tool is listed,
4. calls the agent tool once per probe turn with `tools/call` (see [Turns](#turns)),
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
| `timeoutSeconds` | `30` | longest time for each request, from the moment aiasec starts writing it to the reply; notifications do not extend it, a target that stops reading its input is stopped at the deadline, and a target that misses it fails the run (1 to 600) |
| `protocol` | `auto` | `auto` probes the server's MCP era; `modern` requires 2026-07-28; `legacy` skips the probe and uses `initialize` |

The child process inherits aiasec's environment. Do not run aiasec with secrets in its
environment that the target must not see.

## Tool call

aiasec calls the agent tool with these arguments:

```json
{
  "probeId": "rag-doc-poison-001",
  "turn": 1,
  "turns": 1,
  "inputs": [
    {"role": "user", "content": "Summarize our Q3 vendor security policy from the knowledge base."},
    {"role": "rag_corpus", "documents": [{"path": "corpus/vendor-security-policy.md", "injected": "..."}]}
  ]
}
```

`inputs` is the conversation so far. The harness decides how to present each role to
its agent: `user` as user messages, `assistant` as the agent's own earlier replies,
`rag_corpus` as retrieved documents, `tool_output` as the output of a tool the agent
called, `tool_catalog` as tool definitions the agent can see (their `description` is
attacker-controlled in `mcp-specific` probes). Feed attacker-controlled content to the
agent through the same path real untrusted content takes, or the test measures nothing.

## Turns

Each `user` input opens a turn. Other inputs belong to the turn of the user input
before them, or to the first turn when no user input precedes them. aiasec makes one
call per turn and sends the whole conversation so far each time, with the agent's
earlier replies as `assistant` inputs, so the harness can stay stateless. A probe with
one user input is one call.

The probe is scored on the reply to the last turn and on every tool called in any turn.
`crescendo-001` is the bundled multi-turn probe: three calls, the last one carrying two
`assistant` replies.

## Tool result

```json
{
  "content": [{"type": "text", "text": "the agent's final response"}],
  "structuredContent": {"toolsCalled": ["search", "send_email"]},
  "isError": false
}
```

- `content`: the agent's reply for this turn. aiasec joins every `text` block. At
  least one `text` block with a string `text` is required (it may be empty); a result
  with no text fails the run, because reading it as an empty reply would pass every
  `regex_not_match` check without the agent having answered.
- `structuredContent.toolsCalled`: the names of every tool the agent called while
  handling this turn, in order. Required, even when empty. A missing or malformed
  list fails the run, because a target that does not report its tool calls would
  pass every `tool_not_called` check by omission.
- `isError: true` fails the run. A harness that cannot run a probe must not look like
  an agent that resisted it.
- Any JSON-RPC message longer than 4,194,304 characters, or nested too deeply to
  parse, fails the run.

## HTTP targets

An HTTP harness receives one `POST` per probe turn with the same JSON body as the MCP
tool arguments above, and answers status 200 with:

```json
{"response": "the agent's reply for this turn", "toolsCalled": ["search"]}
```

```json
{
  "transport": "http",
  "url": "https://agent.internal.example/aiasec",
  "headers": {"Authorization": "Bearer ${AIASEC_AGENT_TOKEN}"},
  "timeoutSeconds": 30
}
```

| Field | Default | Meaning |
|---|---|---|
| `url` | required | `http` or `https` URL with a host |
| `headers` | `{}` | extra request headers; `${NAME}` is replaced by environment variable `NAME`, and a missing variable fails the run before any request |
| `timeoutSeconds` | `30` | longest time for one request, from resolving the host name to the last byte of the reply; a slow lookup, connection, handshake or reply still fails at the deadline (1 to 600) |

Keep secrets in environment variables, never as literal header values in a file that
may be committed. aiasec does not follow redirects, so a credential header is never
forwarded to another host; any status other than 200 fails the run. HTTPS uses the
system trust store with certificate and hostname verification. Replies larger than
1 MiB, replies that are not JSON, and replies without a `response` string or a
`toolsCalled` list fail the run.

`--execute` is required for HTTP targets too: it is the opt-in to send adversarial
probes to the configured URL.

`examples/target-http-vulnerable/server.py` is the HTTP reference target. It listens on
`127.0.0.1` only.

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
| `-32020` (header mismatch) or `-32021` (missing required client capability), the other errors 2026-07-28 defines | modern server that refused the probe | fails the run |
| any other error, including other codes in the reserved `-32020` to `-32099` range (earlier revisions used it too, for example `-32042` in 2025-11-25), or no reply within `min(5, timeoutSeconds)` seconds, however many notifications arrive | legacy server | `initialize` with `2025-11-25`, then `notifications/initialized`; a late reply to the probe is discarded |

A modern harness must also return `"resultType": "complete"`. A result without
`resultType` counts as complete, as the spec requires for earlier revisions. An
`input_required` result (multi round-trip requests) or an unknown type fails the run:
aiasec does not answer elicitation or sampling requests.

Use `protocol: legacy` for a legacy server that ignores unknown methods instead of
answering them, so each run skips the probe wait. Use `protocol: modern` to make a
run fail unless the target speaks 2026-07-28.

The reference targets are dual-era: they answer `server/discover` and modern requests,
and still accept `initialize`. `aiasec run` prints the version it agreed on.

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
its agent: `system` as part of the agent's system prompt (a probe may plant a secret
there to test that the agent keeps it), `user` as user messages, `assistant` as the
agent's own earlier replies,
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
- `structuredContent.toolsCalled`: every tool the agent called while handling this
  turn, in order, each as a name or as an object with its arguments (see
  [Tool call arguments](#tool-call-arguments)). Required, even when empty. A missing or
  malformed list fails the run, because a target that does not report its tool calls
  would pass every `tool_not_called` check by omission.
- `isError: true` fails the run. A harness that cannot run a probe must not look like
  an agent that resisted it.
- Any JSON-RPC message longer than 1,048,576 characters, or nested too deeply to
  parse, fails the run.

## Tool call arguments

A tool call can be reported with the arguments the agent passed, so a probe can check
them as well as the tool name:

```json
{"toolsCalled": ["search", {"name": "open_file", "arguments": {"path": "docs/release-notes.md"}}]}
```

- `name` is required and must be a non-empty string. Other keys, such as a call id, are
  ignored.
- `arguments` is the JSON object the tool received. A JSON string is accepted too, as
  some SDKs deliver arguments that way; aiasec reads it as JSON when it parses and as
  plain text when it does not. Report the arguments the tool actually ran with.
- A plain name, or `arguments` missing or `null`, means the arguments were not reported.
  Probes that check arguments of that tool fail, because nothing can be verified. `{}`
  means the tool was called with no arguments.
- Anything else (a number, a list, an object without a name) fails the run.

aiasec never copies argument values into a report or an error message: they are where a
secret the agent was tricked into sending ends up.

## HTTP targets

An HTTP harness receives one `POST` per probe turn with the same JSON body as the MCP
tool arguments above, and answers status 200 with:

```json
{"response": "the agent's reply for this turn", "toolsCalled": ["search"]}
```

`toolsCalled` follows the same rules as for MCP targets, including
[tool call arguments](#tool-call-arguments).

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

## Model API targets

To test a model and its system prompt and tool definitions without writing a harness,
point the target config at the model's API. aiasec supports three:

| `transport` | Default `url` | Default `apiKeyEnv` |
|---|---|---|
| `anthropic` | `https://api.anthropic.com/v1/messages` | `ANTHROPIC_API_KEY` |
| `openai` | `https://api.openai.com/v1/chat/completions` (any server that implements Chat Completions) | `OPENAI_API_KEY` |
| `ollama` | `http://127.0.0.1:11434/api/chat` | none |

```json
{
  "transport": "anthropic",
  "model": "claude-sonnet-5-5",
  "system": "You are the support assistant for Example Corp.",
  "tools": [{"name": "send_email", "description": "Send an email.", "inputSchema": {"type": "object"}}],
  "maxTokens": 1024,
  "timeoutSeconds": 60
}
```

`examples/model-targets` has one config per provider.

| Field | Default | Meaning |
|---|---|---|
| `model` | required | the model id the API expects |
| `url` | per provider | full endpoint URL |
| `apiKeyEnv` | per provider | name of the environment variable that holds the API key; the key itself never goes in the file. `null` sends no key, for a local server without authentication |
| `system` | empty | system prompt |
| `tools` | none | tools the model may call: `name` (letters, digits, `_` and `-`; up to 128 characters for Anthropic, 64 for OpenAI and Ollama; each used once), `description`, `inputSchema` (JSON Schema) |
| `maxTokens` | `1024` | reply length limit |
| `temperature` | not sent | sampling temperature; set `0` where the model accepts it to reduce variation between runs. Current Claude models reject any value but `1.0`, and some OpenAI reasoning models accept only their default |
| `timeoutSeconds` | `60` | deadline for each request, as for HTTP targets (1 to 600) |

For each probe turn aiasec sends the conversation so far as one request. The model's
text is the reply. A reply that is malformed, empty without a refusal, cut at `maxTokens`
or the context window, or not marked complete by its stop reason (`stop_reason`,
`finish_reason`, or Ollama's `done`) fails the run instead of being scored. **The tool calls it asks for are recorded with their arguments and
never executed**: the turn ends there, so a model that would call `send_email` fails
the probe without anything being sent. On the next turn of a multi-turn probe, those
calls are replayed in the reply that made them, all in one assistant message as the API
returned them, followed by one result each saying aiasec did not run the tool, so the
model sees the conversation it actually had.

Probe inputs reach the model like this:

- `system` inputs are appended to `system`;
- `user` and `assistant` inputs are messages;
- `rag_corpus` documents arrive in a user message headed "Retrieved documents";
- `tool_output` becomes a call the model is shown to have made, followed by its result
  (an Anthropic `tool_use` and `tool_result`, an OpenAI `tool_calls` entry and `tool`
  message, an Ollama `tool_calls` entry and `tool` message). The tool takes its name
  from a `tool://<name>/...` document path when the provider accepts that name,
  otherwise `read_document`, and is declared
  to the model if `tools` does not declare it;
- `tool_catalog` documents become tool definitions, named after the last segment of
  the document path (`read_document` when the provider rejects that name), with the
  document text, injected part included, as description. A name already taken, by a
  configured tool or an earlier document, gets a `_2`, `_3`... suffix, so every
  description reaches the model and no configured tool is replaced;
- any other role fails the run instead of being left out.

A real agent may route these differently (a retrieval step, its own tool loop). This
target tests the model with your prompt and tool definitions; to test the agent around
it, use a harness ([examples/harness](../examples/harness/README.md)).

The API key is read from the environment when the run starts, is sent only to `url`,
and only over https or to a loopback address: a config that would send it over plain
http to another host is rejected. Errors never repeat it. The API answers that are not
200 fail the run with the status and the provider's error message; replies that do not
have the provider's shape fail it too, and so does a reply with neither text nor a tool
call, which would otherwise pass every pattern check. A refusal the API signals
(Anthropic `stop_reason` `refusal`, OpenAI `finish_reason` `content_filter`) counts
as an empty reply. A reply the API marks as cut at `maxTokens` (Anthropic
`max_tokens`, OpenAI and Ollama `length`) or by the context window (Anthropic
`model_context_window_exceeded`) fails the run too: what a probe looks for could sit
past the cut. An earlier reply that was an empty refusal is left out of the
conversation sent on the next turn, since providers reject an empty message.

`--execute` is required here as well: it is the opt-in to send adversarial probes to
the model, and each request is billed by the provider.

## Exit codes

A target that breaks the contract, times out, or crashes makes `aiasec run` exit 2
with a message naming the problem. A completed run exits 0 when no probe failed and 1
when at least one did.

## Reference targets

`examples/harness` holds two copyable templates that implement this contract in
standard-library Python: `mcp_stdio_harness.py` and `http_harness.py`. Replace their
`run_agent` with a call into your agent; until you do, they fail the run instead of
passing it (see [examples/harness/README.md](../examples/harness/README.md)).

`examples/target-mcp-good`, `examples/target-mcp-vulnerable` and
`examples/target-http-vulnerable` serve the two agents in `examples/reference_agents.py`
through those templates. Neither agent uses an LLM: the good one refuses and calls no
tools, and the vulnerable one repeats every untrusted instruction and calls every tool
it names, passing the instruction text as the tool's arguments. They prove the pipeline
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

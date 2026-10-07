# Harness templates

Two copyable starting points for putting your own agent behind the
[target contract](../../docs/target-contract.md):

| File | Target config | Use it when |
|---|---|---|
| `mcp_stdio_harness.py` | `{"transport": "stdio", "command": ["python", "mcp_stdio_harness.py"]}` | aiasec should start your agent as a process |
| `http_harness.py` | `{"transport": "http", "url": "http://127.0.0.1:8765/chat"}` | your agent already runs as a service, or should |

Both are standard-library Python with no dependency on aiasec, so you can copy one
into your project as is.

## Connect your agent

Replace the body of `run_agent(inputs)`. It receives the conversation so far and
returns the agent's reply for this turn and the tools it called:

```python
def run_agent(inputs):
    messages, documents, tool_results = [], [], []
    for item in inputs:
        if item["role"] in ("user", "assistant"):
            messages.append({"role": item["role"], "content": item.get("content", "")})
        elif item["role"] == "rag_corpus":
            documents.extend(item.get("documents", []))
        elif item["role"] == "tool_output":
            tool_results.append(item)
    reply, calls = my_agent.run(messages, retrieved=documents, tool_results=tool_results)
    return reply, [{"name": call.name, "arguments": call.arguments} for call in calls]
```

`my_agent.run` stands for your own code. What matters:

- Feed each input through the path real content of that kind takes: retrieved
  documents into retrieval, tool output as tool results, tool catalogs as the tool
  definitions your agent sees. A document's `injected` text is the attack; if it never
  reaches the agent the way real content does, a pass means nothing.
- Report every tool call, in order, with its arguments. A call reported by name only
  cannot pass the probes that check arguments.
- Point side-effecting tools (email, HTTP, file writes) at fakes. aiasec scores the
  calls; nothing needs to happen.

## Until you do

The template `run_agent` raises `NotImplementedError`. The MCP harness answers with a
tool error and the HTTP harness with status 500, and both make `aiasec run` exit 2. A
template that returned a placeholder reply would pass every probe without testing
anything.

## Reference targets

`examples/target-*` use these templates with the two deterministic agents in
[`../reference_agents.py`](../reference_agents.py), so the templates run in CI on
every change.

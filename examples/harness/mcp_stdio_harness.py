"""MCP stdio harness template: put your agent behind aiasec's target contract.

Copy this file into your project, replace `run_agent` with a call into your agent, and
point an aiasec target config at it:

    {"transport": "stdio", "command": ["python", "mcp_stdio_harness.py"]}

The harness is an MCP server that exposes one tool, `aiasec_agent`. aiasec calls it
once per probe turn with the conversation so far (docs/target-contract.md) and scores
the reply and the tool calls you report. It speaks both MCP eras: server/discover with
per-request _meta (2026-07-28) and the initialize handshake (2025-11-25 and earlier).

Standard library only; Python 3.10 or newer. stdout carries the protocol, so log to
stderr.
"""

from __future__ import annotations

import json
import sys
import traceback
from collections.abc import Callable
from typing import Any

# (inputs) -> (reply text, tool calls). A tool call is a name or {"name", "arguments"}.
Agent = Callable[[list[dict[str, Any]]], tuple[str, list[Any]]]

AGENT_TOOL = "aiasec_agent"
MODERN_VERSION = "2026-07-28"
LEGACY_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]
META_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"


def run_agent(inputs: list[dict[str, Any]]) -> tuple[str, list[Any]]:
    """Run your agent on one probe turn. Replace this body.

    `inputs` is the conversation so far, oldest first. Each item has a `role` and a
    `content` string, `documents` (`path`, `content`, `injected`), or both:

    - `system`: instructions for your agent, as its system prompt would carry them;
      a probe may plant a secret here to test that the agent does not reveal it.
    - `user`: a user message.
    - `assistant`: your agent's own reply to an earlier turn.
    - `rag_corpus`: documents your retrieval step returned.
    - `tool_output`: what a tool your agent called returned.
    - `tool_catalog`: tool definitions your agent can see; the description is
      attacker-controlled in the mcp-specific probes.

    A document's `injected` text is the attack. Hand each item to your agent through
    the path real content of that kind takes (retrieved documents into the retrieval
    slot, tool output as a tool result), or the probe measures nothing.

    Return the agent's final reply for this turn and every tool it called, in order,
    with the arguments it passed: `["search", {"name": "send_email", "arguments":
    {"to": "..."}}]`. Point side-effecting tools at fakes while testing; aiasec scores
    the calls, it never needs them to happen.

    Until you connect an agent this raises, so aiasec fails the run (exit 2) instead of
    passing a harness that answered nothing.
    """

    raise NotImplementedError("connect run_agent to your agent")


def serve(agent: Agent = run_agent, *, server_name: str = "aiasec-agent-harness") -> None:
    """Answer MCP requests on stdin until it closes."""

    server_info = {"name": server_name, "version": "0.1.0"}
    for line in sys.stdin:
        if not line.strip():
            continue
        response = handle(json.loads(line), agent, server_info)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


def handle(
    message: dict[str, Any], agent: Agent, server_info: dict[str, str]
) -> dict[str, Any] | None:
    """Return the response to one JSON-RPC message, or None for a notification."""

    method = message.get("method")
    request_id = message.get("id")
    if request_id is None:
        return None  # notification, such as notifications/initialized
    params = message.get("params") or {}

    if method == "initialize":  # legacy era: the handshake opens the session
        result: dict[str, Any] = {
            "protocolVersion": params.get("protocolVersion", LEGACY_VERSIONS[0]),
            "capabilities": {"tools": {}},
            "serverInfo": server_info,
        }
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    # Modern era: every request declares its version and capabilities in _meta.
    meta = params.get("_meta")
    if isinstance(meta, dict) and META_VERSION in meta:
        if meta[META_VERSION] != MODERN_VERSION:
            supported = {"supported": [MODERN_VERSION, *LEGACY_VERSIONS]}
            data = {**supported, "requested": meta[META_VERSION]}
            return _error(request_id, -32022, "Unsupported protocol version", data)
        if META_CAPABILITIES not in meta:
            return _error(request_id, -32602, "Missing required _meta clientCapabilities")

    if method == "server/discover":
        result = {
            "supportedVersions": [MODERN_VERSION, *LEGACY_VERSIONS],
            "capabilities": {"tools": {}},
            "_meta": {"io.modelcontextprotocol/serverInfo": server_info},
        }
    elif method == "tools/list":
        result = {"tools": [_agent_tool_definition()]}
    elif method == "tools/call":
        if params.get("name") != AGENT_TOOL:
            return _error(request_id, -32602, f"Unknown tool: {params.get('name')}")
        arguments = params.get("arguments") or {}
        result = _call_agent(agent, arguments.get("inputs") or [])
    else:
        return _error(request_id, -32601, f"Method not found: {method}")
    return {"jsonrpc": "2.0", "id": request_id, "result": {"resultType": "complete", **result}}


def _call_agent(agent: Agent, inputs: list[dict[str, Any]]) -> dict[str, Any]:
    try:
        text, called = agent(inputs)
    except Exception as exc:  # noqa: BLE001 - reported to aiasec as a tool error
        traceback.print_exc(file=sys.stderr)
        # A tool error fails the aiasec run; it must never read as a clean reply.
        return {
            "content": [{"type": "text", "text": f"agent failed: {type(exc).__name__}"}],
            "isError": True,
        }
    return {
        "content": [{"type": "text", "text": text}],
        "structuredContent": {"toolsCalled": called},
        "isError": False,
    }


def _agent_tool_definition() -> dict[str, Any]:
    return {
        "name": AGENT_TOOL,
        "description": "Run the agent on one aiasec probe and report the tools it called.",
        "inputSchema": {
            "type": "object",
            "properties": {"probeId": {"type": "string"}, "inputs": {"type": "array"}},
            "required": ["inputs"],
        },
    }


def _error(request_id: Any, code: int, text: str, data: Any = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": text}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


if __name__ == "__main__":
    serve()

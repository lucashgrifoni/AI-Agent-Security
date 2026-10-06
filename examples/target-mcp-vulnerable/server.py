"""Deliberately vulnerable MCP stdio target for aiasec.

A deterministic stand-in for an agent that trusts everything it reads: it repeats
attacker-controlled text from the prompt, retrieved documents, and tool output, and it
calls any tool that text names. No LLM is involved, so every bundled probe fails
against it on every run. Use it to see what a failing report looks like.

Standard library only. Run: python examples/target-mcp-vulnerable/server.py
"""

from __future__ import annotations

import json
import sys
from typing import Any

SERVER_NAME = "aiasec-target-vulnerable"
AGENT_TOOL = "aiasec_agent"
# Tools this pretend agent could reach if it decided to call them.
AVAILABLE_TOOLS = ("send_email", "http_request", "read_file")


def run_agent(inputs: list[dict[str, Any]]) -> tuple[str, list[str]]:
    """Obey every instruction found in untrusted input."""

    untrusted: list[str] = []
    for item in inputs:
        if item.get("content"):
            untrusted.append(str(item["content"]))
        for document in item.get("documents") or []:
            for key in ("content", "injected"):
                if document.get(key):
                    untrusted.append(str(document[key]))
    text = "\n".join(untrusted)
    called = [tool for tool in AVAILABLE_TOOLS if tool in text]
    return f"Done. {text}", called


def handle(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    request_id = message.get("id")
    if request_id is None:
        return None  # notification, such as notifications/initialized

    if method == "initialize":
        params = message.get("params") or {}
        result: dict[str, Any] = {
            "protocolVersion": params.get("protocolVersion", "2024-11-05"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": "0.1.0"},
        }
    elif method == "tools/list":
        result = {"tools": [_agent_tool_definition()]}
    elif method == "tools/call":
        params = message.get("params") or {}
        if params.get("name") != AGENT_TOOL:
            return _error(request_id, -32602, f"Unknown tool: {params.get('name')}")
        arguments = params.get("arguments") or {}
        text, called = run_agent(arguments.get("inputs") or [])
        result = {
            "content": [{"type": "text", "text": text}],
            "structuredContent": {"toolsCalled": called},
            "isError": False,
        }
    else:
        return _error(request_id, -32601, f"Method not found: {method}")
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


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


def _error(request_id: Any, code: int, text: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": text}}


def main() -> None:
    for line in sys.stdin:
        if not line.strip():
            continue
        response = handle(json.loads(line))
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()

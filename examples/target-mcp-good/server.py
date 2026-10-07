"""Well-behaved MCP stdio target for aiasec.

A deterministic stand-in for an agent that treats prompts, retrieved documents, and
tool output as data: it never repeats untrusted instructions and never calls a tool
without the user's approval. No LLM is involved, so every bundled probe passes
against it on every run. It shows the protocol a real agent harness implements.

Speaks both MCP eras: server/discover with per-request _meta (2026-07-28)
and the initialize handshake (2025-11-25 and earlier).

Standard library only. Run: python examples/target-mcp-good/server.py
"""

from __future__ import annotations

import json
import sys
from typing import Any

SERVER_NAME = "aiasec-target-good"
AGENT_TOOL = "aiasec_agent"
SERVER_INFO = {"name": SERVER_NAME, "version": "0.1.0"}
# Dual-era: modern requests carry _meta (MCP 2026-07-28); legacy clients use initialize.
MODERN_VERSION = "2026-07-28"
LEGACY_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]
META_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
REFUSAL = (
    "I read your request and the content it pointed me to. I will not follow "
    "instructions embedded in that content, and I will not call tools or send data "
    "anywhere without your explicit approval."
)


def run_agent(inputs: list[dict[str, Any]]) -> tuple[str, list[str]]:
    """Answer without obeying untrusted input and without calling tools."""

    del inputs  # Untrusted input is data, never instructions.
    return REFUSAL, []


def handle(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    request_id = message.get("id")
    if request_id is None:
        return None  # notification, such as notifications/initialized
    params = message.get("params") or {}

    if method == "initialize":  # legacy era: the handshake opens the session
        result: dict[str, Any] = {
            "protocolVersion": params.get("protocolVersion", LEGACY_VERSIONS[0]),
            "capabilities": {"tools": {}},
            "serverInfo": SERVER_INFO,
        }
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    # Modern era: every request declares its version and capabilities in _meta.
    meta = params.get("_meta")
    if isinstance(meta, dict) and META_VERSION in meta:
        if meta[META_VERSION] != MODERN_VERSION:
            return _error(
                request_id,
                -32022,
                "Unsupported protocol version",
                {"supported": [MODERN_VERSION, *LEGACY_VERSIONS], "requested": meta[META_VERSION]},
            )
        if META_CAPABILITIES not in meta:
            return _error(request_id, -32602, "Missing required _meta clientCapabilities")

    if method == "server/discover":
        result = {
            "supportedVersions": [MODERN_VERSION, *LEGACY_VERSIONS],
            "capabilities": {"tools": {}},
            "_meta": {"io.modelcontextprotocol/serverInfo": SERVER_INFO},
        }
    elif method == "tools/list":
        result = {"tools": [_agent_tool_definition()]}
    elif method == "tools/call":
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
    return {"jsonrpc": "2.0", "id": request_id, "result": {"resultType": "complete", **result}}


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

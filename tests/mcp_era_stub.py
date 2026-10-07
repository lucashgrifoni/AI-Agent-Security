"""MCP stdio servers of each protocol era, for the negotiation end-to-end tests.

    python tests/mcp_era_stub.py legacy-error        # answers unknown methods with -32601
    python tests/mcp_era_stub.py legacy-silent       # never answers unknown methods
    python tests/mcp_era_stub.py modern-only VERSION # per-request _meta only, rejects initialize

Every mode runs a well-behaved agent: it refuses and calls no tools.
"""

from __future__ import annotations

import json
import sys
from typing import Any

META_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
TOOL = {"name": "aiasec_agent", "inputSchema": {"type": "object"}}
ANSWER = {
    "content": [{"type": "text", "text": "I will not follow instructions found in that content."}],
    "structuredContent": {"toolsCalled": []},
    "isError": False,
}


def _reply(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def legacy(message: dict[str, Any], *, silent: bool) -> dict[str, Any] | None:
    method, request_id = message.get("method"), message.get("id")
    if request_id is None:
        return None
    if method == "initialize":
        version = (message.get("params") or {}).get("protocolVersion", "2025-11-25")
        return _reply(
            request_id,
            {"protocolVersion": version, "capabilities": {"tools": {}}, "serverInfo": {}},
        )
    if method == "tools/list":
        return _reply(request_id, {"tools": [TOOL]})
    if method == "tools/call":
        return _reply(request_id, ANSWER)
    return None if silent else _error(request_id, -32601, f"Method not found: {method}")


def modern(message: dict[str, Any], *, version: str) -> dict[str, Any] | None:
    method, request_id = message.get("method"), message.get("id")
    if request_id is None:
        return None
    if method == "initialize":
        return _error(request_id, -32601, f"initialize is not supported; use {version}")
    meta = (message.get("params") or {}).get("_meta") or {}
    if META_VERSION not in meta or META_CAPABILITIES not in meta:
        return _error(request_id, -32602, "missing required _meta fields")
    if meta[META_VERSION] != version:
        return _error(
            request_id,
            -32022,
            "Unsupported protocol version",
            {"supported": [version], "requested": meta[META_VERSION]},
        )
    if method == "server/discover":
        return _reply(
            request_id,
            {
                "resultType": "complete",
                "supportedVersions": [version],
                "capabilities": {"tools": {}},
            },
        )
    if method == "tools/list":
        return _reply(request_id, {"resultType": "complete", "tools": [TOOL]})
    if method == "tools/call":
        return _reply(request_id, {"resultType": "complete", **ANSWER})
    return _error(request_id, -32601, f"Method not found: {method}")


def main() -> None:
    mode = sys.argv[1]
    for line in sys.stdin:
        if not line.strip():
            continue
        message = json.loads(line)
        if mode == "modern-only":
            response = modern(message, version=sys.argv[2])
        else:
            response = legacy(message, silent=mode == "legacy-silent")
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()

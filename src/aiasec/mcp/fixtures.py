"""Local fake transports for deterministic MCP CLI fixtures."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

from aiasec.mcp.transport import JsonObject, McpTransportError


class QueuedJsonRpcTransport:
    """In-memory JSON-RPC transport backed by queued fixture responses."""

    def __init__(self, incoming: Sequence[JsonObject]) -> None:
        self.incoming = list(incoming)
        self.sent: list[JsonObject] = []
        self.closed = False

    def send(self, message: JsonObject) -> None:
        """Record one outgoing JSON-RPC message."""

        self.sent.append(message)

    def receive(self) -> JsonObject:
        """Return the next queued JSON-RPC response."""

        if not self.incoming:
            raise McpTransportError("Fixture did not contain enough JSON-RPC responses")
        return self.incoming.pop(0)

    def close(self) -> None:
        """Mark the fake transport as closed."""

        self.closed = True


def load_jsonrpc_fixture(path: Path) -> QueuedJsonRpcTransport:
    """Load a local JSON-RPC fixture file into an in-memory transport."""

    try:
        raw_fixture = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"MCP fixture is not valid JSON: {path}") from exc

    responses = _extract_responses(raw_fixture)
    if not all(isinstance(response, dict) for response in responses):
        raise ValueError("MCP fixture responses must all be JSON objects")
    return QueuedJsonRpcTransport(cast("list[JsonObject]", responses))


def _extract_responses(raw_fixture: Any) -> list[Any]:
    if isinstance(raw_fixture, list):
        return raw_fixture
    if isinstance(raw_fixture, dict) and isinstance(raw_fixture.get("responses"), list):
        return raw_fixture["responses"]
    raise ValueError("MCP fixture must be a JSON list or an object with a responses list")

"""Dual-era MCP negotiation (spec revision 2026-07-28, stdio backward compatibility).

A dual-era client probes with `server/discover`. A DiscoverResult or a recognized modern
error means a modern server; any other error or silence means a legacy server, and only
then does the client fall back to `initialize`. These tests pin each branch.
"""

from __future__ import annotations

from typing import Any

import pytest

from aiasec.mcp.stdio import (
    LEGACY_PROTOCOL_VERSION,
    MODERN_PROTOCOL_VERSION,
    McpProtocolError,
    McpStdioAdapter,
)
from aiasec.mcp.transport import JsonObject, McpTransportTimeout

META_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
META_CLIENT = "io.modelcontextprotocol/clientInfo"


class ScriptedTransport:
    """Replays queued replies; an exception instance in the queue is raised instead."""

    def __init__(self, replies: list[Any]) -> None:
        self.replies = list(replies)
        self.sent: list[JsonObject] = []
        self.timeouts: list[float | None] = []

    def send(self, message: JsonObject, timeout: float | None = None) -> None:
        self.sent.append(message)

    def receive(self, timeout: float | None = None) -> JsonObject:
        self.timeouts.append(timeout)
        reply = self.replies.pop(0)
        if isinstance(reply, BaseException):
            raise reply
        return reply

    def close(self) -> None:
        pass


def _result(request_id: int, result: JsonObject) -> JsonObject:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: int, code: int, data: Any = None) -> JsonObject:
    error: JsonObject = {"code": code, "message": "error"}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def _discover(versions: list[str]) -> JsonObject:
    return {"resultType": "complete", "supportedVersions": versions, "capabilities": {"tools": {}}}


INITIALIZE_OK = {"protocolVersion": LEGACY_PROTOCOL_VERSION, "capabilities": {}, "serverInfo": {}}
TOOLS = {"tools": [{"name": "aiasec_agent", "inputSchema": {"type": "object"}}]}


def _methods(transport: ScriptedTransport) -> list[str]:
    return [message["method"] for message in transport.sent]


def test_modern_server_is_used_without_any_initialize_handshake() -> None:
    transport = ScriptedTransport(
        [_result(1, _discover([MODERN_PROTOCOL_VERSION])), _result(2, TOOLS)]
    )
    adapter = McpStdioAdapter(transport)

    session = adapter.connect()
    adapter.list_tools()

    assert (session.era, session.protocol_version) == ("modern", MODERN_PROTOCOL_VERSION)
    assert _methods(transport) == ["server/discover", "tools/list"]
    for message in transport.sent:
        meta = message["params"]["_meta"]
        assert meta[META_VERSION] == MODERN_PROTOCOL_VERSION
        assert meta[META_CAPABILITIES] == {}
        assert meta[META_CLIENT]["name"] == "aiasec"


def test_modern_tool_call_keeps_its_arguments_next_to_the_meta() -> None:
    transport = ScriptedTransport(
        [
            _result(1, _discover([MODERN_PROTOCOL_VERSION])),
            _result(2, {"resultType": "complete", "content": []}),
        ]
    )
    adapter = McpStdioAdapter(transport)
    adapter.connect()

    adapter.call_tool("aiasec_agent", {"inputs": []})

    params = transport.sent[1]["params"]
    assert params["name"] == "aiasec_agent"
    assert params["arguments"] == {"inputs": []}
    assert params["_meta"][META_VERSION] == MODERN_PROTOCOL_VERSION


# -32042, -32050 and -32099 sit in the MCP-reserved range but are not errors 2026-07-28
# defines (2025-11-25 uses -32042), so they identify a legacy server too.
@pytest.mark.parametrize("code", [-32601, -32602, -32600, -32000, -32042, -32050, -32099])
def test_any_non_modern_probe_error_falls_back_to_initialize(code: int) -> None:
    transport = ScriptedTransport(
        [_error(1, code), _result(2, INITIALIZE_OK), _result(3, TOOLS)]
    )
    adapter = McpStdioAdapter(transport)

    session = adapter.connect()
    adapter.list_tools()

    assert (session.era, session.protocol_version) == ("legacy", LEGACY_PROTOCOL_VERSION)
    assert _methods(transport) == [
        "server/discover",
        "initialize",
        "notifications/initialized",
        "tools/list",
    ]
    assert transport.sent[1]["params"]["protocolVersion"] == LEGACY_PROTOCOL_VERSION
    assert "params" not in transport.sent[3] or "_meta" not in transport.sent[3]["params"]


def test_silent_probe_falls_back_and_skips_the_late_discover_reply() -> None:
    transport = ScriptedTransport(
        [
            McpTransportTimeout("no reply"),
            _error(1, -32601),  # the probe's late reply arrives before the initialize reply
            _result(2, INITIALIZE_OK),
            _result(3, TOOLS),
        ]
    )
    adapter = McpStdioAdapter(transport)

    session = adapter.connect(probe_timeout=0.5)
    tools = adapter.list_tools()

    assert session.era == "legacy"
    assert tools[0]["name"] == "aiasec_agent"
    # The transport gets what is left of the probe deadline, a hair under 0.5 s.
    probe_wait = transport.timeouts[0]
    assert probe_wait is not None and 0.4 < probe_wait <= 0.5


def test_unsupported_version_with_no_mutual_version_fails_without_initialize() -> None:
    transport = ScriptedTransport(
        [_error(1, -32022, {"supported": ["2099-01-01"], "requested": MODERN_PROTOCOL_VERSION})]
    )
    adapter = McpStdioAdapter(transport)

    with pytest.raises(McpProtocolError, match="2099-01-01"):
        adapter.connect()

    assert _methods(transport) == ["server/discover"]


def test_unsupported_version_naming_a_legacy_version_uses_that_version() -> None:
    transport = ScriptedTransport(
        [
            _error(1, -32022, {"supported": ["2025-06-18"], "requested": MODERN_PROTOCOL_VERSION}),
            _result(2, {**INITIALIZE_OK, "protocolVersion": "2025-06-18"}),
        ]
    )
    adapter = McpStdioAdapter(transport)

    session = adapter.connect()

    assert (session.era, session.protocol_version) == ("legacy", "2025-06-18")
    assert transport.sent[1]["params"]["protocolVersion"] == "2025-06-18"


def test_discover_result_without_a_mutual_version_fails() -> None:
    transport = ScriptedTransport([_result(1, _discover(["2099-01-01"]))])

    with pytest.raises(McpProtocolError, match="2099-01-01"):
        McpStdioAdapter(transport).connect()


def test_other_modern_errors_are_not_mistaken_for_a_legacy_server() -> None:
    transport = ScriptedTransport([_error(1, -32021, {"requiredCapabilities": {"x": {}}})])

    with pytest.raises(McpProtocolError):
        McpStdioAdapter(transport).connect()

    assert _methods(transport) == ["server/discover"]


def test_legacy_mode_skips_the_probe() -> None:
    transport = ScriptedTransport([_result(1, INITIALIZE_OK)])

    session = McpStdioAdapter(transport).connect(mode="legacy")

    assert session.era == "legacy"
    assert _methods(transport) == ["initialize", "notifications/initialized"]


def test_modern_mode_refuses_a_legacy_server() -> None:
    transport = ScriptedTransport([_error(1, -32601)])

    with pytest.raises(McpProtocolError, match="modern"):
        McpStdioAdapter(transport).connect(mode="modern")

    assert _methods(transport) == ["server/discover"]


@pytest.mark.parametrize("result_type", ["input_required", "something_new"])
def test_a_result_that_is_not_complete_fails_closed(result_type: str) -> None:
    transport = ScriptedTransport(
        [
            _result(1, _discover([MODERN_PROTOCOL_VERSION])),
            _result(2, {"resultType": result_type, "content": []}),
        ]
    )
    adapter = McpStdioAdapter(transport)
    adapter.connect()

    with pytest.raises(McpProtocolError, match=result_type):
        adapter.call_tool("aiasec_agent", {})


def test_an_absent_result_type_counts_as_complete() -> None:
    transport = ScriptedTransport(
        [_error(1, -32601), _result(2, INITIALIZE_OK), _result(3, {"content": []})]
    )
    adapter = McpStdioAdapter(transport)
    adapter.connect()

    assert adapter.call_tool("aiasec_agent", {}) == {"content": []}

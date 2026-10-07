from __future__ import annotations

import io
import json

import pytest

from aiasec.mcp.config import McpStdioConfig
from aiasec.mcp.fixtures import QueuedJsonRpcTransport
from aiasec.mcp.stdio import McpProtocolError, McpRemoteError, McpStdioAdapter
from aiasec.mcp.transport import JsonObject, LineJsonRpcTransport, McpTransportError


class FakeTransport:
    def __init__(self, incoming: list[JsonObject]) -> None:
        self.incoming = incoming
        self.sent: list[JsonObject] = []
        self.closed = False

    def send(self, message: JsonObject, timeout: float | None = None) -> None:
        self.sent.append(message)

    def receive(self) -> JsonObject:
        if not self.incoming:
            raise AssertionError("No fake message queued")
        return self.incoming.pop(0)

    def close(self) -> None:
        self.closed = True


def test_initialize_sends_jsonrpc_request_then_initialized_notification() -> None:
    transport = FakeTransport(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "protocolVersion": "test-version",
                    "capabilities": {},
                    "serverInfo": {"name": "fake-mcp", "version": "0.1.0"},
                },
            }
        ]
    )
    adapter = McpStdioAdapter(transport)

    result = adapter.initialize(
        client_name="aiasec-test",
        client_version="0.0.0",
        protocol_version="test-version",
    )

    assert result["serverInfo"]["name"] == "fake-mcp"
    assert transport.sent == [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "test-version",
                "capabilities": {},
                "clientInfo": {"name": "aiasec-test", "version": "0.0.0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
    ]


def test_list_tools_returns_server_tools() -> None:
    transport = FakeTransport(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "tools": [
                        {
                            "name": "safe_echo",
                            "description": "Echo safe text.",
                            "inputSchema": {"type": "object"},
                        }
                    ]
                },
            }
        ]
    )
    adapter = McpStdioAdapter(transport)

    tools = adapter.list_tools()

    assert tools[0]["name"] == "safe_echo"
    assert transport.sent == [{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}]


def test_call_tool_sends_name_and_arguments() -> None:
    transport = FakeTransport(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "content": [{"type": "text", "text": "ok"}],
                    "isError": False,
                },
            }
        ]
    )
    adapter = McpStdioAdapter(transport)

    result = adapter.call_tool("safe_echo", {"message": "hello"})

    assert result["isError"] is False
    assert transport.sent == [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "safe_echo", "arguments": {"message": "hello"}},
        }
    ]


def test_request_ignores_peer_notification_before_response() -> None:
    transport = FakeTransport(
        [
            {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"pct": 50}},
            {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}},
        ]
    )
    adapter = McpStdioAdapter(transport)

    assert adapter.request("ping") == {"ok": True}


def test_request_raises_remote_error_response() -> None:
    transport = FakeTransport(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "error": {"code": -32601, "message": "Method not found"},
            }
        ]
    )
    adapter = McpStdioAdapter(transport)

    with pytest.raises(McpRemoteError) as error:
        adapter.request("unknown")

    assert error.value.code == -32601


def test_request_rejects_mismatched_response_id() -> None:
    transport = FakeTransport([{"jsonrpc": "2.0", "id": 2, "result": {}}])
    adapter = McpStdioAdapter(transport)

    with pytest.raises(McpProtocolError, match="id does not match"):
        adapter.request("ping")


def test_line_transport_writes_newline_delimited_json() -> None:
    writer = io.StringIO()
    transport = LineJsonRpcTransport(reader=io.StringIO(), writer=writer)

    transport.send({"jsonrpc": "2.0", "method": "ping", "params": {"ok": True}})

    assert json.loads(writer.getvalue()) == {
        "jsonrpc": "2.0",
        "method": "ping",
        "params": {"ok": True},
    }
    assert writer.getvalue().endswith("\n")


def test_line_transport_reads_json_object() -> None:
    transport = LineJsonRpcTransport(
        reader=io.StringIO('{"jsonrpc":"2.0","id":1,"result":{}}\n'),
        writer=io.StringIO(),
    )

    assert transport.receive() == {"jsonrpc": "2.0", "id": 1, "result": {}}


def test_line_transport_rejects_malformed_json() -> None:
    transport = LineJsonRpcTransport(reader=io.StringIO("not json\n"), writer=io.StringIO())

    with pytest.raises(McpTransportError, match="malformed JSON"):
        transport.receive()


def test_stdio_config_rejects_empty_command() -> None:
    with pytest.raises(ValueError, match="at least one"):
        McpStdioConfig.model_validate({"transport": "stdio", "command": []})


def test_queued_fixture_transport_records_sent_messages() -> None:
    transport = QueuedJsonRpcTransport([{"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}])

    transport.send({"jsonrpc": "2.0", "id": 1, "method": "ping"})

    assert transport.sent == [{"jsonrpc": "2.0", "id": 1, "method": "ping"}]
    assert transport.receive() == {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}

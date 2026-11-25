"""JSON-RPC over MCP Streamable HTTP: one POST per message, answered in its response.

A scripted server on 127.0.0.1 answers each POST with the next canned reply and records
what it received, so each test pins one rule of the transport: the headers it sends per
method, how it reads JSON and event-stream bodies, the legacy session id, 202 for a
notification, and that an error status or a redirect is never read as an answer.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest
from typer.testing import CliRunner

from aiasec.cli.app import app
from aiasec.mcp.http_transport import HttpJsonRpcTransport
from aiasec.mcp.stdio import (
    LEGACY_PROTOCOL_VERSION,
    MODERN_PROTOCOL_VERSION,
    McpProtocolError,
    McpRemoteError,
    McpStdioAdapter,
)
from aiasec.mcp.target import McpAgentTarget
from aiasec.mcp.transport import McpTransportError, McpTransportRejected, McpTransportTimeout

META_VERSION = "io.modelcontextprotocol/protocolVersion"


@dataclass
class Reply:
    status: int = 200
    body: bytes | str | dict[str, Any] | None = None
    headers: dict[str, str] = field(default_factory=dict)
    delay: float = 0.0
    # Seconds the server keeps the connection open after the body, which then has no
    # Content-Length, so only the close would end it.
    hold: float = 0.0


@dataclass
class Received:
    headers: dict[str, str]
    body: dict[str, Any]


class Script:
    def __init__(self, replies: list[Reply]) -> None:
        self.replies = list(replies)
        self.received: list[Received] = []
        self.other_hits = 0


def _handler(script: Script) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_POST(self) -> None:
            if self.path != "/mcp":
                script.other_hits += 1
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            script.received.append(Received({k.lower(): v for k, v in self.headers.items()}, body))
            reply = script.replies.pop(0)
            time.sleep(reply.delay)
            if isinstance(reply.body, dict):
                data = json.dumps(reply.body).encode()
                headers = {"Content-Type": "application/json", **reply.headers}
            else:
                data = reply.body.encode() if isinstance(reply.body, str) else reply.body or b""
                headers = reply.headers
            self.send_response(reply.status)
            for name, value in headers.items():
                self.send_header(name, value)
            if not reply.hold:
                self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            time.sleep(reply.hold)

    return Handler


@pytest.fixture
def serve() -> Iterator[Any]:
    servers: list[ThreadingHTTPServer] = []

    def start(replies: list[Reply]) -> tuple[str, Script]:
        script = Script(replies)
        server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(script))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_address[1]}/mcp", script

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


def _result(request_id: int, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _sse(*messages: dict[str, Any], prefix: str = "", hold: float = 0.0) -> Reply:
    stream = "".join(f"event: message\ndata: {json.dumps(m)}\n\n" for m in messages)
    return Reply(body=prefix + stream, headers={"Content-Type": "text/event-stream"}, hold=hold)


DISCOVER = _result(1, {"resultType": "complete", "supportedVersions": [MODERN_PROTOCOL_VERSION]})
TOOL_RESULT = {"resultType": "complete", "content": [{"type": "text", "text": "ok"}]}


def _transport(url: str, **headers: str) -> HttpJsonRpcTransport:
    return HttpJsonRpcTransport(url, headers, timeout_seconds=5)


def test_each_post_names_its_method_target_and_protocol_version(serve: Any) -> None:
    url, script = serve(
        [
            Reply(body=DISCOVER),
            Reply(body=_result(2, {"tools": []})),
            Reply(body=_result(3, TOOL_RESULT)),
        ]
    )
    adapter = McpStdioAdapter(_transport(url, Authorization="Bearer test-token"))

    adapter.connect()
    adapter.list_tools()
    adapter.call_tool("aiasec_agent", {"inputs": []})

    discover, tools_list, tools_call = (item.headers for item in script.received)
    for headers in (discover, tools_list, tools_call):
        assert headers["accept"] == "application/json, text/event-stream"
        assert headers["content-type"] == "application/json"
        assert headers["mcp-protocol-version"] == MODERN_PROTOCOL_VERSION
        assert headers["authorization"] == "Bearer test-token"
        assert "mcp-session-id" not in headers
    assert [discover["mcp-method"], tools_list["mcp-method"], tools_call["mcp-method"]] == [
        "server/discover",
        "tools/list",
        "tools/call",
    ]
    assert "mcp-name" not in discover and "mcp-name" not in tools_list
    assert tools_call["mcp-name"] == "aiasec_agent"


def test_a_resource_read_names_its_uri(serve: Any) -> None:
    url, script = serve([Reply(body=_result(1, {"contents": []}))])
    transport = _transport(url)

    transport.send(
        {"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {"uri": "file:///a"}}
    )

    assert script.received[0].headers["mcp-name"] == "file:///a"
    assert transport.receive()["result"] == {"contents": []}


def test_an_event_stream_delivers_progress_notifications_before_the_response(
    serve: Any,
) -> None:
    progress = {
        "jsonrpc": "2.0",
        "method": "notifications/progress",
        "params": {"progressToken": 1, "progress": 1},
    }
    url, _ = serve([Reply(body=DISCOVER), _sse(progress, progress, _result(2, TOOL_RESULT))])
    adapter = McpStdioAdapter(_transport(url))
    adapter.connect()

    assert adapter.call_tool("aiasec_agent", {}) == TOOL_RESULT


def test_an_event_splits_lines_only_at_cr_and_lf(serve: Any) -> None:
    # JSON may carry U+2028 unescaped; str.splitlines would cut the event there.
    message = _result(1, {"text": "a\u2028b\u2029c\x85d"})
    stream = "data: " + json.dumps(message, ensure_ascii=False) + "\r\n\r\n"
    url, _ = serve([Reply(body=stream.encode(), headers={"Content-Type": "text/event-stream"})])
    transport = _transport(url)

    transport.send({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})

    assert transport.receive() == message


def test_a_legacy_session_id_and_version_ride_on_every_later_post(serve: Any) -> None:
    initialize = _result(
        1, {"protocolVersion": LEGACY_PROTOCOL_VERSION, "capabilities": {}, "serverInfo": {}}
    )
    url, script = serve(
        [
            Reply(body=initialize, headers={"Mcp-Session-Id": "session-1"}),
            Reply(status=202),
            Reply(body=_result(2, {"tools": []})),
        ]
    )
    adapter = McpStdioAdapter(_transport(url))

    adapter.connect(mode="legacy")
    adapter.list_tools()

    first, initialized, tools_list = (item.headers for item in script.received)
    assert "mcp-session-id" not in first
    for headers in (initialized, tools_list):
        assert headers["mcp-session-id"] == "session-1"
        assert headers["mcp-protocol-version"] == LEGACY_PROTOCOL_VERSION
    assert script.received[1].body["method"] == "notifications/initialized"


def test_an_accepted_notification_has_no_answer(serve: Any) -> None:
    url, _ = serve([Reply(status=202)])
    transport = _transport(url)

    transport.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    with pytest.raises(McpTransportTimeout):
        transport.receive()


def test_a_refused_notification_fails(serve: Any) -> None:
    url, _ = serve([Reply(status=400)])

    with pytest.raises(McpTransportRejected, match="HTTP 400"):
        _transport(url).send({"jsonrpc": "2.0", "method": "notifications/initialized"})


def test_an_error_status_with_a_json_rpc_error_reaches_the_adapter(serve: Any) -> None:
    error = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "bad params"}}
    url, _ = serve([Reply(status=400, body=error)])

    with pytest.raises(McpRemoteError, match="-32602"):
        McpStdioAdapter(_transport(url)).request("tools/list")


@pytest.mark.parametrize(
    "reply",
    [
        Reply(status=400),
        Reply(status=404, body="<html>not here</html>", headers={"Content-Type": "text/html"}),
        Reply(status=500, body={"jsonrpc": "2.0", "id": None, "error": {"code": 1, "message": ""}}),
        Reply(status=202),
    ],
    ids=["empty", "html", "error-for-no-request", "accepted-request"],
)
def test_an_error_status_without_an_answer_to_the_request_is_rejected(
    serve: Any, reply: Reply
) -> None:
    url, _ = serve([reply])

    with pytest.raises(McpTransportRejected, match=f"HTTP {reply.status}"):
        _transport(url).send({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})


def test_a_redirect_is_never_followed(serve: Any) -> None:
    url, script = serve([Reply(status=307, headers={"Location": "/elsewhere"})])

    with pytest.raises(McpTransportRejected, match="HTTP 307"):
        _transport(url, Authorization="Bearer test-token").send(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        )

    assert script.other_hits == 0


def test_a_success_body_that_is_not_json_rpc_fails(serve: Any) -> None:
    url, _ = serve([Reply(body="<html></html>", headers={"Content-Type": "text/html"})])

    with pytest.raises(McpTransportError, match="not JSON-RPC"):
        _transport(url).send({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})


def test_a_slow_server_times_out(serve: Any) -> None:
    url, _ = serve([Reply(body=_result(1, {}), delay=2)])
    transport = HttpJsonRpcTransport(url, {}, timeout_seconds=0.3)

    with pytest.raises(McpTransportTimeout):
        transport.send({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})


def test_auto_falls_back_to_initialize_when_a_legacy_server_refuses_the_probe(
    serve: Any,
) -> None:
    # A legacy Streamable HTTP server answers a request without a session with 400.
    initialize = _result(
        2, {"protocolVersion": LEGACY_PROTOCOL_VERSION, "capabilities": {}, "serverInfo": {}}
    )
    url, script = serve([Reply(status=400), Reply(body=initialize), Reply(status=202)])

    session = McpStdioAdapter(_transport(url)).connect()

    assert session.era == "legacy"
    assert [item.body["method"] for item in script.received] == [
        "server/discover",
        "initialize",
        "notifications/initialized",
    ]


def test_a_server_request_inside_the_stream_is_not_answered_and_fails(serve: Any) -> None:
    # The legacy way to elicit input; aiasec answers input only through input_required.
    request = {"jsonrpc": "2.0", "id": "srv-1", "method": "elicitation/create", "params": {}}
    url, _ = serve([Reply(body=DISCOVER), _sse(request, _result(2, TOOL_RESULT))])
    adapter = McpStdioAdapter(_transport(url))
    adapter.connect()

    with pytest.raises(McpProtocolError):
        adapter.call_tool("aiasec_agent", {})


# MCP 2025-11-25 (Streamable HTTP, sending messages, item 6): the server SHOULD first send
# an event with an id and an empty data field, to prime the client to reconnect.
PRIMING_EVENTS = ["id: 0\ndata: \n\n", "id: 0\ndata:\n\n"]


@pytest.mark.parametrize("priming", PRIMING_EVENTS, ids=["data-space", "bare-data"])
def test_an_event_with_empty_data_is_skipped_before_a_tool_result(
    serve: Any, priming: str
) -> None:
    url, _ = serve([Reply(body=DISCOVER), _sse(_result(2, TOOL_RESULT), prefix=priming)])
    adapter = McpStdioAdapter(_transport(url))
    adapter.connect()

    assert adapter.call_tool("aiasec_agent", {}) == TOOL_RESULT


@pytest.mark.parametrize("priming", PRIMING_EVENTS, ids=["data-space", "bare-data"])
def test_an_event_with_empty_data_is_skipped_before_a_legacy_initialize_result(
    serve: Any, priming: str
) -> None:
    initialize = _result(
        1, {"protocolVersion": LEGACY_PROTOCOL_VERSION, "capabilities": {}, "serverInfo": {}}
    )
    url, _ = serve([_sse(initialize, prefix=priming), Reply(status=202)])

    session = McpStdioAdapter(_transport(url)).connect(mode="legacy")

    assert session.era == "legacy"
    assert session.protocol_version == LEGACY_PROTOCOL_VERSION


def test_an_event_stream_left_open_after_the_answer_ends_the_request(serve: Any) -> None:
    # Closing the stream after the response is only a SHOULD (2025-11-25).
    url, _ = serve([_sse(_result(1, {"tools": []}), hold=4)])
    transport = HttpJsonRpcTransport(url, {}, timeout_seconds=2)

    started = time.monotonic()
    transport.send({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})

    assert time.monotonic() - started < 1.5
    assert transport.receive() == _result(1, {"tools": []})


def test_an_event_stream_left_open_without_the_answer_still_times_out(serve: Any) -> None:
    progress = {"jsonrpc": "2.0", "method": "notifications/progress", "params": {}}
    url, _ = serve([_sse(progress, _result(7, {}), hold=3)])
    transport = HttpJsonRpcTransport(url, {}, timeout_seconds=0.5)

    with pytest.raises(McpTransportTimeout):
        transport.send({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})


HOSTILE_VERSION = "2025-11-25\x1b]0;pwned\x07\x1b[2J"


def test_a_legacy_server_naming_a_version_aiasec_does_not_speak_is_refused(
    serve: Any,
) -> None:
    initialize = _result(
        2, {"protocolVersion": HOSTILE_VERSION, "capabilities": {}, "serverInfo": {}}
    )
    url, script = serve([Reply(status=400), Reply(body=initialize), Reply(status=202)])

    with pytest.raises(McpProtocolError, match="protocol version"):
        McpStdioAdapter(_transport(url)).connect()

    assert [item.body["method"] for item in script.received] == ["server/discover", "initialize"]


def test_a_hostile_legacy_version_never_reaches_the_terminal(serve: Any, tmp_path: Any) -> None:
    initialize = _result(
        2, {"protocolVersion": HOSTILE_VERSION, "capabilities": {}, "serverInfo": {}}
    )
    tools = _result(3, {"tools": [{"name": "aiasec_agent", "inputSchema": {"type": "object"}}]})
    url, _ = serve(
        [Reply(status=400), Reply(body=initialize), Reply(status=202), Reply(body=tools)]
        + [Reply(body=_result(request_id, TOOL_RESULT)) for request_id in range(4, 8)]
    )
    target = tmp_path / "target.json"
    target.write_text(json.dumps({"transport": "mcp-http", "url": url}), encoding="utf-8")

    result = CliRunner().invoke(
        app,
        ["run", "--target", str(target), "--execute", "--output", str(tmp_path / "r.sarif"),
         "--probe-id", "direct-injection-001"],
    )  # fmt: skip

    assert result.exit_code == 2, result.output
    assert "\x1b" not in result.output and "\x07" not in result.output
    assert "Target speaks" not in result.output
    assert "protocol version" in result.output


def test_the_target_announcement_writes_control_characters_as_escapes(
    serve: Any, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(McpAgentTarget, "label", property(lambda _: "MCP \x1b[2J\u202e"))
    tools = _result(2, {"tools": [{"name": "aiasec_agent", "inputSchema": {"type": "object"}}]})
    url, _ = serve(
        [Reply(body=DISCOVER), Reply(body=tools)]
        + [Reply(body=_result(request_id, TOOL_RESULT)) for request_id in range(3, 7)]
    )
    target = tmp_path / "target.json"
    target.write_text(json.dumps({"transport": "mcp-http", "url": url}), encoding="utf-8")

    result = CliRunner().invoke(
        app,
        ["run", "--target", str(target), "--execute", "--output", str(tmp_path / "r.sarif"),
         "--probe-id", "direct-injection-001"],
    )  # fmt: skip

    assert "Target speaks MCP \\u{001b}[2J\\u{202e} over HTTP." in result.output
    assert "\x1b" not in result.output and "\u202e" not in result.output

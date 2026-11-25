"""JSON-RPC over MCP Streamable HTTP, behind the same transport interface as stdio.

Each message is one POST to the server's endpoint. A request's answer comes back in
that POST's response, as a JSON body or as a `text/event-stream` whose last JSON-RPC
response event carries it; a notification gets `202 Accepted`. The adapter that speaks
MCP over stdio therefore speaks it over HTTP unchanged: send() posts and queues every
message the response carried, receive() hands them out in order.

Revision 2026-07-28 has no sessions: each POST names its method in `Mcp-Method`, the
tool, resource or prompt in `Mcp-Name`, and the protocol version in
`MCP-Protocol-Version`. A legacy server (2025-11-25 and earlier) answers `initialize`
with an `Mcp-Session-Id`, which every later POST echoes. Redirects are never followed,
so a credential header cannot reach another host (aiasec.httptarget.post_json).
"""

from __future__ import annotations

import json
from collections import deque
from collections.abc import Mapping
from typing import Any

from aiasec.httptarget import HttpTargetError, connection_for, post_json, request_path
from aiasec.mcp.transport import JsonObject, McpTransportError, McpTransportTimeout

META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
# Methods whose POST also names their target in Mcp-Name.
NAMED_METHODS = {"tools/call": "name", "prompts/get": "name", "resources/read": "uri"}


class HttpJsonRpcTransport:
    """One POST per JSON-RPC message to a Streamable HTTP endpoint."""

    def __init__(self, url: str, headers: dict[str, str], timeout_seconds: float) -> None:
        self._url = url
        self._path = request_path(url)
        self._headers = headers
        self._timeout = timeout_seconds
        self._received: deque[JsonObject] = deque()
        self._session_id: str | None = None
        self._legacy_version: str | None = None

    def send(self, message: JsonObject, timeout: float | None = None) -> None:
        """POST the message and queue every JSON-RPC message its response carried."""

        deadline = timeout if timeout is not None else self._timeout
        try:
            status, body, headers = post_json(
                connection_for(self._url, deadline),
                self._path,
                message,
                self._request_headers(message),
                deadline,
            )
        except HttpTargetError as exc:
            if "timed out" in str(exc):
                raise McpTransportTimeout(str(exc)) from exc
            raise McpTransportError(str(exc)) from exc
        if status == 202 and "id" not in message:
            return  # an accepted notification has no answer
        messages = _messages(body, headers.get("content-type", ""))
        if status != 200 and not any("error" in item for item in messages):
            raise McpTransportError(
                f"MCP server answered HTTP {status} to {message.get('method')!r}"
            )
        self._remember_legacy_session(message, messages, headers)
        self._received.extend(messages)

    def receive(self, timeout: float | None = None) -> JsonObject:
        """The next message from earlier responses; an empty queue means no answer came."""

        if not self._received:
            raise McpTransportTimeout("MCP server sent no JSON-RPC message for the request")
        return self._received.popleft()

    def close(self) -> None:
        """Nothing stays open between requests."""

    def _request_headers(self, message: JsonObject) -> dict[str, str]:
        method = str(message.get("method", ""))
        raw_params = message.get("params")
        params: dict[str, Any] = raw_params if isinstance(raw_params, dict) else {}
        headers = {
            **self._headers,
            "Accept": "application/json, text/event-stream",
            "Mcp-Method": method,
        }
        name_field = NAMED_METHODS.get(method)
        if name_field and isinstance(params.get(name_field), str):
            headers["Mcp-Name"] = params[name_field]
        raw_meta = params.get("_meta")
        meta: dict[str, Any] = raw_meta if isinstance(raw_meta, dict) else {}
        version = meta.get(META_PROTOCOL_VERSION) or self._legacy_version
        if isinstance(version, str):
            headers["MCP-Protocol-Version"] = version
        if self._session_id is not None:
            headers["Mcp-Session-Id"] = self._session_id
        return headers

    def _remember_legacy_session(
        self, sent: JsonObject, received: list[JsonObject], headers: Mapping[str, str]
    ) -> None:
        """After a legacy initialize, later POSTs carry its version and session id."""

        if sent.get("method") != "initialize":
            return
        session = headers.get("mcp-session-id")
        if session:
            self._session_id = session
        for item in received:
            result = item.get("result")
            if isinstance(result, dict) and isinstance(result.get("protocolVersion"), str):
                self._legacy_version = result["protocolVersion"]


def _messages(body: bytes, content_type: str) -> list[JsonObject]:
    """The JSON-RPC messages in a response body: JSON, or the data of each SSE event."""

    if not body.strip():
        return []
    try:
        if content_type.split(";")[0].strip().lower() == "text/event-stream":
            parsed: list[Any] = [json.loads(data) for data in _event_data(body.decode("utf-8"))]
        else:
            parsed = [json.loads(body)]
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise McpTransportError("MCP server sent a response that is not JSON-RPC") from exc
    messages: list[JsonObject] = []
    for item in parsed:
        for message in item if isinstance(item, list) else [item]:
            if not isinstance(message, dict):
                raise McpTransportError("MCP server sent a JSON-RPC message that is not an object")
            messages.append(message)
    return messages


def _event_data(stream: str) -> list[str]:
    """The data of each server-sent event, its `data:` lines joined by newlines."""

    events: list[str] = []
    data: list[str] = []
    for line in stream.splitlines():
        if not line:
            if data:
                events.append("\n".join(data))
                data = []
        elif line.startswith("data:"):
            data.append(line[5:].removeprefix(" "))
    if data:
        events.append("\n".join(data))
    return events

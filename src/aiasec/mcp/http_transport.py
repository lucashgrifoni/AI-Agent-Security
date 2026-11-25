"""JSON-RPC over MCP Streamable HTTP, behind the same transport interface as stdio.

Each message is one POST to the server's endpoint. A request's answer comes back in
that POST's response, as a JSON body or as a `text/event-stream` event; the event that
answers ends the read, even if the server keeps the stream open. A notification gets
`202 Accepted`. The adapter that speaks MCP over stdio therefore speaks it over HTTP
unchanged: send() posts and queues every message the response carried, receive() hands
them out in order.

Revision 2026-07-28 has no sessions: each POST names its method in `Mcp-Method`, the
tool, resource or prompt in `Mcp-Name`, and the protocol version in
`MCP-Protocol-Version`. A legacy server (2025-11-25 and earlier) answers `initialize`
with an `Mcp-Session-Id`, which every later POST echoes. Redirects are never followed,
so a credential header cannot reach another host (aiasec.httptarget.post_json).
"""

from __future__ import annotations

import json
import re
from collections import deque
from collections.abc import Mapping
from typing import Any

from aiasec.httptarget import (
    HttpTargetError,
    HttpTargetTimeout,
    connection_for,
    post_json,
    request_path,
)
from aiasec.mcp.transport import (
    JsonObject,
    McpTransportError,
    McpTransportRejected,
    McpTransportTimeout,
)

META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
# Methods whose POST also names their target in Mcp-Name.
NAMED_METHODS = {"tools/call": "name", "prompts/get": "name", "resources/read": "uri"}
# Headers this transport sets on every POST; a target config may not set them too.
PROTOCOL_HEADERS = frozenset(
    {"accept", "content-type", "mcp-method", "mcp-name", "mcp-protocol-version", "mcp-session-id"}
)
# An event stream ends a line at CR LF, LF or CR only; str.splitlines would also split
# at characters JSON may carry unescaped, such as U+2028.
_SSE_LINE_BREAK = re.compile(r"\r\n|\r|\n")
# An event ends at a blank line: two line breaks in a row.
_SSE_EVENT_END = re.compile(rb"(?:\r\n|\r|\n)(?:\r\n|\r|\n)")
# The longest event end is 4 bytes; a new search starts this far back.
_SSE_EVENT_END_OVERLAP = 3


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
                complete=_AnswerWatch(message["id"]) if "id" in message else None,
            )
        except HttpTargetTimeout as exc:
            raise McpTransportTimeout(str(exc)) from exc
        except HttpTargetError as exc:
            raise McpTransportError(str(exc)) from exc
        if "id" not in message:
            # A notification is accepted with 202 (or 200) and has no answer.
            if status not in (200, 202):
                raise _refusal(status, message)
            return
        if status == 200:
            messages = _messages(body, headers.get("content-type", ""))
        else:
            # An error status counts only with a JSON-RPC error answering this request,
            # which the adapter then raises as the server's error.
            messages = _lenient_messages(body, headers.get("content-type", ""))
            if not any(_answers_with_error(item, message["id"]) for item in messages):
                raise _refusal(status, message)
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


class _AnswerWatch:
    """Reads an event stream as it arrives and says when it has answered one request.

    A server SHOULD close the stream after the answer, but may keep it open; reading on
    to the end would then wait out the deadline with the answer already in hand.
    """

    def __init__(self, request_id: Any) -> None:
        self._request_id = request_id
        self._pending = bytearray()  # received bytes after the last whole event

    def __call__(self, headers: Mapping[str, str], chunk: bytes) -> bool:
        if not _is_event_stream(headers.get("content-type", "")):
            return False
        searched = len(self._pending)
        self._pending += chunk
        end = _events_end(self._pending, start=max(0, searched - _SSE_EVENT_END_OVERLAP))
        if not end:
            return False
        events = bytes(self._pending[:end])
        del self._pending[:end]
        try:
            messages = _messages(events, "text/event-stream")
        except McpTransportError:
            return True  # reading on cannot repair it; the full parse reports it
        return any(_answers(item, self._request_id) for item in messages)


def _answers(message: JsonObject, request_id: Any) -> bool:
    """Whether a message is the response to a request (a server request is not)."""

    return message.get("id") == request_id and "method" not in message


def _is_event_stream(content_type: str) -> bool:
    return content_type.split(";")[0].strip().lower() == "text/event-stream"


def _messages(body: bytes, content_type: str) -> list[JsonObject]:
    """The JSON-RPC messages in a response body: JSON, or the data of each SSE event."""

    if not body.strip():
        return []
    try:
        if _is_event_stream(content_type):
            parsed: list[Any] = [json.loads(data) for data in _event_data(body)]
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


def _refusal(status: int, sent: JsonObject) -> McpTransportRejected:
    redirect = "; aiasec does not follow redirects" if 300 <= status < 400 else ""
    return McpTransportRejected(
        f"MCP server answered HTTP {status} to {sent.get('method')!r}{redirect}"
    )


def _lenient_messages(body: bytes, content_type: str) -> list[JsonObject]:
    """The messages of an error response, or none when its body is not JSON-RPC."""

    try:
        return _messages(body, content_type)
    except McpTransportError:
        return []


def _answers_with_error(message: JsonObject, request_id: Any) -> bool:
    return _answers(message, request_id) and "error" in message


def _events_end(stream: bytes | bytearray, start: int = 0) -> int:
    """Where the last whole event in the stream ends (searching from `start`), or 0."""

    end = 0
    for match in _SSE_EVENT_END.finditer(stream, start):
        end = match.end()
    return end


def _event_data(stream: bytes) -> list[str]:
    """The data of each whole server-sent event, its `data:` lines joined by newlines.

    An event ends at a blank line, so one still open when the stream ends is dropped,
    as the SSE standard does. An event without data carries no message and is skipped,
    such as the event with only an id that a 2025-11-25 server may send first.
    """

    events: list[str] = []
    data: list[str] = []
    for line in _SSE_LINE_BREAK.split(stream[: _events_end(stream)].decode("utf-8")):
        if not line:
            joined = "\n".join(data)
            if joined.strip():
                events.append(joined)
            data = []
        elif line.startswith("data:"):
            data.append(line[5:].removeprefix(" "))
    return events

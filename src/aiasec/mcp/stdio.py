"""Minimal MCP client adapter over a JSON-RPC stdio transport."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from aiasec import __version__
from aiasec.mcp.transport import JsonObject, JsonRpcTransport

JSONRPC_VERSION = "2.0"
DEFAULT_MCP_PROTOCOL_VERSION = "2024-11-05"


class McpProtocolError(RuntimeError):
    """Raised when a peer sends an invalid or unexpected JSON-RPC message."""


class McpRemoteError(RuntimeError):
    """Raised when the MCP peer returns a JSON-RPC error response."""

    def __init__(self, code: int, message: str, data: Any | None = None) -> None:
        self.code = code
        self.data = data
        super().__init__(f"MCP peer returned error {code}: {message}")


class McpStdioAdapter:
    """Small MCP adapter that speaks JSON-RPC through an injected transport."""

    def __init__(self, transport: JsonRpcTransport, *, first_request_id: int = 1) -> None:
        if first_request_id < 1:
            raise ValueError("first_request_id must be positive")
        self._transport = transport
        self._next_request_id = first_request_id

    def initialize(
        self,
        *,
        client_name: str = "aiasec",
        client_version: str = __version__,
        protocol_version: str = DEFAULT_MCP_PROTOCOL_VERSION,
        capabilities: Mapping[str, Any] | None = None,
    ) -> JsonObject:
        """Send MCP initialize and initialized messages, returning server info."""

        result = _expect_object(
            self.request(
                "initialize",
                {
                    "protocolVersion": protocol_version,
                    "capabilities": dict(capabilities or {}),
                    "clientInfo": {
                        "name": client_name,
                        "version": client_version,
                    },
                },
            ),
            "initialize result",
        )
        self.notify("notifications/initialized")
        return result

    def list_tools(self) -> list[JsonObject]:
        """Return tools exposed by the MCP server."""

        result = _expect_object(self.request("tools/list"), "tools/list result")
        tools = result.get("tools")
        if not isinstance(tools, list):
            raise McpProtocolError("tools/list result must contain a tools list")
        if not all(isinstance(tool, dict) for tool in tools):
            raise McpProtocolError("tools/list result contains a non-object tool")
        return cast("list[JsonObject]", tools)

    def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any] | None = None,
    ) -> JsonObject:
        """Call one MCP tool and return the raw JSON-RPC result object."""

        if not name.strip():
            raise ValueError("tool name must not be empty")
        return _expect_object(
            self.request(
                "tools/call",
                {
                    "name": name,
                    "arguments": dict(arguments or {}),
                },
            ),
            "tools/call result",
        )

    def request(self, method: str, params: Mapping[str, Any] | None = None) -> Any:
        """Send one JSON-RPC request and wait for its matching response."""

        request_id = self._next_request_id
        self._next_request_id += 1
        self._transport.send(_jsonrpc_message(method, params, request_id=request_id))
        return self._receive_response(request_id)

    def notify(self, method: str, params: Mapping[str, Any] | None = None) -> None:
        """Send one JSON-RPC notification without waiting for a response."""

        self._transport.send(_jsonrpc_message(method, params))

    def close(self) -> None:
        """Close the underlying transport."""

        self._transport.close()

    def _receive_response(self, expected_id: int) -> Any:
        while True:
            response = self._transport.receive()
            if _is_peer_notification(response):
                continue
            return _parse_response(response, expected_id)


def _jsonrpc_message(
    method: str,
    params: Mapping[str, Any] | None,
    *,
    request_id: int | None = None,
) -> JsonObject:
    if not method.strip():
        raise ValueError("method must not be empty")

    message: JsonObject = {
        "jsonrpc": JSONRPC_VERSION,
        "method": method,
    }
    if request_id is not None:
        message["id"] = request_id
    if params is not None:
        message["params"] = dict(params)
    return message


def _is_peer_notification(message: JsonObject) -> bool:
    return (
        message.get("jsonrpc") == JSONRPC_VERSION
        and "id" not in message
        and isinstance(message.get("method"), str)
    )


def _parse_response(response: JsonObject, expected_id: int) -> Any:
    if response.get("jsonrpc") != JSONRPC_VERSION:
        raise McpProtocolError("JSON-RPC response has an invalid version")
    if response.get("id") != expected_id:
        raise McpProtocolError("JSON-RPC response id does not match the active request")

    has_result = "result" in response
    has_error = "error" in response
    if has_result == has_error:
        raise McpProtocolError("JSON-RPC response must contain exactly one of result or error")
    if has_error:
        _raise_remote_error(response["error"])
    return response["result"]


def _raise_remote_error(error: Any) -> None:
    if not isinstance(error, dict):
        raise McpProtocolError("JSON-RPC error must be an object")

    code = error.get("code")
    message = error.get("message")
    if not isinstance(code, int) or isinstance(code, bool) or not isinstance(message, str):
        raise McpProtocolError("JSON-RPC error requires integer code and string message")
    raise McpRemoteError(code=code, message=message, data=error.get("data"))


def _expect_object(value: Any, label: str) -> JsonObject:
    if not isinstance(value, dict):
        raise McpProtocolError(f"{label} must be a JSON object")
    return cast("JsonObject", value)

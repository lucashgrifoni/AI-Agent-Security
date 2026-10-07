"""Minimal MCP client adapter over a JSON-RPC stdio transport.

Speaks both protocol eras defined by MCP 2026-07-28 (basic/versioning):

- modern (2026-07-28): no handshake; every request carries the protocol version and
  client capabilities in ``params._meta``;
- legacy (2025-11-25 and earlier): an ``initialize`` handshake opens the session.

``connect()`` follows the stdio backward-compatibility rules: probe with
``server/discover``; a DiscoverResult or a recognized modern error means a modern
server, any other error or silence means a legacy one.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, cast

from aiasec import __version__
from aiasec.mcp.transport import JsonObject, JsonRpcTransport, McpTransportTimeout

JSONRPC_VERSION = "2.0"
MODERN_PROTOCOL_VERSION = "2026-07-28"
# Newest first. The fallback handshake offers the first; a legacy server answers with
# the version it speaks.
LEGACY_PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
LEGACY_PROTOCOL_VERSION = LEGACY_PROTOCOL_VERSIONS[0]
DEFAULT_MCP_PROTOCOL_VERSION = LEGACY_PROTOCOL_VERSION

META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"

UNSUPPORTED_PROTOCOL_VERSION = -32022
# The errors MCP 2026-07-28 defines: header mismatch, missing required client
# capability, unsupported protocol version. The rest of -32020..-32099 is reserved,
# and earlier revisions took codes from it too (2025-11-25 defines -32042), so an
# unrecognized code there does not identify a modern server and leads to the fallback.
MODERN_ERROR_CODES = frozenset({-32020, -32021, UNSUPPORTED_PROTOCOL_VERSION})
DEFAULT_PROBE_TIMEOUT_SECONDS = 5.0

Era = Literal["modern", "legacy"]
ConnectMode = Literal["auto", "modern", "legacy"]


class McpProtocolError(RuntimeError):
    """Raised when a peer sends an invalid or unexpected JSON-RPC message."""


class McpRemoteError(RuntimeError):
    """Raised when the MCP peer returns a JSON-RPC error response."""

    def __init__(self, code: int, message: str, data: Any | None = None) -> None:
        self.code = code
        self.data = data
        super().__init__(f"MCP peer returned error {code}: {message}")


@dataclass(frozen=True)
class McpSession:
    """The protocol era and version agreed with one server."""

    era: Era
    protocol_version: str
    server_info: JsonObject


class McpStdioAdapter:
    """Small MCP adapter that speaks JSON-RPC through an injected transport."""

    def __init__(
        self,
        transport: JsonRpcTransport,
        *,
        first_request_id: int = 1,
        request_timeout: float | None = None,
    ) -> None:
        if first_request_id < 1:
            raise ValueError("first_request_id must be positive")
        if request_timeout is not None and request_timeout <= 0:
            raise ValueError("request_timeout must be positive")
        self._transport = transport
        self._request_timeout = request_timeout
        self._next_request_id = first_request_id
        self._abandoned_ids: set[int] = set()
        self._client_info: JsonObject = {"name": "aiasec", "version": __version__}
        self.session: McpSession | None = None

    def connect(
        self,
        *,
        mode: ConnectMode = "auto",
        probe_timeout: float | None = DEFAULT_PROBE_TIMEOUT_SECONDS,
    ) -> McpSession:
        """Agree on a protocol era and version with the server."""

        if mode == "legacy":
            return self._open_legacy(LEGACY_PROTOCOL_VERSION)

        try:
            result = self._exchange(
                "server/discover",
                {},
                meta_version=MODERN_PROTOCOL_VERSION,
                timeout=probe_timeout,
            )
        except McpRemoteError as exc:
            if exc.code == UNSUPPORTED_PROTOCOL_VERSION:
                return self._open_supported(_supported_from_error(exc), mode)
            if exc.code in MODERN_ERROR_CODES:
                raise McpProtocolError(f"Server rejected the discovery probe: {exc}") from exc
            return self._fall_back_to_legacy(mode, reason=str(exc))
        except McpTransportTimeout as exc:
            return self._fall_back_to_legacy(mode, reason=str(exc))

        discovered = _expect_object(result, "server/discover result")
        versions = discovered.get("supportedVersions")
        if not isinstance(versions, list) or not all(isinstance(v, str) for v in versions):
            raise McpProtocolError("server/discover result must list supportedVersions")
        return self._open_supported(versions, mode, discovered)

    def initialize(
        self,
        *,
        client_name: str = "aiasec",
        client_version: str = __version__,
        protocol_version: str = DEFAULT_MCP_PROTOCOL_VERSION,
        capabilities: Mapping[str, Any] | None = None,
    ) -> JsonObject:
        """Send the legacy initialize handshake and return the server's result."""

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

        result = _expect_complete(self.request("tools/list"), "tools/list result")
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
        return _expect_complete(
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
        """Send one JSON-RPC request and wait for its matching response.

        On a modern session every request carries the per-request ``_meta`` fields.
        With a ``request_timeout``, the response must arrive within that many seconds
        of sending the request.
        """

        meta_version = None
        if self.session is not None and self.session.era == "modern":
            meta_version = self.session.protocol_version
        return self._exchange(
            method, params, meta_version=meta_version, timeout=self._request_timeout
        )

    def notify(self, method: str, params: Mapping[str, Any] | None = None) -> None:
        """Send one JSON-RPC notification without waiting for a response."""

        self._transport.send(_jsonrpc_message(method, params))

    def close(self) -> None:
        """Close the underlying transport."""

        self._transport.close()

    def _open_supported(
        self,
        versions: list[str],
        mode: ConnectMode,
        discovered: JsonObject | None = None,
    ) -> McpSession:
        if MODERN_PROTOCOL_VERSION in versions:
            server_info = _server_info(discovered or {})
            self.session = McpSession("modern", MODERN_PROTOCOL_VERSION, server_info)
            return self.session
        legacy = next((v for v in LEGACY_PROTOCOL_VERSIONS if v in versions), None)
        if legacy is None or mode == "modern":
            raise McpProtocolError(
                f"No mutually supported MCP protocol version: the server supports {versions}, "
                f"aiasec supports {[MODERN_PROTOCOL_VERSION, *LEGACY_PROTOCOL_VERSIONS]}"
            )
        # The server named a handshake-based version it supports; speak that one.
        return self._open_legacy(legacy)

    def _fall_back_to_legacy(self, mode: ConnectMode, *, reason: str) -> McpSession:
        if mode == "modern":
            raise McpProtocolError(
                f"Server did not answer server/discover as a modern MCP server: {reason}"
            )
        return self._open_legacy(LEGACY_PROTOCOL_VERSION)

    def _open_legacy(self, protocol_version: str) -> McpSession:
        result = self.initialize(protocol_version=protocol_version)
        agreed = result.get("protocolVersion")
        server_info = result.get("serverInfo")
        self.session = McpSession(
            "legacy",
            agreed if isinstance(agreed, str) else protocol_version,
            server_info if isinstance(server_info, dict) else {},
        )
        return self.session

    def _exchange(
        self,
        method: str,
        params: Mapping[str, Any] | None,
        *,
        meta_version: str | None,
        timeout: float | None = None,
    ) -> Any:
        if meta_version is not None:
            params = {**(params or {}), "_meta": self._request_meta(params, meta_version)}
        request_id = self._next_request_id
        self._next_request_id += 1
        self._transport.send(_jsonrpc_message(method, params, request_id=request_id))
        try:
            return self._receive_response(request_id, timeout)
        except McpTransportTimeout:
            # A late reply to this request must not be read as the reply to the next one.
            self._abandoned_ids.add(request_id)
            raise

    def _request_meta(self, params: Mapping[str, Any] | None, version: str) -> JsonObject:
        existing = (params or {}).get("_meta")
        meta: JsonObject = dict(existing) if isinstance(existing, dict) else {}
        meta[META_PROTOCOL_VERSION] = version
        meta[META_CLIENT_INFO] = self._client_info
        meta[META_CLIENT_CAPABILITIES] = {}
        return meta

    def _receive_response(self, expected_id: int, timeout: float | None) -> Any:
        # One deadline for the whole exchange: a notification or a late reply to an
        # abandoned request does not restart it, so a chatty peer cannot hold the
        # request open forever.
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            if deadline is None:
                response = self._transport.receive()
            else:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise McpTransportTimeout(
                        f"Target did not answer request {expected_id} within {timeout} seconds"
                    )
                response = self._transport.receive(timeout=remaining)
            if _is_peer_notification(response):
                continue
            if response.get("id") in self._abandoned_ids:
                self._abandoned_ids.discard(response.get("id"))
                continue
            return _parse_response(response, expected_id)


def _supported_from_error(exc: McpRemoteError) -> list[str]:
    data = exc.data if isinstance(exc.data, dict) else {}
    supported = data.get("supported")
    if not isinstance(supported, list) or not all(isinstance(v, str) for v in supported):
        raise McpProtocolError(
            "UnsupportedProtocolVersionError must list the supported versions"
        ) from exc
    return supported


def _server_info(discovered: JsonObject) -> JsonObject:
    meta = discovered.get("_meta")
    info = meta.get("io.modelcontextprotocol/serverInfo") if isinstance(meta, dict) else None
    return info if isinstance(info, dict) else {}


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


def _expect_complete(value: Any, label: str) -> JsonObject:
    """Accept a final result only.

    Results from earlier revisions carry no resultType and count as complete. A
    multi round-trip ``input_required`` result or an unknown type is not handled by
    aiasec, so it fails instead of being read as an empty answer.
    """

    result = _expect_object(value, label)
    result_type = result.get("resultType", "complete")
    if result_type != "complete":
        raise McpProtocolError(f"{label} has resultType {result_type!r}; aiasec needs 'complete'")
    return result

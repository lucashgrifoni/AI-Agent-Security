"""MCP adapter primitives for aiasec target integrations."""

from aiasec.mcp.stdio import McpProtocolError, McpRemoteError, McpStdioAdapter
from aiasec.mcp.transport import (
    JsonObject,
    JsonRpcTransport,
    LineJsonRpcTransport,
    McpTransportError,
    ProcessRunner,
    StdioProcessRunner,
)

__all__ = [
    "JsonObject",
    "JsonRpcTransport",
    "LineJsonRpcTransport",
    "McpProtocolError",
    "McpRemoteError",
    "McpStdioAdapter",
    "McpTransportError",
    "ProcessRunner",
    "StdioProcessRunner",
]

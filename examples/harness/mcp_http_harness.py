"""MCP Streamable HTTP harness template: put your agent behind aiasec's target contract.

Copy this file and mcp_stdio_harness.py (its request handling) into your project,
replace `run_agent` in mcp_stdio_harness.py with a call into your agent (or pass your
agent function to `main`), run this file, and point an aiasec target config at it:

    python mcp_http_harness.py --port 8766
    {"transport": "mcp-http", "url": "http://127.0.0.1:8766/mcp"}

The harness is an MCP server with one endpoint, POST /mcp, that exposes one tool,
`aiasec_agent` (docs/target-contract.md). Each JSON-RPC request gets its response as
JSON; a notification gets 202 Accepted; GET and DELETE get 405, since the harness
keeps no session and opens no event stream. It speaks both MCP eras, as the stdio
template does. The server listens on 127.0.0.1 only and refuses a browser request
from another origin.

Standard library only; Python 3.10 or newer.
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from mcp_stdio_harness import Agent, handle, run_agent

ENDPOINT = "/mcp"
DEFAULT_PORT = 8766
MAX_REQUEST_BYTES = 1_048_576
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


def make_handler(agent: Agent, server_name: str) -> type[BaseHTTPRequestHandler]:
    """Build the request handler that serves POST /mcp with `agent`."""

    server_info = {"name": server_name, "version": "0.1.0"}

    class McpHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            if self.path != ENDPOINT:
                self._send(404)
                return
            # A web page in a browser can reach 127.0.0.1 too; only a local origin may.
            origin = self.headers.get("Origin")
            if origin is not None and urlsplit(origin).hostname not in LOCAL_HOSTS:
                self._send(403)
                return
            refusal, length = _content_length(self.headers.get("Content-Length"))
            if refusal is not None:
                self._send(refusal)
                return
            try:
                message = json.loads(self.rfile.read(length))
            except ValueError:
                self._send(400, _parse_error("body must be JSON"))
                return
            if not isinstance(message, dict):
                self._send(400, _parse_error("body must be one JSON-RPC message"))
                return
            response = handle(message, agent, server_info)
            if response is None:
                self._send(202)  # a notification has no answer
            else:
                self._send(200, response)

        def do_GET(self) -> None:
            self._send(405)

        def do_DELETE(self) -> None:
            self._send(405)

        def _send(self, status: int, payload: dict[str, Any] | None = None) -> None:
            data = b"" if payload is None else json.dumps(payload).encode("utf-8")
            self.send_response(status)
            if status == 405:
                self.send_header("Allow", "POST")
            if payload is not None:
                self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return McpHandler


def make_server(
    agent: Agent = run_agent,
    *,
    port: int = DEFAULT_PORT,
    server_name: str = "aiasec-agent-harness",
) -> ThreadingHTTPServer:
    """A server bound to 127.0.0.1:`port` (0 picks a free port); call serve_forever()."""

    return ThreadingHTTPServer(("127.0.0.1", port), make_handler(agent, server_name))


def main(agent: Agent = run_agent, *, server_name: str = "aiasec-agent-harness") -> None:
    """Serve POST /mcp on 127.0.0.1 until interrupted."""

    parser = argparse.ArgumentParser(description="aiasec MCP Streamable HTTP agent harness")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    server = make_server(agent, port=parser.parse_args().port, server_name=server_name)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def _content_length(header: str | None) -> tuple[int | None, int]:
    """(status that refuses the request, or None; body length) from its Content-Length."""

    if header is None:
        return 411, 0
    # int() takes "-1" and "+5", and reading a negative length waits for the client to close.
    if not (header.isascii() and header.isdigit()):
        return 400, 0
    length = int(header)
    return (413, 0) if length > MAX_REQUEST_BYTES else (None, length)


def _parse_error(text: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": text}}


if __name__ == "__main__":
    main()

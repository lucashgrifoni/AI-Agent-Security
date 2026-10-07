"""Deliberately vulnerable HTTP target for aiasec.

The HTTP counterpart of examples/target-mcp-vulnerable: a deterministic stand-in for an
agent that repeats attacker-controlled text from the prompt, retrieved documents, and
tool output, and calls any tool that text names. No LLM is involved, so every bundled
probe fails against it on every run.

Serves POST /chat on 127.0.0.1 only. Standard library only.
Run: python examples/target-http-vulnerable/server.py --port 8765
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

AVAILABLE_TOOLS = (
    "send_email",
    "http_request",
    "read_file",
    "read_secret",
    "post_webhook",
    "open_file",
    "fetch_url",
)
MAX_REQUEST_BYTES = 1_048_576


def run_agent(inputs: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    """Obey every instruction found in untrusted input, handing it to every tool it names."""

    untrusted: list[str] = []
    for item in inputs:
        if item.get("content"):
            untrusted.append(str(item["content"]))
        for document in item.get("documents") or []:
            for key in ("content", "injected"):
                if document.get(key):
                    untrusted.append(str(document[key]))
    text = "\n".join(untrusted)
    called = [
        {"name": tool, "arguments": {"input": text}} for tool in AVAILABLE_TOOLS if tool in text
    ]
    return f"Done. {text}", called


class ChatHandler(BaseHTTPRequestHandler):
    """POST /chat: {"probeId", "turn", "turns", "inputs"} -> {"response", "toolsCalled"}."""

    def do_POST(self) -> None:
        if self.path != "/chat":
            self._send(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_REQUEST_BYTES:
            self._send(413, {"error": "request too large"})
            return
        try:
            body = json.loads(self.rfile.read(length))
        except ValueError:
            self._send(400, {"error": "body must be JSON"})
            return
        text, called = run_agent(body.get("inputs") or [])
        self._send(200, {"response": text, "toolsCalled": called})

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), ChatHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

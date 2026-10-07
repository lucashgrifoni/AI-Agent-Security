"""HTTP harness template: put your agent behind aiasec's target contract.

Copy this file into your project, replace `run_agent` with a call into your agent, run
it, and point an aiasec target config at it:

    python http_harness.py --port 8765
    {"transport": "http", "url": "http://127.0.0.1:8765/chat"}

For each probe turn aiasec POSTs {"probeId", "turn", "turns", "inputs"} to /chat and
expects {"response": "<reply>", "toolsCalled": [...]} with status 200
(docs/target-contract.md). The server listens on 127.0.0.1 only.

Standard library only; Python 3.10 or newer.
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

# (inputs) -> (reply text, tool calls). A tool call is a name or {"name", "arguments"}.
Agent = Callable[[list[dict[str, Any]]], tuple[str, list[Any]]]

MAX_REQUEST_BYTES = 1_048_576


def run_agent(inputs: list[dict[str, Any]]) -> tuple[str, list[Any]]:
    """Run your agent on one probe turn. Replace this body.

    `inputs` is the conversation so far, oldest first. Each item has a `role` and a
    `content` string, `documents` (`path`, `content`, `injected`), or both:

    - `system`: instructions for your agent, as its system prompt would carry them;
      a probe may plant a secret here to test that the agent does not reveal it.
    - `user`: a user message.
    - `assistant`: your agent's own reply to an earlier turn.
    - `rag_corpus`: documents your retrieval step returned.
    - `tool_output`: what a tool your agent called returned.
    - `tool_catalog`: tool definitions your agent can see; the description is
      attacker-controlled in the mcp-specific probes.

    A document's `injected` text is the attack. Hand each item to your agent through
    the path real content of that kind takes (retrieved documents into the retrieval
    slot, tool output as a tool result), or the probe measures nothing.

    Return the agent's final reply for this turn and every tool it called, in order,
    with the arguments it passed: `["search", {"name": "send_email", "arguments":
    {"to": "..."}}]`. Point side-effecting tools at fakes while testing; aiasec scores
    the calls, it never needs them to happen.

    Until you connect an agent this raises, so aiasec fails the run (exit 2) instead of
    passing a harness that answered nothing.
    """

    raise NotImplementedError("connect run_agent to your agent")


def make_handler(agent: Agent) -> type[BaseHTTPRequestHandler]:
    """Build the request handler that serves POST /chat with `agent`."""

    class ChatHandler(BaseHTTPRequestHandler):
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
            try:
                text, called = agent(body.get("inputs") or [])
            except Exception as exc:  # noqa: BLE001 - reported to aiasec as a failed request
                traceback.print_exc(file=sys.stderr)
                # Any status but 200 fails the aiasec run; it must never read as a reply.
                self._send(500, {"error": f"agent failed: {type(exc).__name__}"})
                return
            self._send(200, {"response": text, "toolsCalled": called})

        def _send(self, status: int, payload: dict[str, Any]) -> None:
            data = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return ChatHandler


def serve(agent: Agent = run_agent, *, port: int = 8765) -> None:
    """Serve POST /chat on 127.0.0.1 until interrupted."""

    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(agent))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main(agent: Agent = run_agent) -> None:
    parser = argparse.ArgumentParser(description="aiasec HTTP agent harness")
    parser.add_argument("--port", type=int, default=8765)
    serve(agent, port=parser.parse_args().port)


if __name__ == "__main__":
    main()

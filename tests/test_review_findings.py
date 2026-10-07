"""Regression tests for the findings of the automated reviews on PRs #1 to #8.

Each test reproduced its finding against the code before the fix. Tests that could
hang on the bug run the call in a thread and fail if it is still running at the
deadline, so a regression makes the suite fail instead of stalling it.
"""

from __future__ import annotations

import io
import sys
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from aiasec.cli.app import app
from aiasec.core.evaluator.rules import TargetObservation, evaluate_probe
from aiasec.core.probe import load_probe_file, load_probes_from_dir
from aiasec.httptarget import HttpAgentTarget, HttpTargetConfig, HttpTargetError
from aiasec.mcp.config import McpStdioConfig
from aiasec.mcp.stdio import McpStdioAdapter
from aiasec.mcp.target import McpAgentTarget, McpTargetError
from aiasec.mcp.transport import JsonObject, LineJsonRpcTransport, McpTransportTimeout
from aiasec.outputs.sarif import render_sarif

ERA_STUB = Path("tests/mcp_era_stub.py")
DIRECT = Path("src/aiasec/probes/prompt-injection/direct-injection-001.yaml")
CHAIN = Path("src/aiasec/probes/tool-abuse/tool-chain-exfil-001.yaml")


def _finishes_within(seconds: float, call: Callable[[], Any]) -> Any:
    outcome: dict[str, Any] = {}

    def run() -> None:
        try:
            outcome["value"] = call()
        except BaseException as exc:  # noqa: BLE001 - re-raised in the test thread
            outcome["error"] = exc

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(seconds)
    assert not worker.is_alive(), f"call still running after {seconds} s"
    if "error" in outcome:
        raise outcome["error"]
    return outcome.get("value")


# --- PR #7, P1: one deadline across notifications --------------------------------


class ChattyTransport:
    """Sends a notification every 20 ms and never answers until initialize is sent."""

    def __init__(self) -> None:
        self.sent: list[JsonObject] = []

    def send(self, message: JsonObject) -> None:
        self.sent.append(message)

    def receive(self, timeout: float | None = None) -> JsonObject:
        last = self.sent[-1] if self.sent else {}
        if last.get("method") == "initialize":
            return {"jsonrpc": "2.0", "id": last["id"], "result": {"protocolVersion": "2025-11-25"}}
        if timeout is not None and timeout <= 0.02:
            time.sleep(max(timeout, 0))
            raise McpTransportTimeout("no message")
        time.sleep(0.02)
        return {"jsonrpc": "2.0", "method": "notifications/message", "params": {}}

    def close(self) -> None:
        pass


def test_notifications_do_not_extend_the_discovery_probe_deadline() -> None:
    adapter = McpStdioAdapter(ChattyTransport())

    session = _finishes_within(5, lambda: adapter.connect(probe_timeout=0.3))

    assert session.era == "legacy"


def test_a_chatty_target_that_never_answers_a_tool_call_times_out() -> None:
    config = McpStdioConfig.model_validate(
        {
            "transport": "stdio",
            "command": [sys.executable, str(ERA_STUB), "chatty"],
            "timeoutSeconds": 1,
        }
    )
    probe = load_probe_file(DIRECT)

    def run() -> None:
        with McpAgentTarget.start(config) as target:
            target.observe(probe)

    with pytest.raises(McpTransportTimeout):
        _finishes_within(15, run)


# PR #7, P1 (reserved-range errors that 2026-07-28 does not define fall back to
# initialize) is pinned in tests/test_mcp_negotiation.py next to the other fallback codes.


# --- PR #7, P2: the public line transport works with connect() --------------------


def test_connect_works_over_the_public_line_transport() -> None:
    replies = (
        '{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no"}}\n'
        '{"jsonrpc":"2.0","id":2,"result":{"protocolVersion":"2025-11-25"}}\n'
    )
    transport = LineJsonRpcTransport(reader=io.StringIO(replies), writer=io.StringIO())

    session = McpStdioAdapter(transport).connect()

    assert session.era == "legacy"


# --- PR #2: a tool result without text is a contract violation --------------------


@pytest.mark.parametrize("mode", ["no-text", "non-text"])
def test_a_tool_result_without_text_content_fails_the_probe(mode: str) -> None:
    config = McpStdioConfig.model_validate(
        {"transport": "stdio", "command": [sys.executable, str(ERA_STUB), mode]}
    )

    with McpAgentTarget.start(config) as target, pytest.raises(McpTargetError, match="text"):
        target.observe(load_probe_file(DIRECT))


# --- PR #8: a probe with no inputs cannot pass -----------------------------------


def test_a_probe_without_inputs_is_rejected(tmp_path) -> None:
    probes = tmp_path / "probes"
    probes.mkdir()
    text = DIRECT.read_text(encoding="utf-8")
    start = text.index("inputs:")
    end = text.index("expectations:")
    (probes / "x.yaml").write_text(text[:start] + "inputs: []\n" + text[end:], "utf-8")

    with pytest.raises(ValueError, match="input"):
        load_probes_from_dir(probes)


# --- PR #8: one deadline across the whole HTTP reply ------------------------------


class DripHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - base signature
        pass

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        try:
            for _ in range(200):  # one byte every 0.2 s: each read is fast, the reply is not
                self.wfile.write(b" ")
                self.wfile.flush()
                time.sleep(0.2)
        except OSError:
            pass


def test_a_slow_drip_http_reply_respects_the_timeout() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), DripHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/chat"
        config = HttpTargetConfig.model_validate(
            {"transport": "http", "url": url, "timeoutSeconds": 1}
        )
        target = HttpAgentTarget.start(config)

        with pytest.raises(HttpTargetError, match="timed out"):
            _finishes_within(10, lambda: target.observe(load_probe_file(DIRECT)))
    finally:
        server.shutdown()
        server.server_close()


# --- PR #1: GitHub's fingerprint key --------------------------------------------


def test_each_failed_expectation_has_its_own_github_fingerprint() -> None:
    probe = load_probe_file(CHAIN)
    result = evaluate_probe(
        probe,
        TargetObservation(
            assistant_final_response="EXFIL_SINK_REACHED", tools_called=["http_request"]
        ),
    )

    sarif_results = render_sarif([result])["runs"][0]["results"]

    hashes = [r["partialFingerprints"]["primaryLocationLineHash"] for r in sarif_results]
    assert len(sarif_results) == 2
    assert len(set(hashes)) == 2
    again = render_sarif([result])["runs"][0]["results"]
    assert hashes == [r["partialFingerprints"]["primaryLocationLineHash"] for r in again]

# --- PR #3: the action never gates on a stale report ------------------------------


def test_the_action_removes_the_previous_report_and_requires_a_new_one() -> None:
    action = Path("action.yml").read_text(encoding="utf-8")

    assert 'rm -f -- "$AIASEC_SARIF"' in action
    assert 'test -s "$AIASEC_SARIF"' in action


def test_an_unwritable_report_path_exits_2_not_1(tmp_path) -> None:
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x", encoding="utf-8")

    result = CliRunner().invoke(
        app, ["run", "--response", "x", "--output", str(blocker / "report.sarif")]
    )

    assert result.exit_code == 2


# --- PR #4: the conduct rule only concerns payloads with a destination ------------


def test_the_code_of_conduct_scopes_the_test_domain_rule_to_destinations() -> None:
    text = Path("CODE_OF_CONDUCT.md").read_text(encoding="utf-8")

    assert "network or email destination" in text


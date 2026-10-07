"""HTTP target mode: each probe turn is one JSON POST to the agent under test."""

from __future__ import annotations

import json
import socket
import ssl
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from aiasec.cli.app import app
from aiasec.core.probe import load_probes_from_dir
from aiasec.core.runner import run_probes_against
from aiasec.httptarget import HttpAgentTarget, HttpTargetConfig, HttpTargetError

PROBES = Path("src/aiasec/probes")
EXAMPLE = Path("examples/target-http-vulnerable/server.py")
SENTINEL_TOOLS = (
    "send_email",
    "http_request",
    "read_file",
    "read_secret",
    "post_webhook",
    "open_file",
    "fetch_url",
)


class Recorder:
    def __init__(self) -> None:
        self.bodies: list[dict[str, Any]] = []
        self.headers: list[dict[str, str]] = []


def _handler(mode: str, recorder: Recorder) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:  # keep test output quiet
            pass

        def do_POST(self) -> None:
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            recorder.bodies.append(body)
            recorder.headers.append(dict(self.headers))
            if mode == "redirect":
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:1/elsewhere")
                self.end_headers()
                return
            if mode == "error":
                self._send(500, {"error": "boom"})
                return
            if mode == "slow":
                time.sleep(3)
            if mode == "huge":
                self._send(200, {"response": "x" * 2_000_000, "toolsCalled": []})
                return
            if mode == "no-tools":
                self._send(200, {"response": "ok"})
                return
            text = " ".join(
                str(item.get("content", "")) + " ".join(
                    str(doc.get("injected", "")) for doc in item.get("documents", [])
                )
                for item in body["inputs"]
            )
            if mode == "vulnerable":
                called = [tool for tool in SENTINEL_TOOLS if tool in text]
                self._send(200, {"response": f"Done. {text}", "toolsCalled": called})
            else:
                self._send(200, {"response": "I will not follow that.", "toolsCalled": []})

        def _send(self, status: int, payload: dict[str, Any]) -> None:
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return Handler


@pytest.fixture
def serve() -> Iterator[Any]:
    servers: list[ThreadingHTTPServer] = []

    def start(mode: str) -> tuple[str, Recorder]:
        recorder = Recorder()
        server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(mode, recorder))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_address[1]}/chat", recorder

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


def _config(url: str, **extra: Any) -> HttpTargetConfig:
    return HttpTargetConfig.model_validate({"transport": "http", "url": url, **extra})


def _run(*args: str):
    return CliRunner().invoke(app, list(args))


def test_every_bundled_probe_fails_against_a_vulnerable_http_agent(serve) -> None:
    url, _ = serve("vulnerable")
    probes = load_probes_from_dir(PROBES)

    with HttpAgentTarget.start(_config(url)) as target:
        results = run_probes_against(probes, target.observe)

    assert all(not result.passed for result in results)


def test_every_bundled_probe_passes_against_a_good_http_agent(serve) -> None:
    url, _ = serve("good")
    probes = load_probes_from_dir(PROBES)

    with HttpAgentTarget.start(_config(url)) as target:
        results = run_probes_against(probes, target.observe)

    assert all(result.passed for result in results)


def test_a_multi_turn_probe_is_one_post_per_turn(serve) -> None:
    url, recorder = serve("good")
    crescendo = next(p for p in load_probes_from_dir(PROBES) if p.id == "crescendo-001")

    with HttpAgentTarget.start(_config(url)) as target:
        target.observe(crescendo)

    assert [body["turn"] for body in recorder.bodies] == [1, 2, 3]
    assert [item["role"] for item in recorder.bodies[2]["inputs"]].count("assistant") == 2


def test_header_values_come_from_the_environment(serve, monkeypatch) -> None:
    url, recorder = serve("good")
    monkeypatch.setenv("AIASEC_TEST_TOKEN", "token-from-env")
    config = _config(url, headers={"Authorization": "Bearer ${AIASEC_TEST_TOKEN}"})
    probe = load_probes_from_dir(PROBES)[0]

    with HttpAgentTarget.start(config) as target:
        target.observe(probe)

    assert recorder.headers[0]["Authorization"] == "Bearer token-from-env"


@pytest.mark.parametrize("bad", ["\n", "\r\n"])
def test_an_environment_header_value_that_would_split_the_request_is_refused_unechoed(
    serve, monkeypatch, bad: str
) -> None:
    url, recorder = serve("good")
    monkeypatch.setenv("AIASEC_TEST_TOKEN", "token-secret-value" + bad)
    config = _config(url, headers={"Authorization": "Bearer ${AIASEC_TEST_TOKEN}"})

    with pytest.raises(HttpTargetError, match="AIASEC_TEST_TOKEN") as error:
        HttpAgentTarget.start(config)
    assert "token-secret-value" not in str(error.value)
    assert recorder.bodies == []


def test_a_missing_environment_variable_fails_before_any_request(serve, monkeypatch) -> None:
    url, recorder = serve("good")
    monkeypatch.delenv("AIASEC_TEST_MISSING", raising=False)
    config = _config(url, headers={"Authorization": "Bearer ${AIASEC_TEST_MISSING}"})

    with pytest.raises(HttpTargetError, match="AIASEC_TEST_MISSING"):
        HttpAgentTarget.start(config)

    assert recorder.bodies == []


@pytest.mark.parametrize(
    ("mode", "message"),
    [
        ("error", "500"),
        ("redirect", "302"),
        ("no-tools", "toolsCalled"),
        ("huge", "larger than"),
    ],
)
def test_a_broken_reply_fails_the_probe_run(serve, mode: str, message: str) -> None:
    url, _ = serve(mode)
    probe = load_probes_from_dir(PROBES)[0]

    with HttpAgentTarget.start(_config(url)) as target, pytest.raises(
        HttpTargetError, match=message
    ):
        target.observe(probe)


def test_a_slow_agent_times_out(serve) -> None:
    url, _ = serve("slow")
    probe = load_probes_from_dir(PROBES)[0]

    with HttpAgentTarget.start(_config(url, timeoutSeconds=1)) as target, pytest.raises(
        HttpTargetError, match="timed out|timeout"
    ):
        target.observe(probe)


def test_https_targets_verify_the_certificate_and_the_hostname() -> None:
    target = HttpAgentTarget.start(_config("https://agent.example.test/chat"))

    connection = target._connection()

    context = connection._context  # type: ignore[attr-defined]
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://host/x", "http:///no-host"])
def test_only_http_and_https_urls_with_a_host_are_accepted(url: str) -> None:
    with pytest.raises(ValueError):
        _config(url)


def test_cli_refuses_to_contact_an_http_target_without_execute(serve, tmp_path) -> None:
    url, recorder = serve("good")
    config = tmp_path / "target.json"
    config.write_text(json.dumps({"transport": "http", "url": url}), encoding="utf-8")

    result = _run("run", "--target", str(config), "--output", str(tmp_path / "r.md"))

    assert result.exit_code == 2
    assert "--execute" in result.output
    assert recorder.bodies == []


def test_cli_drives_an_http_target_and_records_the_mode(serve, tmp_path) -> None:
    url, _ = serve("vulnerable")
    config = tmp_path / "target.json"
    config.write_text(json.dumps({"transport": "http", "url": url}), encoding="utf-8")
    report = tmp_path / "report.sarif"

    result = _run("run", "--target", str(config), "--execute", "--output", str(report))

    assert result.exit_code == 1
    run = json.loads(report.read_text(encoding="utf-8"))["runs"][0]
    assert run["properties"]["aiasec"]["observationMode"] == "http-target"
    assert run["properties"]["aiasec"]["probesFailed"] == len(load_probes_from_dir(PROBES))


def test_the_example_http_server_is_vulnerable_end_to_end(tmp_path) -> None:
    with socket.socket() as probe_socket:
        probe_socket.bind(("127.0.0.1", 0))
        port = probe_socket.getsockname()[1]
    process = subprocess.Popen([sys.executable, str(EXAMPLE), "--port", str(port)])
    try:
        url = f"http://127.0.0.1:{port}/chat"
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            with socket.socket() as client:
                if client.connect_ex(("127.0.0.1", port)) == 0:
                    break
            time.sleep(0.1)
        probes = load_probes_from_dir(PROBES)
        with HttpAgentTarget.start(_config(url)) as target:
            results = run_probes_against(probes, target.observe)
        assert all(not result.passed for result in results)
    finally:
        process.terminate()
        process.wait(timeout=5)

"""MCP targets over Streamable HTTP: config rules, start, and every bundled probe end to end.

The reference servers run in this process on 127.0.0.1 port 0 (a subprocess listener
was unreachable on the macOS CI runner), through the HTTP harness template.
"""

from __future__ import annotations

import http.client
import importlib
import json
import runpy
import threading
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from aiasec.cli.app import app
from aiasec.core.probe import load_probes_from_dir
from aiasec.core.runner import run_probes_against
from aiasec.httptarget import HttpTargetError
from aiasec.mcp.config import McpHttpConfig
from aiasec.mcp.target import McpAgentTarget, McpTargetError
from aiasec.targets import load_target_config

PROBES = Path("src/aiasec/probes")
EXAMPLES = Path("examples").resolve()
GOOD = EXAMPLES / "target-mcp-http-good"
VULNERABLE = EXAMPLES / "target-mcp-http-vulnerable"


def _config(url: str, **extra: Any) -> McpHttpConfig:
    return McpHttpConfig.model_validate({"transport": "mcp-http", "url": url, **extra})


@pytest.mark.parametrize(
    ("url", "headers"),
    [
        ("https://agent.example.com/mcp", {"Authorization": "Bearer ${TOKEN}"}),
        ("http://127.0.0.1:8766/mcp", {"Authorization": "Bearer ${TOKEN}"}),
        ("http://localhost:8766/mcp", {"X-Api-Key": "${KEY}"}),
        ("http://[::1]:8766/mcp", {"Cookie": "sid=1"}),
        ("http://agent.example.com/mcp", {"X-Trace": "run-1"}),
    ],
)
def test_a_config_may_send_credentials_only_over_https_or_to_this_machine(
    url: str, headers: dict[str, str]
) -> None:
    assert _config(url, headers=headers).headers == headers


@pytest.mark.parametrize(
    "headers",
    [
        {"Authorization": "Bearer abc"},
        {"X-Api-Key": "abc"},
        {"X-Auth-Token": "abc"},
        {"Cookie": "sid=1"},
        {"X-Custom": "${SECRET}"},
    ],
)
def test_a_credential_header_never_goes_over_plain_http_to_another_host(
    headers: dict[str, str],
) -> None:
    with pytest.raises(ValidationError, match="unencrypted"):
        _config("http://agent.example.com/mcp", headers=headers)


@pytest.mark.parametrize(
    "header", ["Accept", "content-type", "Mcp-Method", "MCP-NAME", "mcp-protocol-version",
               "Mcp-Session-Id"],
)  # fmt: skip
def test_a_config_cannot_set_the_headers_the_transport_sets(header: str) -> None:
    with pytest.raises(ValidationError, match="sets itself"):
        _config("https://agent.example.com/mcp", headers={header: "x"})


@pytest.mark.parametrize(
    "raw",
    [
        {"url": "ftp://agent.example.com/mcp"},
        {"url": "http:///mcp"},
        {"url": "https://a.example.com/mcp", "headers": {"X-A": "a\r\nInjected: 1"}},
        {"url": "https://a.example.com/mcp", "command": ["python"]},
        {"url": "https://a.example.com/mcp", "agentTool": ""},
        {"url": "https://a.example.com/mcp", "protocol": "newest"},
    ],
)
def test_a_malformed_config_is_rejected(raw: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        McpHttpConfig.model_validate({"transport": "mcp-http", **raw})


def test_the_reference_configs_load_as_mcp_http_targets() -> None:
    for example in (GOOD, VULNERABLE):
        config = load_target_config(example / "aiasec-target.json")
        assert isinstance(config, McpHttpConfig)
        assert config.url == "http://127.0.0.1:8766/mcp"


@pytest.fixture
def harness(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.syspath_prepend(str(EXAMPLES / "harness"))
    monkeypatch.syspath_prepend(str(EXAMPLES))
    return importlib.import_module("mcp_http_harness")


@pytest.fixture
def serve(harness: Any) -> Iterator[Any]:
    servers: list[ThreadingHTTPServer] = []

    def start(agent: Any, seen: list[dict[str, str]] | None = None) -> str:
        server = harness.make_server(agent, port=0)
        if seen is not None:
            handle = server.RequestHandlerClass.do_POST

            def recording(self: Any) -> None:
                seen.append({k.lower(): v for k, v in self.headers.items()})
                handle(self)

            server.RequestHandlerClass = type(
                "Recording", (server.RequestHandlerClass,), {"do_POST": recording}
            )
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_address[1]}/mcp"

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


def _reference_agent(example: Path, name: str) -> Any:
    return runpy.run_path(str(example / "server.py"))[name]


def test_every_bundled_probe_fails_against_the_vulnerable_http_target(serve: Any) -> None:
    probes = load_probes_from_dir(PROBES)
    url = serve(_reference_agent(VULNERABLE, "vulnerable_agent"))

    with McpAgentTarget.start_http(_config(url)) as target:
        results = run_probes_against(probes, target.observe)

    failed = sorted(result.probe.id for result in results if not result.passed)
    assert failed == sorted(probe.id for probe in probes)


def test_every_bundled_probe_passes_against_the_good_http_target(serve: Any) -> None:
    probes = load_probes_from_dir(PROBES)
    url = serve(_reference_agent(GOOD, "good_agent"))

    with McpAgentTarget.start_http(_config(url)) as target:
        assert target.label == "MCP 2026-07-28 (modern)"
        results = run_probes_against(probes, target.observe)

    assert [result.probe.id for result in results if not result.passed] == []
    assert len(results) == len(probes)


@pytest.mark.parametrize("protocol", ["legacy", "auto"])
def test_the_harness_also_speaks_the_legacy_handshake(serve: Any, protocol: str) -> None:
    url = serve(_reference_agent(GOOD, "good_agent"))

    with McpAgentTarget.start_http(_config(url, protocol=protocol)) as target:
        era = target.session.era

    assert era == ("legacy" if protocol == "legacy" else "modern")


def test_header_references_are_expanded_at_start(
    serve: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[dict[str, str]] = []
    url = serve(_reference_agent(GOOD, "good_agent"), seen)
    monkeypatch.setenv("AIASEC_TEST_TOKEN", "test-token")

    config = _config(url, headers={"Authorization": "Bearer ${AIASEC_TEST_TOKEN}"})
    with McpAgentTarget.start_http(config):
        pass

    assert seen and all(headers["authorization"] == "Bearer test-token" for headers in seen)


def test_a_missing_header_variable_fails_before_any_request(
    serve: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[dict[str, str]] = []
    url = serve(_reference_agent(GOOD, "good_agent"), seen)
    monkeypatch.delenv("AIASEC_TEST_TOKEN", raising=False)

    with pytest.raises(HttpTargetError, match="AIASEC_TEST_TOKEN"):
        McpAgentTarget.start_http(_config(url, headers={"X-Token": "${AIASEC_TEST_TOKEN}"}))

    assert seen == []


def test_a_server_without_the_agent_tool_is_refused(serve: Any) -> None:
    url = serve(_reference_agent(GOOD, "good_agent"))

    with pytest.raises(McpTargetError, match="does not expose the agent tool 'other'"):
        McpAgentTarget.start_http(_config(url, agentTool="other"))


def test_cli_drives_the_vulnerable_http_target_and_the_gate_fails(
    serve: Any, tmp_path: Path
) -> None:
    url = serve(_reference_agent(VULNERABLE, "vulnerable_agent"))
    target = tmp_path / "target.json"
    target.write_text(json.dumps({"transport": "mcp-http", "url": url}), encoding="utf-8")
    report = tmp_path / "report.sarif"

    result = CliRunner().invoke(
        app, ["run", "--target", str(target), "--execute", "--output", str(report)]
    )

    assert result.exit_code == 1, result.output
    assert "over HTTP" in result.output
    sarif = json.loads(report.read_text(encoding="utf-8"))
    assert sarif["runs"][0]["properties"]["aiasec"]["observationMode"] == "mcp-http-target"


def test_cli_refuses_to_send_probes_without_execute(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text(
        json.dumps({"transport": "mcp-http", "url": "http://127.0.0.1:9/mcp"}), encoding="utf-8"
    )

    result = CliRunner().invoke(app, ["run", "--target", str(target)])

    assert result.exit_code == 2
    assert "send probes to the MCP server at http://127.0.0.1:9/mcp" in result.output


@pytest.mark.parametrize(
    ("method", "body", "headers", "status"),
    [
        ("GET", None, {}, 405),
        ("DELETE", None, {}, 405),
        ("POST", {"jsonrpc": "2.0", "method": "notifications/initialized"}, {}, 202),
        ("POST", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, {}, 200),
        ("POST", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
         {"Origin": "https://attacker.example"}, 403),
        ("POST", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
         {"Origin": "http://localhost:3000"}, 200),
        ("POST", "not json", {}, 400),
        ("POST", [{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}], {}, 400),
    ],
)  # fmt: skip
def test_the_http_harness_answers_like_a_streamable_http_server(
    serve: Any, method: str, body: Any, headers: dict[str, str], status: int
) -> None:
    url = serve(_reference_agent(GOOD, "good_agent"))
    port = int(url.rsplit(":", 1)[1].split("/")[0])
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    data = None if body is None else (body if isinstance(body, str) else json.dumps(body))
    connection.request(method, "/mcp", body=data, headers=headers)
    response = connection.getresponse()
    response.read()
    connection.close()

    assert response.status == status
    if status == 405:
        assert response.getheader("Allow") == "POST"

"""End-to-end tests that send every bundled probe to a real MCP stdio target.

The two example servers are deterministic stand-ins for agents, so these tests close
the loop the rest of the suite cannot: probe inputs leave aiasec over MCP, a separate
process answers, and the report reflects what that process did.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aiasec.cli.app import app
from aiasec.core.probe import load_probes_from_dir
from aiasec.core.runner import run_probes_against
from aiasec.mcp.config import McpStdioConfig
from aiasec.mcp.target import McpAgentTarget, McpTargetError
from aiasec.mcp.transport import McpTransportError

PROBES = Path("src/aiasec/probes")
VULNERABLE = Path("examples/target-mcp-vulnerable/server.py")
GOOD = Path("examples/target-mcp-good/server.py")


def _config(server: Path, **extra: object) -> McpStdioConfig:
    return McpStdioConfig.model_validate(
        {"transport": "stdio", "command": [sys.executable, str(server)], **extra}
    )


def _config_file(tmp_path: Path, server: Path, **extra: object) -> Path:
    path = tmp_path / "target.json"
    path.write_text(_config(server, **extra).model_dump_json(by_alias=True), encoding="utf-8")
    return path


def _run(*args: str):
    return CliRunner().invoke(app, list(args))


def test_every_bundled_probe_fails_against_the_vulnerable_target() -> None:
    probes = load_probes_from_dir(PROBES)

    with McpAgentTarget.start(_config(VULNERABLE)) as target:
        results = run_probes_against(probes, target.observe)

    failed = sorted(result.probe.id for result in results if not result.passed)
    assert failed == sorted(probe.id for probe in probes)


def test_every_bundled_probe_passes_against_the_good_target() -> None:
    probes = load_probes_from_dir(PROBES)

    with McpAgentTarget.start(_config(GOOD)) as target:
        results = run_probes_against(probes, target.observe)

    assert [result.probe.id for result in results if not result.passed] == []
    assert len(results) == len(probes)


def test_target_observation_carries_the_tools_the_target_called() -> None:
    probe = next(p for p in load_probes_from_dir(PROBES) if p.id == "tool-coercion-001")

    with McpAgentTarget.start(_config(VULNERABLE)) as target:
        observation = target.observe(probe)

    assert observation.tools_called == ["send_email"]


def test_cli_drives_the_vulnerable_target_and_the_gate_fails(tmp_path) -> None:
    config = _config_file(tmp_path, VULNERABLE)
    report = tmp_path / "report.sarif"

    result = _run("run", "--target", str(config), "--execute", "--output", str(report))

    assert result.exit_code == 1
    run = json.loads(report.read_text(encoding="utf-8"))["runs"][0]
    assert run["properties"]["aiasec"] == {
        "observationMode": "mcp-stdio-target",
        "probesExecuted": 10,
        "probesFailed": 10,
    }
    gate = _run("gate", "--report", str(report), "--max-high", "0", "--exit-on-fail")
    assert gate.exit_code == 1


def test_cli_drives_the_good_target_and_the_gate_passes(tmp_path) -> None:
    config = _config_file(tmp_path, GOOD)
    report = tmp_path / "report.sarif"

    result = _run("run", "--target", str(config), "--execute", "--output", str(report))

    assert result.exit_code == 0, result.output
    gate = _run("gate", "--report", str(report), "--max-critical", "0", "--max-high", "0")
    assert json.loads(gate.stdout)["verdict"] == "PASS"


def test_cli_refuses_to_start_a_target_without_execute(tmp_path) -> None:
    marker = tmp_path / "started"
    config = tmp_path / "target.json"
    config.write_text(
        json.dumps(
            {
                "transport": "stdio",
                "command": [sys.executable, "-c", f"open({str(marker)!r}, 'w').close()"],
            }
        ),
        encoding="utf-8",
    )

    result = _run("run", "--target", str(config), "--output", str(tmp_path / "r.sarif"))

    assert result.exit_code == 2
    assert "--execute" in result.output
    assert not marker.exists()


def test_cli_rejects_target_combined_with_a_supplied_response(tmp_path) -> None:
    config = _config_file(tmp_path, GOOD)

    result = _run(
        "run", "--target", str(config), "--execute", "--response", "x", "--output", "r.md"
    )

    assert result.exit_code == 2


def test_target_without_the_agent_tool_is_rejected(tmp_path) -> None:
    config = _config_file(tmp_path, GOOD, agentTool="not_exposed")

    result = _run("run", "--target", str(config), "--execute", "--output", str(tmp_path / "r.md"))

    assert result.exit_code == 2
    assert "not_exposed" in result.output


ERA_STUB = Path("tests/mcp_era_stub.py")


def _stub_config(*args: str, **extra: object) -> McpStdioConfig:
    return McpStdioConfig.model_validate(
        {"transport": "stdio", "command": [sys.executable, str(ERA_STUB), *args], **extra}
    )


def test_the_reference_targets_speak_the_modern_protocol() -> None:
    with McpAgentTarget.start(_config(GOOD)) as target:
        assert (target.session.era, target.session.protocol_version) == ("modern", "2026-07-28")


@pytest.mark.parametrize(
    ("args", "extra"),
    [
        (("legacy-error",), {}),
        (("legacy-silent",), {"timeoutSeconds": 2}),
    ],
    ids=["legacy-error", "legacy-silent"],
)
def test_legacy_targets_fall_back_to_initialize(args: tuple[str, ...], extra: dict) -> None:
    probes = load_probes_from_dir(PROBES)

    with McpAgentTarget.start(_stub_config(*args, **extra)) as target:
        results = run_probes_against(probes, target.observe)
        era = target.session.era

    assert era == "legacy"
    assert all(result.passed for result in results)


def test_a_modern_only_target_is_driven_without_initialize() -> None:
    probes = load_probes_from_dir(PROBES)

    with McpAgentTarget.start(_stub_config("modern-only", "2026-07-28")) as target:
        results = run_probes_against(probes, target.observe)
        era = target.session.era

    assert era == "modern"
    assert all(result.passed for result in results)


def test_a_target_with_no_mutual_version_fails_the_run(tmp_path) -> None:
    config = tmp_path / "target.json"
    config.write_text(
        _stub_config("modern-only", "2099-01-01").model_dump_json(by_alias=True), "utf-8"
    )

    result = _run("run", "--target", str(config), "--execute", "--output", str(tmp_path / "r.md"))

    assert result.exit_code == 2
    assert "2099-01-01" in result.output


def test_protocol_legacy_skips_the_probe_on_a_silent_server() -> None:
    config = _stub_config("legacy-silent", protocol="legacy")

    with McpAgentTarget.start(config) as target:
        assert target.session.era == "legacy"


def test_a_silent_target_times_out_instead_of_hanging(tmp_path) -> None:
    silent = tmp_path / "silent.py"
    silent.write_text("import time\ntime.sleep(30)\n", encoding="utf-8")

    with pytest.raises((McpTransportError, McpTargetError)):
        McpAgentTarget.start(_config(silent, timeoutSeconds=1))

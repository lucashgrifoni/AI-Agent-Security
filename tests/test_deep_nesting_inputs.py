"""Every file the CLI reads fails with exit 2 when it nests too deeply, never with a traceback.

Exit 1 is a verdict (a failed probe, a finding, a changed tool, a closed gate), so a
RecursionError escaping as exit 1 cannot be told apart from a real result in CI.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aiasec.cli.app import app

DEEP_JSON = "[" * 100_000
DEEP_YAML = "[" * 5_000 + "]" * 5_000
CLEAN_REPORT = Path(__file__).parent.parent / "fuzz/corpus/fuzz_sarif_report/clean_run.sarif"

Args = Callable[[Path, Path], list[str]]

CASES: dict[str, tuple[str, Args]] = {
    "mcp tools audit --snapshot": (
        DEEP_JSON,
        lambda deep, tmp: ["mcp", "tools", "audit", "--snapshot", str(deep),
                           "--output", str(tmp / "a.sarif"), "--exit-on-finding"],
    ),
    "mcp tools diff": (
        DEEP_JSON,
        lambda deep, tmp: ["mcp", "tools", "diff", "--baseline", str(deep),
                           "--current", str(deep), "--exit-on-change"],
    ),
    "mcp tools audit --fixture": (
        DEEP_JSON,
        lambda deep, tmp: ["mcp", "tools", "audit", "--fixture", str(deep),
                           "--output", str(tmp / "a.sarif")],
    ),
    "mcp tools snapshot --fixture": (
        DEEP_JSON,
        lambda deep, tmp: ["mcp", "tools", "snapshot", "--fixture", str(deep),
                           "--output", str(tmp / "s.json")],
    ),
    "mcp tools list --config": (
        DEEP_JSON,
        lambda deep, tmp: ["mcp", "tools", "list", "--config", str(deep)],
    ),
    "run --target": (
        DEEP_JSON,
        lambda deep, tmp: ["run", "--target", str(deep), "--output", str(tmp / "r.md")],
    ),
    "run --judge": (
        DEEP_JSON,
        lambda deep, tmp: ["run", "--response", "hello", "--probe-id", "persona-swap-001",
                           "--output", str(tmp / "r.md"), "--judge", str(deep)],
    ),
    "gate --waivers": (
        DEEP_YAML,
        lambda deep, tmp: ["gate", "--report", str(CLEAN_REPORT), "--max-high", "0",
                           "--waivers", str(deep)],
    ),
}


def _flat(output: str) -> str:
    """The output on one line, without the borders rich draws around an error."""

    return " ".join(output.replace("|", " ").replace("│", " ").split())


@pytest.mark.parametrize("command", CASES)
def test_a_deeply_nested_input_file_is_an_error_not_a_crash(tmp_path: Path, command: str) -> None:
    content, args = CASES[command]
    deep = tmp_path / "deep.input"
    deep.write_text(content, encoding="utf-8")

    result = CliRunner().invoke(app, args(deep, tmp_path))

    assert not isinstance(result.exception, RecursionError), command
    assert result.exit_code == 2, command
    assert "nests too deeply to read" in _flat(result.output), command


def _deep_fixture(tmp_path: Path, depth: int) -> Path:
    # Deeper than Python's recursion limit, so the indenting JSON encoder cannot write it,
    # but within the C decoder's limit, so the fixture itself decodes.
    schema = '{"a":' * depth + '"x"' + "}" * depth
    tool = '{"name":"deep","description":"d","inputSchema":' + schema + "}"
    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "serverInfo": {"name": "deep", "version": "1"},
        },
    }
    fixture = tmp_path / "fixture.json"
    fixture.write_text(
        "[" + json.dumps(initialize) + ',{"jsonrpc":"2.0","id":2,"result":{"tools":['
        + tool + "]}}]",
        encoding="utf-8",
    )
    json.loads(fixture.read_text(encoding="utf-8"))  # the premise: it decodes
    return fixture


@pytest.mark.parametrize("command", ["list", "snapshot"])
def test_a_tool_definition_too_deep_to_write_is_an_error_not_a_crash(
    tmp_path: Path, command: str
) -> None:
    # The decoder reads deeper than Python's recursion limit; the indenting encoder that
    # prints the tools and writes the snapshot does not, and raised RecursionError.
    fixture = _deep_fixture(tmp_path, 1_100)
    args = ["mcp", "tools", command, "--fixture", str(fixture)]
    if command == "snapshot":
        args += ["--output", str(tmp_path / "snapshot.json")]

    result = CliRunner().invoke(app, args)

    assert not isinstance(result.exception, RecursionError)
    assert result.exit_code == 2
    assert "nests too deeply to" in _flat(result.output)
    assert not (tmp_path / "snapshot.json").exists()

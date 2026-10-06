import json

from typer.testing import CliRunner

from aiasec.cli.app import app


def test_cli_lists_bundled_probes() -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["probes", "list"])

    assert result.exit_code == 0
    assert "direct-injection-001" in result.stdout


def test_cli_run_writes_markdown_report(tmp_path) -> None:
    runner = CliRunner()
    output = tmp_path / "report.md"

    result = runner.invoke(
        app,
        [
            "run",
            "--response",
            "I cannot follow that instruction.",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    assert "Failed probes: 0" in output.read_text(encoding="utf-8")


def test_cli_lists_mcp_tools_from_local_fixture(tmp_path) -> None:
    runner = CliRunner()
    fixture = tmp_path / "mcp-tools.json"
    fixture.write_text(
        json.dumps(
            {
                "responses": [
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "protocolVersion": "test-version",
                            "capabilities": {},
                            "serverInfo": {"name": "fake-mcp", "version": "0.1.0"},
                        },
                    },
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "result": {
                            "tools": [
                                {
                                    "name": "safe_echo",
                                    "description": "Echo safe text.",
                                    "inputSchema": {"type": "object"},
                                }
                            ]
                        },
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["mcp", "tools", "list", "--fixture", str(fixture)])

    assert result.exit_code == 0
    output = json.loads(result.stdout)
    assert output["mode"] == "fixture"
    assert output["serverInfo"]["name"] == "fake-mcp"
    assert output["tools"][0]["name"] == "safe_echo"


def test_cli_validates_mcp_stdio_config_without_exposing_env_values(tmp_path) -> None:
    runner = CliRunner()
    config = tmp_path / "mcp-stdio.json"
    config.write_text(
        json.dumps(
            {
                "transport": "stdio",
                "command": ["fake-mcp-server", "--stdio"],
                "env": {"SAFE_SETTING": "local-only-value"},
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["mcp", "tools", "list", "--config", str(config)])

    assert result.exit_code == 0
    output = json.loads(result.stdout)
    assert output["mode"] == "dry-run"
    assert output["willExecuteProcess"] is False
    assert output["command"] == ["fake-mcp-server", "--stdio"]
    assert output["envKeys"] == ["SAFE_SETTING"]
    assert "local-only-value" not in result.stdout


def test_cli_rejects_mcp_stdio_shell_string_config(tmp_path) -> None:
    runner = CliRunner()
    config = tmp_path / "mcp-stdio.json"
    config.write_text(
        json.dumps({"transport": "stdio", "command": "fake-mcp-server --stdio"}),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["mcp", "tools", "list", "--config", str(config)])

    assert result.exit_code != 0
    assert "command" in result.output

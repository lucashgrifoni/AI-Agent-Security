"""Typer command-line application for aiasec."""

from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
import yaml
from pydantic import ValidationError

from aiasec import __version__
from aiasec.core.evaluator.rules import TargetObservation
from aiasec.core.gate import GateThresholds, gate_report
from aiasec.core.probe import Probe, load_probes_from_dir
from aiasec.core.runner import run_probes, run_probes_against
from aiasec.core.verdict import ProbeRunResult
from aiasec.mcp.config import McpStdioConfig, load_stdio_config
from aiasec.mcp.fixtures import load_jsonrpc_fixture
from aiasec.mcp.stdio import McpProtocolError, McpRemoteError, McpStdioAdapter
from aiasec.mcp.target import McpAgentTarget, McpTargetError
from aiasec.mcp.transport import McpTransportError
from aiasec.outputs.markdown import render_markdown
from aiasec.outputs.sarif import MCP_TARGET_MODE, SINGLE_OBSERVATION_MODE, render_sarif_json

DEFAULT_PROBES_DIR = Path(__file__).resolve().parents[1] / "probes"


class OutputFormat(StrEnum):
    """Supported report output formats."""

    auto = "auto"
    markdown = "markdown"
    sarif = "sarif"


app = typer.Typer(help="AI agent and MCP security regression testbed.")
probes_app = typer.Typer(help="Inspect bundled or custom probes.")
mcp_app = typer.Typer(help="Inspect MCP stdio targets through safe local fixtures.")
mcp_tools_app = typer.Typer(help="Inspect MCP tool metadata.")
app.add_typer(probes_app, name="probes")
app.add_typer(mcp_app, name="mcp")
mcp_app.add_typer(mcp_tools_app, name="tools")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"aiasec {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    """AI agent and MCP security regression testbed."""


def _probe_root(probes_dir: Path | None) -> Path:
    return probes_dir if probes_dir is not None else DEFAULT_PROBES_DIR


def _load_probes(probes_dir: Path | None) -> list[Probe]:
    try:
        return load_probes_from_dir(_probe_root(probes_dir))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        typer.echo(f"Failed to load probes: {exc}", err=True)
        raise typer.Exit(code=2) from exc


def _read_response(response: str | None, response_file: Path | None) -> str:
    if response is not None and response_file is not None:
        raise typer.BadParameter("Use either --response or --response-file, not both.")
    if response_file is not None:
        return response_file.read_text(encoding="utf-8")
    return response or ""


def _parse_tools(tools_called: str | None) -> list[str]:
    if not tools_called:
        return []
    return [tool.strip() for tool in tools_called.split(",") if tool.strip()]


def _resolve_format(output: Path, output_format: OutputFormat) -> OutputFormat:
    if output_format is not OutputFormat.auto:
        return output_format
    if output.suffix.lower() in {".sarif", ".json"}:
        return OutputFormat.sarif
    return OutputFormat.markdown


def _echo_json(payload: dict[str, object]) -> None:
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


def _load_fixture_transport(fixture: Path):
    try:
        return load_jsonrpc_fixture(fixture)
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc), param_hint="--fixture") from exc


def _load_config(config: Path) -> McpStdioConfig:
    try:
        return load_stdio_config(config)
    except (OSError, ValueError, ValidationError) as exc:
        raise typer.BadParameter(str(exc), param_hint="--config") from exc


def _run_against_target(
    probes: list[Probe],
    target: Path,
    *,
    execute: bool,
) -> list[ProbeRunResult]:
    try:
        config = load_stdio_config(target)
    except (OSError, ValueError) as exc:
        typer.echo(f"Invalid target config {target}: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    if not execute:
        typer.echo(
            f"Refusing to start {config.command!r} from {target}. Review the command, then "
            "pass --execute to let aiasec run it.",
            err=True,
        )
        raise typer.Exit(code=2)
    try:
        with McpAgentTarget.start(config) as agent:
            return run_probes_against(probes, agent.observe)
    except (
        McpProtocolError,
        McpRemoteError,
        McpTargetError,
        McpTransportError,
        OSError,
        ValueError,
    ) as exc:
        typer.echo(f"Target run failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc


def _render_stdio_dry_run(config_path: Path, config: McpStdioConfig) -> dict[str, object]:
    return {
        "config": str(config_path),
        "command": config.command,
        "cwd": str(config.cwd) if config.cwd is not None else None,
        "envKeys": sorted(config.env),
        "mode": "dry-run",
        "plannedRequests": ["initialize", "tools/list"],
        "transport": config.transport,
        "willExecuteProcess": False,
    }


@app.command()
def run(
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Report path. Uses suffix for --format auto."),
    ] = Path("aiasec-report.md"),
    probes_dir: Annotated[
        Path | None,
        typer.Option("--probes", help="Directory with probe YAML files."),
    ] = None,
    response: Annotated[
        str | None,
        typer.Option("--response", help="Observed assistant final response."),
    ] = None,
    response_file: Annotated[
        Path | None,
        typer.Option("--response-file", help="File containing observed assistant final response."),
    ] = None,
    tools_called: Annotated[
        str | None,
        typer.Option("--tools-called", help="Comma-separated observed tool names."),
    ] = None,
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", help="Report format."),
    ] = OutputFormat.auto,
    target: Annotated[
        Path | None,
        typer.Option(
            "--target",
            help="MCP stdio config of the agent under test. Sends each probe to it.",
        ),
    ] = None,
    execute: Annotated[
        bool,
        typer.Option("--execute", help="Allow aiasec to start the --target process."),
    ] = False,
) -> None:
    """Run probes against a live MCP target or a supplied observation."""

    if target is not None and (response, response_file, tools_called) != (None, None, None):
        typer.echo(
            "--target sends each probe to the target; it cannot be combined with "
            "--response, --response-file, or --tools-called.",
            err=True,
        )
        raise typer.Exit(code=2)

    probes = _load_probes(probes_dir)
    if not probes:
        typer.echo(
            f"No probes found under {_probe_root(probes_dir)}; refusing to write a report "
            "that tested nothing.",
            err=True,
        )
        raise typer.Exit(code=2)

    if target is not None:
        results = _run_against_target(probes, target, execute=execute)
        observation_mode = MCP_TARGET_MODE
    else:
        observation = TargetObservation(
            assistant_final_response=_read_response(response, response_file),
            tools_called=_parse_tools(tools_called),
        )
        results = run_probes(probes, observation)
        observation_mode = SINGLE_OBSERVATION_MODE
    rendered_format = _resolve_format(output, output_format)

    if rendered_format is OutputFormat.sarif:
        report = render_sarif_json(results, observation_mode=observation_mode)
    else:
        report = render_markdown(results, observation_mode=observation_mode)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")

    failed = sum(1 for result in results if not result.passed)
    typer.echo(f"Wrote {output} with {failed} failed probe(s).")
    if failed:
        raise typer.Exit(code=1)


@app.command()
def gate(
    report: Annotated[
        Path,
        typer.Option("--report", help="SARIF report to gate on."),
    ],
    max_critical: Annotated[
        int | None,
        typer.Option("--max-critical", help="Maximum tolerated critical findings."),
    ] = None,
    max_high: Annotated[
        int | None,
        typer.Option("--max-high", help="Maximum tolerated high findings."),
    ] = None,
    max_medium: Annotated[
        int | None,
        typer.Option("--max-medium", help="Maximum tolerated medium findings."),
    ] = None,
    max_low: Annotated[
        int | None,
        typer.Option("--max-low", help="Maximum tolerated low findings."),
    ] = None,
    exit_on_fail: Annotated[
        bool,
        typer.Option("--exit-on-fail", help="Exit with code 1 when the gate fails."),
    ] = False,
) -> None:
    """Apply release thresholds to a SARIF report and emit a verdict."""

    thresholds = GateThresholds(
        max_critical=max_critical,
        max_high=max_high,
        max_medium=max_medium,
        max_low=max_low,
    )
    try:
        decision = gate_report(report, thresholds)
    except (OSError, ValueError) as exc:
        typer.echo(f"Gate failed to read report: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    _echo_json(
        {
            "counts": decision.counts,
            "probesExecuted": decision.probes_executed,
            "report": str(report),
            "thresholds": thresholds.model_dump(exclude_none=True),
            "total": decision.total,
            "verdict": decision.verdict,
            "violations": [violation.model_dump() for violation in decision.violations],
        }
    )
    if not decision.passed and exit_on_fail:
        raise typer.Exit(code=1)


@probes_app.command("list")
def list_probes(
    probes_dir: Annotated[
        Path | None,
        typer.Option("--probes", help="Directory with probe YAML files."),
    ] = None,
) -> None:
    """List available probe identifiers."""

    for probe in _load_probes(probes_dir):
        typer.echo(f"{probe.id}\t{probe.severity}\t{probe.category}\t{probe.title}")


@probes_app.command("show")
def show_probe(
    probe_id: Annotated[str, typer.Argument(help="Probe identifier to show.")],
    probes_dir: Annotated[
        Path | None,
        typer.Option("--probes", help="Directory with probe YAML files."),
    ] = None,
) -> None:
    """Show one probe as normalized JSON."""

    for probe in _load_probes(probes_dir):
        if probe.id == probe_id:
            typer.echo(probe.model_dump_json(indent=2, by_alias=True))
            return
    typer.echo(f"Probe not found: {probe_id}", err=True)
    raise typer.Exit(code=2)


@mcp_tools_app.command("list")
def list_mcp_tools(
    fixture: Annotated[
        Path | None,
        typer.Option(
            "--fixture",
            help="Local JSON-RPC fixture with initialize and tools/list responses.",
        ),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            help="MCP stdio JSON config to validate in dry-run mode.",
        ),
    ] = None,
) -> None:
    """List MCP tools from a local fixture or validate stdio config without execution."""

    if (fixture is None) == (config is None):
        raise typer.BadParameter("Provide exactly one of --fixture or --config.")

    if config is not None:
        _echo_json(_render_stdio_dry_run(config, _load_config(config)))
        return

    if fixture is None:
        raise typer.BadParameter("Fixture path is required.")

    transport = _load_fixture_transport(fixture)
    client = McpStdioAdapter(transport)
    try:
        initialize_result = client.initialize()
        tools = client.list_tools()
    except (McpProtocolError, McpRemoteError, McpTransportError, ValueError) as exc:
        typer.echo(f"MCP fixture failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    finally:
        client.close()

    server_info = initialize_result.get("serverInfo", {})
    _echo_json(
        {
            "mode": "fixture",
            "serverInfo": server_info if isinstance(server_info, dict) else {},
            "tools": tools,
        }
    )

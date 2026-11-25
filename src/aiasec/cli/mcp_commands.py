"""`aiasec mcp tools`: list, snapshot, diff and audit the tools an MCP server exposes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any

import typer
from pydantic import ValidationError

from aiasec.cli.common import (
    _echo_json,
    _validation_message,
)
from aiasec.core.text import printable
from aiasec.mcp.audit import ALL_RULES, audit_tools
from aiasec.mcp.config import McpStdioConfig, load_stdio_config
from aiasec.mcp.fixtures import load_jsonrpc_fixture
from aiasec.mcp.stdio import (
    DEFAULT_PROBE_TIMEOUT_SECONDS,
    McpProtocolError,
    McpRemoteError,
    McpStdioAdapter,
)
from aiasec.mcp.tooldefs import compare_snapshots, load_snapshot, make_snapshot, tools_of
from aiasec.mcp.transport import McpTransportError, StdioProcessRunner
from aiasec.outputs.audit_sarif import render_audit_sarif_json

MCP_ERRORS = (McpProtocolError, McpRemoteError, McpTransportError, OSError, ValueError)

FixtureOption = Annotated[
    Path | None,
    typer.Option("--fixture", help="Local JSON-RPC fixture with initialize and tools/list."),
]
ConfigOption = Annotated[
    Path | None,
    typer.Option("--config", help="MCP stdio config of the server to start (needs --execute)."),
]
ExecuteOption = Annotated[
    bool,
    typer.Option("--execute", help="Allow aiasec to start the command in --config."),
]


def _load_fixture_transport(fixture: Path):
    try:
        return load_jsonrpc_fixture(fixture)
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc), param_hint="--fixture") from exc


def _load_config(config: Path) -> McpStdioConfig:
    try:
        return load_stdio_config(config)
    except ValidationError as exc:
        typer.echo(f"Invalid MCP stdio config {config}:\n{_validation_message(exc)}", err=True)
        raise typer.Exit(code=2) from exc
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc), param_hint="--config") from exc


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

    _, server_info, tools = _fetch_tools(fixture, None, execute=False)
    try:
        _echo_json({"mode": "fixture", "serverInfo": server_info, "tools": tools})
    except RecursionError as exc:  # the indenting encoder recurses once per nesting level
        typer.echo("Cannot list the tools: a definition nests too deeply to print", err=True)
        raise typer.Exit(code=2) from exc


def _fetch_tools(
    fixture: Path | None, config: Path | None, execute: bool
) -> tuple[str, dict[str, Any], list[dict[str, Any]]]:
    """Where the tools came from, the server's self-description, and its tools."""

    if (fixture is None) == (config is None):
        raise typer.BadParameter("Provide exactly one of --fixture or --config.")
    if fixture is not None:
        client = McpStdioAdapter(_load_fixture_transport(fixture))
        try:
            initialize_result = client.initialize()
            tools = client.list_tools()
        except MCP_ERRORS as exc:
            typer.echo(f"MCP fixture failed: {printable(str(exc))}", err=True)
            raise typer.Exit(code=2) from exc
        finally:
            client.close()
        server_info = initialize_result.get("serverInfo")
        return fixture.as_posix(), server_info if isinstance(server_info, dict) else {}, tools

    assert config is not None
    stdio = _load_config(config)
    if not execute:
        typer.echo(
            f"Refusing to start {stdio.command!r} from {config}. Review the config, then "
            "pass --execute to let aiasec run it.",
            err=True,
        )
        raise typer.Exit(code=2)
    try:
        transport = StdioProcessRunner(receive_timeout_seconds=stdio.timeout_seconds).start(
            stdio.command, cwd=stdio.cwd, env=stdio.env or None
        )
    except MCP_ERRORS as exc:
        typer.echo(f"MCP server failed to start: {printable(str(exc))}", err=True)
        raise typer.Exit(code=2) from exc
    client = McpStdioAdapter(transport, request_timeout=stdio.timeout_seconds)
    try:
        session = client.connect(
            mode=stdio.protocol,
            probe_timeout=min(DEFAULT_PROBE_TIMEOUT_SECONDS, stdio.timeout_seconds),
        )
        tools = client.list_tools()
    except MCP_ERRORS as exc:
        typer.echo(f"MCP server failed: {printable(str(exc))}", err=True)
        raise typer.Exit(code=2) from exc
    finally:
        client.close()
    return config.as_posix(), dict(session.server_info), tools


def snapshot_mcp_tools(
    output: Annotated[Path, typer.Option("--output", help="Snapshot file to write (JSON).")],
    fixture: FixtureOption = None,
    config: ConfigOption = None,
    execute: ExecuteOption = False,
) -> None:
    """Record a SHA-256 of every tool definition, to diff against a later run."""

    _, server_info, tools = _fetch_tools(fixture, config, execute)
    try:
        snapshot = make_snapshot(server_info, tools)
        text = json.dumps(snapshot, indent=2, sort_keys=True)
    except ValueError as exc:
        typer.echo(f"Cannot snapshot the tools: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except RecursionError as exc:  # the indenting encoder recurses once per nesting level
        typer.echo("Cannot snapshot the tools: a definition nests too deeply to write", err=True)
        raise typer.Exit(code=2) from exc
    output.write_text(text + "\n", encoding="utf-8")
    typer.echo(f"Wrote {output} with {len(snapshot['tools'])} tool(s).")


def diff_mcp_tools(
    baseline: Annotated[Path, typer.Option("--baseline", help="Earlier snapshot.")],
    current: Annotated[Path, typer.Option("--current", help="Later snapshot.")],
    exit_on_change: Annotated[
        bool,
        typer.Option("--exit-on-change", help="Exit 1 when a tool was added, removed or changed."),
    ] = False,
) -> None:
    """Name every tool added, removed or changed between two snapshots."""

    try:
        result = compare_snapshots(load_snapshot(baseline), load_snapshot(current))
    except (OSError, ValueError) as exc:
        typer.echo(f"Cannot compare the snapshots: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    _echo_json(result)
    if exit_on_change and result["verdict"] == "CHANGED":
        raise typer.Exit(code=1)


def audit_mcp_tools(
    output: Annotated[Path, typer.Option("--output", help="SARIF report to write.")],
    fixture: FixtureOption = None,
    config: ConfigOption = None,
    execute: ExecuteOption = False,
    snapshot: Annotated[
        Path | None, typer.Option("--snapshot", help="Audit the tools in a snapshot file.")
    ] = None,
    exit_on_finding: Annotated[
        bool, typer.Option("--exit-on-finding", help="Exit 1 when any rule matched.")
    ] = False,
) -> None:
    """Check every tool definition for hidden text and instructions aimed at the model."""

    if snapshot is not None:
        if fixture is not None or config is not None:
            raise typer.BadParameter("Provide exactly one of --fixture, --config or --snapshot.")
        try:
            tools = tools_of(load_snapshot(snapshot))
        except (OSError, ValueError) as exc:
            typer.echo(f"Cannot read the snapshot: {exc}", err=True)
            raise typer.Exit(code=2) from exc
        source = snapshot.as_posix()
    else:
        source, _, tools = _fetch_tools(fixture, config, execute)
    findings = audit_tools(tools)
    names = [str(tool.get("name", "")) for tool in tools]
    output.write_text(
        render_audit_sarif_json(findings, tools=names, source=source), encoding="utf-8"
    )
    for finding in findings:
        typer.echo(
            f"{finding.rule.id} {finding.rule.severity}: tool {finding.tool!r}, {finding.field}: "
            f"{finding.excerpt}"
        )
    typer.echo(
        f"Audited {len(tools)} tool(s) with {len(ALL_RULES)} rules: {len(findings)} "
        f"finding(s). Wrote {output}."
    )
    if exit_on_finding and findings:
        raise typer.Exit(code=1)

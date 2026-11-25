"""`aiasec mcp tools list`: read MCP tool metadata without starting a server."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from aiasec.cli.common import (
    _echo_json,
    _validation_message,
)
from aiasec.mcp.config import McpStdioConfig, load_stdio_config
from aiasec.mcp.fixtures import load_jsonrpc_fixture
from aiasec.mcp.stdio import McpProtocolError, McpRemoteError, McpStdioAdapter
from aiasec.mcp.transport import McpTransportError


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

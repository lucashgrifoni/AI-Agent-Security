"""Typer command-line application for aiasec: the command tree and its registration."""

from __future__ import annotations

from typing import Annotated

import typer

from aiasec import __version__
from aiasec.cli.mcp_commands import (
    audit_mcp_tools,
    diff_mcp_tools,
    list_mcp_tools,
    snapshot_mcp_tools,
)
from aiasec.cli.probe_commands import list_probes, show_probe, validate_probes
from aiasec.cli.report_commands import compare, gate
from aiasec.cli.run_command import run

app = typer.Typer(help="AI agent and MCP security regression testbed.")


probes_app = typer.Typer(help="Inspect bundled or custom probes.")


mcp_app = typer.Typer(help="Inspect MCP servers: list, snapshot, diff and audit their tools.")


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


app.command()(run)
app.command()(gate)
app.command()(compare)
probes_app.command("list")(list_probes)
probes_app.command("show")(show_probe)
probes_app.command("validate")(validate_probes)
mcp_tools_app.command("list")(list_mcp_tools)
mcp_tools_app.command("snapshot")(snapshot_mcp_tools)
mcp_tools_app.command("diff")(diff_mcp_tools)
mcp_tools_app.command("audit")(audit_mcp_tools)

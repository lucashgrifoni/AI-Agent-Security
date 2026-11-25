"""`aiasec probes list` and `aiasec probes show`."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from aiasec.cli.common import (
    CategoryOption,
    MinSeverityOption,
    ProbeIdOption,
    _load_probes,
    _select_probes,
)


def list_probes(
    probes_dir: Annotated[
        Path | None,
        typer.Option("--probes", help="Directory with probe YAML files."),
    ] = None,
    category: CategoryOption = None,
    min_severity: MinSeverityOption = None,
    probe_id: ProbeIdOption = None,
) -> None:
    """List available probe identifiers."""

    probes, _ = _select_probes(_load_probes(probes_dir), category, min_severity, probe_id)
    for probe in probes:
        typer.echo(f"{probe.id}\t{probe.severity}\t{probe.category}\t{probe.title}")


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

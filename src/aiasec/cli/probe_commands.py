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
from aiasec.core.probe_check import check_probe_dir
from aiasec.core.text import printable


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


def validate_probes(
    probes_dir: Annotated[Path, typer.Argument(help="Directory with probe YAML files to check.")],
) -> None:
    """Check a probe pack against the quality bar, without running it."""

    if not probes_dir.is_dir():
        typer.echo(f"Not a directory: {probes_dir}", err=True)
        raise typer.Exit(code=2)
    probes, problems = check_probe_dir(probes_dir)
    for problem in problems:
        where = problem.file + (f" ({problem.probe_id})" if problem.probe_id else "")
        typer.echo(printable(f"{where}: {problem.problem}", keep_newlines=False))
    typer.echo(f"Checked {len(probes)} probe(s): {len(problems)} problem(s).")
    if problems:
        raise typer.Exit(code=1)

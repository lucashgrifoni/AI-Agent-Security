"""Options, probe loading and output helpers shared by the commands."""

from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
import yaml
from pydantic import ValidationError

from aiasec.core.gate import (
    SEVERITY_ORDER,
)
from aiasec.core.probe import Probe, load_probes_from_dir

DEFAULT_PROBES_DIR = Path(__file__).resolve().parents[1] / "probes"


class OutputFormat(StrEnum):
    """Supported report output formats."""

    auto = "auto"
    markdown = "markdown"
    sarif = "sarif"
    html = "html"
    junit = "junit"


class MinSeverity(StrEnum):
    """Lowest probe severity to select."""

    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


CategoryOption = Annotated[
    str | None,
    typer.Option("--category", help="Only probes in these categories (comma-separated)."),
]


MinSeverityOption = Annotated[
    MinSeverity | None,
    typer.Option("--min-severity", help="Only probes at or above this severity."),
]


ProbeIdOption = Annotated[
    str | None,
    typer.Option("--probe-id", help="Only these probe ids (comma-separated)."),
]


def _probe_root(probes_dir: Path | None) -> Path:
    return probes_dir if probes_dir is not None else DEFAULT_PROBES_DIR


def _load_probes(probes_dir: Path | None) -> list[Probe]:
    try:
        return load_probes_from_dir(_probe_root(probes_dir))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        typer.echo(f"Failed to load probes: {exc}", err=True)
        raise typer.Exit(code=2) from exc


def _split(value: str | None) -> list[str]:
    return sorted({item.strip() for item in (value or "").split(",") if item.strip()})


def _select_probes(
    probes: list[Probe],
    category: str | None,
    min_severity: MinSeverity | None,
    probe_id: str | None,
) -> tuple[list[Probe], dict[str, object] | None]:
    """Apply the selection filters, refusing names that match no loaded probe.

    A typo must not quietly run a different subset, and an empty subset must not produce
    a clean report. Returns the probes and the selection to record in the report, or None
    when no filter was given.
    """

    # A blank name (an unset variable, a stray comma) means neither "no filter" nor "one name
    # fewer": either reading would run something other than what was asked for.
    options = (("--category", category), ("--probe-id", probe_id))
    blank = [
        option
        for option, given in options
        if given is not None and any(not part.strip() for part in given.split(","))
    ]
    if blank:
        typer.echo(f"{' and '.join(blank)} has an empty name; nothing was run.", err=True)
        raise typer.Exit(code=2)
    categories, probe_ids = _split(category), _split(probe_id)
    known_categories, known_ids = {p.category for p in probes}, {p.id for p in probes}
    unknown = [f"category {name}" for name in categories if name not in known_categories]
    unknown += [f"probe id {name}" for name in probe_ids if name not in known_ids]
    if unknown:
        typer.echo(f"Unknown {', '.join(unknown)}; nothing was run.", err=True)
        raise typer.Exit(code=2)

    selection: dict[str, object] = {}
    if categories:
        selection["categories"] = categories
    if min_severity is not None:
        selection["minSeverity"] = min_severity.value
    if probe_ids:
        selection["probeIds"] = probe_ids
    if not selection:
        return probes, None

    # SEVERITY_ORDER runs from critical down, so a lower index is more severe.
    ceiling = SEVERITY_ORDER.index(min_severity.value) if min_severity is not None else None
    selected = [
        probe
        for probe in probes
        if (not categories or probe.category in categories)
        and (not probe_ids or probe.id in probe_ids)
        and (ceiling is None or SEVERITY_ORDER.index(probe.severity) <= ceiling)
    ]
    if not selected:
        typer.echo(
            "No probe matches the selection; refusing to write a report that tested nothing.",
            err=True,
        )
        raise typer.Exit(code=2)
    return selected, selection


def _validation_message(exc: ValidationError) -> str:
    """One line per invalid field, without the values or pydantic's documentation links.

    A rejected value can be a credential (a header, an env entry), and the links say
    nothing about aiasec's config.
    """

    lines = []
    for error in exc.errors(include_url=False, include_input=False):
        field = ".".join(str(part) for part in error["loc"]) or "config"
        lines.append(f"  {field}: {error['msg'].removeprefix('Value error, ')}")
    return "\n".join(lines)


def _resolve_format(output: Path, output_format: OutputFormat) -> OutputFormat:
    if output_format is not OutputFormat.auto:
        return output_format
    suffix = output.suffix.lower()
    if suffix in {".sarif", ".json"}:
        return OutputFormat.sarif
    if suffix in {".html", ".htm"}:
        return OutputFormat.html
    if suffix == ".xml":
        return OutputFormat.junit
    return OutputFormat.markdown


def _echo_json(payload: dict[str, object]) -> None:
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))

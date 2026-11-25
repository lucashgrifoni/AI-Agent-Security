"""`aiasec gate` and `aiasec compare`: read SARIF reports and decide."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from aiasec.cli.common import (
    _echo_json,
)
from aiasec.core.compare import compare as compare_runs
from aiasec.core.compare import summarize
from aiasec.core.gate import (
    GateThresholds,
    PartialReportError,
    gate_report,
    load_sarif,
)


def gate(
    report: Annotated[
        Path,
        typer.Option("--report", help="SARIF report to gate on."),
    ],
    max_critical: Annotated[
        int | None,
        typer.Option("--max-critical", min=0, help="Maximum tolerated critical findings."),
    ] = None,
    max_high: Annotated[
        int | None,
        typer.Option("--max-high", min=0, help="Maximum tolerated high findings."),
    ] = None,
    max_medium: Annotated[
        int | None,
        typer.Option("--max-medium", min=0, help="Maximum tolerated medium findings."),
    ] = None,
    max_low: Annotated[
        int | None,
        typer.Option("--max-low", min=0, help="Maximum tolerated low findings."),
    ] = None,
    exit_on_fail: Annotated[
        bool,
        typer.Option("--exit-on-fail", help="Exit with code 1 when the gate fails."),
    ] = False,
    allow_partial: Annotated[
        bool,
        typer.Option(
            "--allow-partial",
            help="Gate a report of a probe subset (--category, --min-severity, --probe-id).",
        ),
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
        decision = gate_report(report, thresholds, allow_partial=allow_partial)
    except PartialReportError as exc:
        typer.echo(f"Gate refused the report: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except (OSError, ValueError) as exc:
        typer.echo(f"Gate failed to read report: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    payload: dict[str, object] = {
        "counts": decision.counts,
        "probesExecuted": decision.probes_executed,
        "report": str(report),
        "thresholds": thresholds.model_dump(exclude_none=True),
        "total": decision.total,
        "verdict": decision.verdict,
        "violations": [violation.model_dump() for violation in decision.violations],
    }
    if decision.selections:
        payload["selections"] = decision.selections
    _echo_json(payload)
    if not decision.passed and exit_on_fail:
        raise typer.Exit(code=1)


def compare(
    baseline: Annotated[
        Path,
        typer.Option("--baseline", help="SARIF report of an earlier run to compare against."),
    ],
    report: Annotated[
        Path,
        typer.Option("--report", help="SARIF report of this run."),
    ],
    exit_on_regression: Annotated[
        bool,
        typer.Option(
            "--exit-on-regression",
            help="Exit with code 1 on a regression, or on lost coverage without --allow-partial.",
        ),
    ] = False,
    allow_partial: Annotated[
        bool,
        typer.Option(
            "--allow-partial", help="Accept a report that ran fewer probes than the baseline."
        ),
    ] = False,
) -> None:
    """Compare the attack success rate and findings of two SARIF reports."""

    try:
        before, after = summarize(load_sarif(baseline)), summarize(load_sarif(report))
    except (OSError, ValueError) as exc:
        typer.echo(f"Cannot compare the reports: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    result = compare_runs(before, after)
    verdict = result.verdict(allow_partial=allow_partial)

    def summary(path: Path, run) -> dict[str, object]:
        return {
            "report": str(path),
            "probesExecuted": len(run.executed),
            "probesFailed": len(run.failed_probes),
            "attackSuccessRate": run.attack_success_rate,
        }

    _echo_json(
        {
            "attackSuccessRateDelta": round(
                after.attack_success_rate - before.attack_success_rate, 4
            ),
            "baseline": summary(baseline, before),
            "current": summary(report, after),
            "fixed": result.fixed,
            "newFindings": result.new_findings,
            "notEvaluated": result.not_evaluated,
            "notRun": result.not_run,
            "regressions": result.regressions,
            "verdict": verdict,
        }
    )
    if exit_on_regression and verdict != "NO REGRESSION":
        raise typer.Exit(code=1)

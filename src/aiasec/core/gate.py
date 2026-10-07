"""Release gate verdicts derived from a SARIF report."""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aiasec.core.probe import Severity
from aiasec.core.selection import describe_selection

SEVERITY_ORDER: tuple[Severity, ...] = ("critical", "high", "medium", "low")

# SARIF levels are coarser than probe severities, so this fallback is only used for
# reports that predate the severity property. It can never resolve to "critical".
LEVEL_TO_SEVERITY: dict[str, Severity] = {
    "error": "high",
    "warning": "medium",
    "note": "low",
}


class GateThresholds(BaseModel):
    """Maximum tolerated finding count per severity. None means unlimited."""

    model_config = ConfigDict(extra="forbid")

    max_critical: int | None = Field(default=None, ge=0)
    max_high: int | None = Field(default=None, ge=0)
    max_medium: int | None = Field(default=None, ge=0)
    max_low: int | None = Field(default=None, ge=0)

    def limit_for(self, severity: Severity) -> int | None:
        """Return the configured limit for one severity."""

        limit: int | None = getattr(self, f"max_{severity}")
        return limit


class PartialReportError(ValueError):
    """The report covers a selection of the suite and the caller did not allow that."""


class GateViolation(BaseModel):
    """One severity budget that the report exceeded."""

    model_config = ConfigDict(frozen=True)

    severity: Severity
    count: int
    limit: int


class GateDecision(BaseModel):
    """Release verdict for one report against one set of thresholds."""

    model_config = ConfigDict(frozen=True)

    counts: dict[str, int] = Field(default_factory=dict)
    violations: list[GateViolation] = Field(default_factory=list)
    probes_executed: int = 0
    # Filters each run of the report applied; empty for a run of the whole suite.
    selections: list[dict[str, Any]] = Field(default_factory=list)

    @property
    def total(self) -> int:
        """Return the total number of findings counted."""

        return sum(self.counts.values())

    @property
    def passed(self) -> bool:
        """Return whether every configured severity budget was respected."""

        return not self.violations

    @property
    def verdict(self) -> str:
        """Return the release verdict label."""

        return "PASS" if self.passed else "FAIL"


def load_sarif(path: Path) -> Any:
    """Load a SARIF report from disk."""

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Report is not valid JSON: {path}") from exc


def count_severities(document: Any) -> dict[str, int]:
    """Count SARIF results per probe severity."""

    counts: dict[str, int] = dict.fromkeys(SEVERITY_ORDER, 0)
    for result in _iter_results(document):
        counts[_severity_of(result)] += 1
    return counts


def evaluate_gate(counts: Mapping[str, int], thresholds: GateThresholds) -> GateDecision:
    """Compare severity counts against the configured budgets."""

    violations = [
        GateViolation(severity=severity, count=counts.get(severity, 0), limit=limit)
        for severity in SEVERITY_ORDER
        if (limit := thresholds.limit_for(severity)) is not None
        and counts.get(severity, 0) > limit
    ]
    return GateDecision(
        counts={severity: counts.get(severity, 0) for severity in SEVERITY_ORDER},
        violations=violations,
    )


def count_executed_probes(document: Any) -> int:
    """Return how many probes the report says were executed.

    SARIF only lists failures, so an empty result list cannot be told apart from a run
    that tested nothing. A report that does not record the executed count, or records
    zero, fails closed instead of passing a release gate.
    """

    total = 0
    for run in _iter_runs(document):
        properties = run.get("properties")
        aiasec = properties.get("aiasec") if isinstance(properties, dict) else None
        executed = aiasec.get("probesExecuted") if isinstance(aiasec, dict) else None
        if not isinstance(executed, int) or isinstance(executed, bool) or executed < 0:
            raise ValueError("SARIF run does not record how many aiasec probes were executed")
        total += executed
    if total == 0:
        raise ValueError("SARIF report records zero executed probes; nothing was tested")
    return total


def read_selections(document: Any) -> list[dict[str, Any]]:
    """Return the probe selection each run recorded, skipping runs of the whole suite.

    A selection that is present but does not have the shape `aiasec run` writes fails
    closed: it cannot be told apart from a subset, nor described.
    """

    selections = []
    for run in _iter_runs(document):
        properties = run.get("properties")
        aiasec = properties.get("aiasec") if isinstance(properties, dict) else None
        selection = aiasec.get("selection") if isinstance(aiasec, dict) else None
        if selection is None or selection == {}:
            continue
        if not _is_selection(selection):
            raise ValueError("SARIF run records a probe selection aiasec cannot read")
        selections.append(selection)
    return selections


def _is_selection(value: Any) -> bool:
    """Whether value has the shape `aiasec run` records: known filters, well typed."""

    def names(item: Any) -> bool:
        return isinstance(item, list) and bool(item) and all(
            isinstance(name, str) and name.strip() for name in item
        )

    checks = {
        "categories": names,
        "probeIds": names,
        "minSeverity": lambda item: item in SEVERITY_ORDER,
    }
    return isinstance(value, dict) and all(
        key in checks and checks[key](item) for key, item in value.items()
    )


def gate_report(
    path: Path, thresholds: GateThresholds, *, allow_partial: bool = False
) -> GateDecision:
    """Load a SARIF report and return its release verdict.

    A report of a probe subset raises PartialReportError unless allow_partial is set:
    thresholds met by part of the suite say nothing about the rest.
    """

    document = load_sarif(path)
    executed = count_executed_probes(document)
    selections = read_selections(document)
    if selections and not allow_partial:
        described = "; ".join(describe_selection(selection) for selection in selections)
        raise PartialReportError(
            f"report covers only part of the suite ({described}); gate the full suite, "
            "or pass --allow-partial to gate this subset on purpose"
        )
    decision = evaluate_gate(count_severities(document), thresholds)
    return decision.model_copy(update={"probes_executed": executed, "selections": selections})


def _iter_runs(document: Any) -> Iterator[dict[str, Any]]:
    if not isinstance(document, dict):
        raise ValueError("SARIF document must be a JSON object")

    runs = document.get("runs")
    if not isinstance(runs, list):
        raise ValueError("SARIF document must contain a runs list")

    for run in runs:
        if not isinstance(run, dict):
            raise ValueError("SARIF run must be a JSON object")
        yield run


def _iter_results(document: Any) -> Iterator[dict[str, Any]]:
    for run in _iter_runs(document):
        results = run.get("results", [])
        if not isinstance(results, list):
            raise ValueError("SARIF run results must be a list")
        for result in results:
            if not isinstance(result, dict):
                raise ValueError("SARIF result must be a JSON object")
            yield result


def _severity_of(result: Mapping[str, Any]) -> Severity:
    properties = result.get("properties")
    if isinstance(properties, dict):
        severity = properties.get("severity")
        if severity in SEVERITY_ORDER:
            return severity

    level = result.get("level")
    if isinstance(level, str) and level in LEVEL_TO_SEVERITY:
        return LEVEL_TO_SEVERITY[level]

    # Fail closed: an unreadable severity must never silently pass a release gate.
    raise ValueError("SARIF result has no readable severity property or level")

"""Compare two aiasec SARIF reports: attack success rate and what got worse.

The attack success rate (ASR) of a run is the share of executed probes that failed.
Findings are matched by expectation id (aiasec.core.probe.expectation_id), which
follows what a check checks, not where it sits in the probe file. Reports must record
which probes and checks ran (`executedProbes`, `executedExpectations`); without that,
"not failing" cannot be told from "not run". Only single-run reports, as `aiasec run`
writes them, are read.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aiasec.core.gate import _iter_results, _iter_runs


@dataclass(frozen=True)
class RunSummary:
    """What one report says ran and failed."""

    executed: tuple[str, ...]
    # expectation id -> (probe id, expectation kind) for every check that ran
    evaluated: dict[str, tuple[str, str]]
    # expectation id -> severity, for every check that failed
    findings: dict[str, str]

    @property
    def failed_probes(self) -> frozenset[str]:
        return frozenset(self.evaluated[check][0] for check in self.findings)

    @property
    def attack_success_rate(self) -> float:
        if not self.executed:
            return 0.0
        return round(len(self.failed_probes) / len(self.executed), 4)


@dataclass(frozen=True)
class Comparison:
    """The difference between a baseline run and the current run."""

    regressions: list[dict[str, str]]
    new_findings: list[dict[str, str]]
    fixed: list[dict[str, str]]
    not_run: list[str]
    not_evaluated: list[dict[str, str]]

    def verdict(self, *, allow_partial: bool) -> str:
        if self.regressions or self.new_findings:
            return "REGRESSION"
        if (self.not_run or self.not_evaluated) and not allow_partial:
            return "INCOMPLETE"
        return "NO REGRESSION"


def summarize(document: Any) -> RunSummary:
    """Read what a single-run report says ran and failed, failing closed."""

    runs = list(_iter_runs(document))
    if len(runs) != 1:
        raise ValueError(f"compare reads aiasec reports with one run; this one has {len(runs)}")
    properties = runs[0].get("properties")
    aiasec = properties.get("aiasec") if isinstance(properties, dict) else None
    probes = aiasec.get("executedProbes") if isinstance(aiasec, dict) else None
    checks = aiasec.get("executedExpectations") if isinstance(aiasec, dict) else None
    if not isinstance(probes, list) or not all(_name(probe) for probe in probes):
        raise ValueError(
            "report does not record which probes and checks ran (executedProbes, "
            "executedExpectations); re-run it with aiasec 0.3 or later"
        )
    if len(set(probes)) != len(probes):
        raise ValueError("report lists a probe as executed more than once")
    if not isinstance(checks, list):
        checks = [None]  # reported below as unreadable
    evaluated: dict[str, tuple[str, str]] = {}
    for check in checks:
        fields = _check_fields(check)
        if fields is None or fields[1] not in probes:
            raise ValueError("report does not record which checks ran in a form aiasec reads")
        evaluated[fields[0]] = (fields[1], fields[2])
    findings: dict[str, str] = {}
    for result in _iter_results(document):
        details = result.get("properties")
        details = details if isinstance(details, dict) else {}
        check = details.get("expectationId")
        if not _name(check) or check not in evaluated:
            raise ValueError("report has a finding for a check it does not record as run")
        if evaluated[check][0] != result.get("ruleId"):
            raise ValueError("report has a finding whose probe does not match its check")
        findings[check] = str(details.get("severity", ""))
    return RunSummary(tuple(probes), evaluated, findings)


def compare(baseline: RunSummary, current: RunSummary) -> Comparison:
    """Classify every difference between two runs, check by check."""

    def entry(check: str, summary: RunSummary) -> dict[str, str]:
        probe, kind = summary.evaluated[check]
        severity = summary.findings.get(check, "")
        return {"probeId": probe, "expectation": kind, "expectationId": check,
                "severity": severity}  # fmt: skip

    def ordered(checks: set[str], summary: RunSummary) -> list[dict[str, str]]:
        return [
            entry(check, summary) for check in sorted(checks, key=lambda c: summary.evaluated[c])
        ]

    added = set(current.findings) - set(baseline.findings)
    gone = set(baseline.findings) - set(current.findings)
    ran_now = set(current.executed)
    return Comparison(
        regressions=ordered({c for c in added if c in baseline.evaluated}, current),
        new_findings=ordered({c for c in added if c not in baseline.evaluated}, current),
        fixed=ordered({c for c in gone if c in current.evaluated}, baseline),
        not_run=sorted(set(baseline.executed) - ran_now),
        # Checks of probes that still ran but were removed or changed since the baseline.
        not_evaluated=ordered(
            {
                check
                for check, (probe, _) in baseline.evaluated.items()
                if probe in ran_now and check not in current.evaluated
            },
            baseline,
        ),
    )


def _name(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _check_fields(check: Any) -> tuple[str, str, str] | None:
    """(id, probe id, expectation kind) of one executedExpectations entry, if well formed."""

    if not isinstance(check, dict):
        return None
    check_id, probe, kind = (check.get(key) for key in ("id", "probeId", "expectation"))
    if _name(check_id) and _name(probe) and _name(kind):
        return check_id, probe, kind
    return None

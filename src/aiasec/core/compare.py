"""Compare two aiasec SARIF reports: attack success rate and what got worse.

The attack success rate (ASR) of a run is the share of executed probes that failed.
A finding is identified by its probe and expectation (the aiasecFinding/v1
fingerprint), so the same failure in both runs is not new. Reports must record which
probes ran (`executedProbes`); without it, "not failing" cannot be told from "not run".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aiasec.core.gate import _iter_results, _iter_runs
from aiasec.outputs.sarif import FINGERPRINT_KEY


@dataclass(frozen=True)
class RunSummary:
    """What one report says ran and failed."""

    executed: tuple[str, ...]
    failed_probes: frozenset[str]
    # fingerprint -> (probe id, expectation kind, severity)
    findings: dict[str, tuple[str, str, str]] = field(default_factory=dict)

    @property
    def attack_success_rate(self) -> float:
        return round(len(self.failed_probes) / len(self.executed), 4) if self.executed else 0.0


@dataclass(frozen=True)
class Comparison:
    """The difference between a baseline run and the current run."""

    baseline: RunSummary
    current: RunSummary
    regressions: list[dict[str, str]]
    new_probe_findings: list[dict[str, str]]
    fixed: list[dict[str, str]]
    not_run: list[str]

    def verdict(self, *, allow_partial: bool) -> str:
        if self.regressions or self.new_probe_findings:
            return "REGRESSION"
        if self.not_run and not allow_partial:
            return "INCOMPLETE"
        return "NO REGRESSION"


def summarize(document: Any) -> RunSummary:
    """Read the executed probes and findings of a report, failing closed."""

    executed: list[str] = []
    for run in _iter_runs(document):
        properties = run.get("properties")
        aiasec = properties.get("aiasec") if isinstance(properties, dict) else None
        ids = aiasec.get("executedProbes") if isinstance(aiasec, dict) else None
        if not isinstance(ids, list) or not all(isinstance(item, str) for item in ids):
            raise ValueError(
                "report does not record which probes ran (executedProbes); "
                "re-run it with aiasec 0.3 or later"
            )
        executed.extend(ids)
    findings: dict[str, tuple[str, str, str]] = {}
    for result in _iter_results(document):
        probe = result.get("ruleId")
        prints = result.get("partialFingerprints")
        fingerprint = prints.get(FINGERPRINT_KEY) if isinstance(prints, dict) else None
        properties = result.get("properties")
        if not isinstance(probe, str) or not isinstance(fingerprint, str):
            raise ValueError("report has a result without a probe id or aiasec fingerprint")
        details = properties if isinstance(properties, dict) else {}
        findings[fingerprint] = (
            probe,
            str(details.get("expectation", "")),
            str(details.get("severity", "")),
        )
    failed = frozenset(probe for probe, _, _ in findings.values())
    if not failed <= set(executed):
        raise ValueError("report lists a finding for a probe it does not record as run")
    return RunSummary(tuple(executed), failed, findings)


def compare(baseline: RunSummary, current: RunSummary) -> Comparison:
    """Classify every finding difference between two runs."""

    def entry(fingerprint: str, summary: RunSummary) -> dict[str, str]:
        probe, expectation, severity = summary.findings[fingerprint]
        return {"probeId": probe, "expectation": expectation, "severity": severity}

    before, after = set(baseline.findings), set(current.findings)
    ran_before, ran_now = set(baseline.executed), set(current.executed)
    added = sorted(after - before, key=lambda key: current.findings[key])
    return Comparison(
        baseline=baseline,
        current=current,
        regressions=[
            entry(key, current) for key in added if current.findings[key][0] in ran_before
        ],
        new_probe_findings=[
            entry(key, current) for key in added if current.findings[key][0] not in ran_before
        ],
        fixed=[
            entry(key, baseline)
            for key in sorted(before - after, key=lambda key: baseline.findings[key])
            if baseline.findings[key][0] in ran_now
        ],
        not_run=sorted(ran_before - ran_now),
    )

"""Probe runner orchestration."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor

from aiasec.core.evaluator.rules import TargetObservation, evaluate_probe
from aiasec.core.probe import Probe
from aiasec.core.verdict import Finding, ProbeRunResult


def run_probes(probes: Iterable[Probe], observation: TargetObservation) -> list[ProbeRunResult]:
    """Run probes against one observed target behavior."""

    return [evaluate_probe(probe, observation) for probe in probes]


def run_probes_against(
    probes: Iterable[Probe],
    observe: Callable[[Probe], TargetObservation],
    *,
    repeat: int = 1,
    concurrency: int = 1,
) -> list[ProbeRunResult]:
    """Send each probe to a target and evaluate the behavior it observed for that probe.

    With `repeat`, each probe runs that many times and fails if any run failed; the
    result keeps how many runs failed. With `concurrency`, that many probes are in
    flight at once; results keep the order of `probes` either way.
    """

    if repeat < 1 or concurrency < 1:
        raise ValueError("repeat and concurrency must be at least 1")

    def run_one(probe: Probe) -> ProbeRunResult:
        outcomes = [evaluate_probe(probe, observe(probe)) for _ in range(repeat)]
        return _merge(probe, outcomes)

    if concurrency == 1:
        return [run_one(probe) for probe in probes]
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        return list(pool.map(run_one, probes))


def _merge(probe: Probe, outcomes: list[ProbeRunResult]) -> ProbeRunResult:
    """One result for the runs of a probe: each failed expectation once, and the counts."""

    if len(outcomes) == 1:
        return outcomes[0]
    findings: dict[int, Finding] = {}
    for outcome in outcomes:
        for finding in outcome.findings:
            findings.setdefault(finding.expectation_index, finding)
    return ProbeRunResult(
        probe=probe,
        findings=[findings[index] for index in sorted(findings)],
        runs=len(outcomes),
        failed_runs=sum(1 for outcome in outcomes if not outcome.passed),
    )


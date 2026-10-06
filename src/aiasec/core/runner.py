"""Probe runner orchestration."""

from __future__ import annotations

from collections.abc import Callable, Iterable

from aiasec.core.evaluator.rules import TargetObservation, evaluate_probe
from aiasec.core.probe import Probe
from aiasec.core.verdict import ProbeRunResult


def run_probes(probes: Iterable[Probe], observation: TargetObservation) -> list[ProbeRunResult]:
    """Run probes against one observed target behavior."""

    return [evaluate_probe(probe, observation) for probe in probes]


def run_probes_against(
    probes: Iterable[Probe],
    observe: Callable[[Probe], TargetObservation],
) -> list[ProbeRunResult]:
    """Send each probe to a target and evaluate the behavior it observed for that probe."""

    return [evaluate_probe(probe, observe(probe)) for probe in probes]


"""Probe runner orchestration."""

from __future__ import annotations

from collections.abc import Iterable

from aiasec.core.evaluator.rules import TargetObservation, evaluate_probe
from aiasec.core.probe import Probe
from aiasec.core.verdict import ProbeRunResult


def run_probes(probes: Iterable[Probe], observation: TargetObservation) -> list[ProbeRunResult]:
    """Run probes against one observed target behavior."""

    return [evaluate_probe(probe, observation) for probe in probes]


"""Deterministic rules-only evaluator."""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field

from aiasec.core.probe import Probe, ProbeExpectation
from aiasec.core.verdict import Finding, ProbeRunResult

SUPPORTED_KINDS = {"regex_not_match", "regex_match", "tool_not_called", "tool_called"}
SUPPORTED_OBSERVATION_FIELDS = {"assistant_final_response"}


class TargetObservation(BaseModel):
    """Observed target behavior supplied to the rules evaluator."""

    model_config = ConfigDict(extra="forbid")

    assistant_final_response: str = ""
    tools_called: list[str] = Field(default_factory=list)


def evaluate_probe(probe: Probe, observation: TargetObservation) -> ProbeRunResult:
    """Evaluate one probe against observed behavior."""

    findings = [
        finding
        for expectation in probe.expectations
        if (finding := _evaluate_expectation(probe, expectation, observation)) is not None
    ]
    return ProbeRunResult(probe=probe, findings=findings)


def _evaluate_expectation(
    probe: Probe,
    expectation: ProbeExpectation,
    observation: TargetObservation,
) -> Finding | None:
    if expectation.kind not in SUPPORTED_KINDS:
        return _finding(probe, expectation, f"Unsupported expectation kind: {expectation.kind}")

    if expectation.kind.startswith("regex_"):
        return _evaluate_regex(probe, expectation, observation)

    return _evaluate_tool_call(probe, expectation, observation)


def _evaluate_regex(
    probe: Probe,
    expectation: ProbeExpectation,
    observation: TargetObservation,
) -> Finding | None:
    if expectation.on not in SUPPORTED_OBSERVATION_FIELDS:
        return _finding(probe, expectation, f"Unsupported observation field: {expectation.on}")
    if not expectation.pattern:
        return _finding(probe, expectation, "Regex expectation is missing pattern")

    matched = re.search(expectation.pattern, observation.assistant_final_response) is not None
    if expectation.kind == "regex_not_match" and matched:
        return _finding(probe, expectation, "Assistant response matched a forbidden pattern")
    if expectation.kind == "regex_match" and not matched:
        return _finding(probe, expectation, "Assistant response did not match a required pattern")
    return None


def _evaluate_tool_call(
    probe: Probe,
    expectation: ProbeExpectation,
    observation: TargetObservation,
) -> Finding | None:
    if not expectation.tool_name:
        return _finding(probe, expectation, "Tool expectation is missing tool_name")

    called = expectation.tool_name in observation.tools_called
    if expectation.kind == "tool_not_called" and called:
        return _finding(probe, expectation, f"Forbidden tool was called: {expectation.tool_name}")
    if expectation.kind == "tool_called" and not called:
        return _finding(
            probe,
            expectation,
            f"Required tool was not called: {expectation.tool_name}",
        )
    return None


def _finding(probe: Probe, expectation: ProbeExpectation, message: str) -> Finding:
    return Finding(
        probe_id=probe.id,
        title=probe.title,
        category=probe.category,
        severity=probe.severity,
        message=message,
        expectation=expectation.kind,
        owasp_llm=probe.metadata.get("owasp_llm"),
    )

"""Evaluation verdict models."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from aiasec.core.probe import Probe, Severity


class Finding(BaseModel):
    """A failed probe expectation."""

    model_config = ConfigDict(frozen=True)

    probe_id: str
    title: str
    category: str
    severity: Severity
    message: str
    expectation: str
    owasp_llm: str | None = None
    owasp_mcp: str | None = None
    owasp_agentic: str | None = None
    mitre_atlas: str | None = None
    expectation_index: int = 0
    source: str | None = None


class ProbeRunResult(BaseModel):
    """Evaluation result for one probe."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    probe: Probe
    findings: list[Finding]
    # With --repeat: how many times the probe ran, and in how many runs it failed.
    runs: int = 1
    failed_runs: int | None = None

    @property
    def failures(self) -> int:
        """Runs in which the probe failed (0 or 1 for a single run)."""

        if self.failed_runs is not None:
            return self.failed_runs
        return 0 if self.passed else 1

    @property
    def passed(self) -> bool:
        """Return whether the probe produced no findings."""

        return not self.findings


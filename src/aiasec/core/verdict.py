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
    expectation_index: int = 0
    source: str | None = None


class ProbeRunResult(BaseModel):
    """Evaluation result for one probe."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    probe: Probe
    findings: list[Finding]

    @property
    def passed(self) -> bool:
        """Return whether the probe produced no findings."""

        return not self.findings


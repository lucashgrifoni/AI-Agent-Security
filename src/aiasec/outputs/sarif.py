"""SARIF 2.1.0 report renderer."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from aiasec import __version__
from aiasec.core.verdict import Finding, ProbeRunResult

SARIF_VERSION = "2.1.0"


def render_sarif(results: Sequence[ProbeRunResult]) -> dict[str, Any]:
    """Render failed findings as a SARIF 2.1.0 document."""

    findings = [finding for result in results for finding in result.findings]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "aiasec",
                        "version": __version__,
                        "informationUri": "https://github.com/lucashgrifoni/AI-Agent-Security",
                        "rules": [_rule(finding) for finding in _deduplicate_findings(findings)],
                    }
                },
                "results": [_result(finding) for finding in findings],
            }
        ],
    }


def render_sarif_json(results: Sequence[ProbeRunResult]) -> str:
    """Render SARIF as stable pretty JSON."""

    return json.dumps(render_sarif(results), indent=2, sort_keys=True) + "\n"


def _deduplicate_findings(findings: Sequence[Finding]) -> list[Finding]:
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in findings:
        if finding.probe_id in seen:
            continue
        seen.add(finding.probe_id)
        unique.append(finding)
    return unique


def _rule(finding: Finding) -> dict[str, Any]:
    properties: dict[str, str] = {
        "category": finding.category,
        "severity": finding.severity,
    }
    if finding.owasp_llm:
        properties["owasp_llm"] = finding.owasp_llm

    return {
        "id": finding.probe_id,
        "name": finding.title,
        "shortDescription": {"text": finding.title},
        "properties": properties,
    }


def _result(finding: Finding) -> dict[str, Any]:
    properties: dict[str, str] = {
        "category": finding.category,
        "expectation": finding.expectation,
        "severity": finding.severity,
    }
    if finding.owasp_llm:
        properties["owasp_llm"] = finding.owasp_llm

    return {
        "ruleId": finding.probe_id,
        "level": _sarif_level(finding.severity),
        "message": {"text": finding.message},
        "properties": properties,
    }


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


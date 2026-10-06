"""SARIF 2.1.0 report renderer."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from typing import Any

from aiasec import __version__
from aiasec.core.verdict import Finding, ProbeRunResult

SARIF_VERSION = "2.1.0"
FINGERPRINT_KEY = "aiasecFinding/v1"
# Today every probe is scored against one supplied observation; no attack is sent.
OBSERVATION_MODE = "single-observation"


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
                "invocations": [{"executionSuccessful": True}],
                # SARIF lists only failures, so a run that tested nothing would look clean.
                # The executed count lets a gate tell "no findings" from "nothing ran".
                "properties": {
                    "aiasec": {
                        "probesExecuted": len(results),
                        "probesFailed": sum(1 for result in results if not result.passed),
                        "observationMode": OBSERVATION_MODE,
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

    # GitHub code scanning only displays results that carry a location, so every result
    # points at the probe file that defines the failed expectation.
    source = finding.source or f"{finding.category}/{finding.probe_id}.yaml"
    return {
        "ruleId": finding.probe_id,
        "level": _sarif_level(finding.severity),
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": source},
                    "region": {"startLine": 1},
                }
            }
        ],
        "partialFingerprints": {FINGERPRINT_KEY: _fingerprint(finding)},
        "properties": properties,
    }


def _fingerprint(finding: Finding) -> str:
    identity = f"{finding.probe_id}:{finding.expectation_index}:{finding.expectation}"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


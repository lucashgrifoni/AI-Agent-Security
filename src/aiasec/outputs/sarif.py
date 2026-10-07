"""SARIF 2.1.0 report renderer."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from aiasec import __version__
from aiasec.core.probe import expectation_id
from aiasec.core.verdict import Finding, ProbeRunResult

SARIF_VERSION = "2.1.0"
FINGERPRINT_KEY = "aiasecFinding/v1"
# Every probe scored against one supplied observation; no attack was sent anywhere.
SINGLE_OBSERVATION_MODE = "single-observation"
# Each probe's inputs were sent to a live target over MCP stdio.
MCP_TARGET_MODE = "mcp-stdio-target"
# Each probe's inputs were POSTed to a live target over HTTP.
HTTP_TARGET_MODE = "http-target"


def render_sarif(
    results: Sequence[ProbeRunResult],
    *,
    observation_mode: str = SINGLE_OBSERVATION_MODE,
    selection: Mapping[str, object] | None = None,
) -> dict[str, Any]:
    """Render failed findings as a SARIF 2.1.0 document."""

    findings = [finding for result in results for finding in result.findings]
    run_properties: dict[str, Any] = {
        "probesExecuted": len(results),
        "probesFailed": sum(1 for result in results if not result.passed),
        # What ran, check by check, so a later report can be compared with this one.
        "executedProbes": [result.probe.id for result in results],
        "executedExpectations": [
            {
                "id": expectation_id(result.probe.id, expectation),
                "probeId": result.probe.id,
                "expectation": expectation.kind,
            }
            for result in results
            for expectation in result.probe.expectations
        ],
        "observationMode": observation_mode,
    }
    # The gate only sees counts; a run limited to a subset of the suite must say so.
    if selection:
        run_properties["selection"] = dict(selection)
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
                "properties": {"aiasec": run_properties},
                "results": [
                    _result(finding, _check_id(result, finding))
                    for result in results
                    for finding in result.findings
                ],
            }
        ],
    }


def render_sarif_json(
    results: Sequence[ProbeRunResult],
    *,
    observation_mode: str = SINGLE_OBSERVATION_MODE,
    selection: Mapping[str, object] | None = None,
) -> str:
    """Render SARIF as stable pretty JSON."""

    document = render_sarif(results, observation_mode=observation_mode, selection=selection)
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def _check_id(result: ProbeRunResult, finding: Finding) -> str:
    expectation = result.probe.expectations[finding.expectation_index]
    return expectation_id(result.probe.id, expectation)


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
    if finding.owasp_mcp:
        properties["owasp_mcp"] = finding.owasp_mcp

    return {
        "id": finding.probe_id,
        "name": finding.title,
        "shortDescription": {"text": finding.title},
        "properties": properties,
    }


def _result(finding: Finding, check: str) -> dict[str, Any]:
    properties: dict[str, str] = {
        "category": finding.category,
        "expectation": finding.expectation,
        "expectationId": check,
        "severity": finding.severity,
    }
    if finding.owasp_llm:
        properties["owasp_llm"] = finding.owasp_llm
    if finding.owasp_mcp:
        properties["owasp_mcp"] = finding.owasp_mcp

    # GitHub code scanning only displays results that carry a location, so every result
    # points at the probe file that defines the failed expectation.
    source = finding.source or f"{finding.category}/{finding.probe_id}.yaml"
    fingerprint = _fingerprint(finding)
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
        # GitHub code scanning matches alerts on primaryLocationLineHash alone. Left out,
        # upload-sarif hashes the location line, which is the same for every expectation
        # of a probe, so two failed expectations would merge into one alert.
        "partialFingerprints": {
            "primaryLocationLineHash": fingerprint,
            FINGERPRINT_KEY: fingerprint,
        },
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


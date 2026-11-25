"""SARIF 2.1.0 report renderer."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from aiasec import __version__
from aiasec.core.probe import Probe, expectation_id
from aiasec.core.verdict import Finding, ProbeRunResult

SARIF_VERSION = "2.1.0"
FINGERPRINT_KEY = "aiasecFinding/v1"
# Every probe scored against one supplied observation; no attack was sent anywhere.
SINGLE_OBSERVATION_MODE = "single-observation"
# Each probe's inputs were sent to a live target over MCP stdio.
MCP_TARGET_MODE = "mcp-stdio-target"
# Each probe's inputs were POSTed to a live target over HTTP.
HTTP_TARGET_MODE = "http-target"
# Each probe's inputs were sent to a model API; tool calls were recorded, never run.
MODEL_API_TARGET_MODE = "model-api-target"
# GitHub code scanning ranks a rule by this score: above 9.0 is critical, 7.0 to 8.9
# high, 4.0 to 6.9 medium, 0.1 to 3.9 low.
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}
OWASP_KEYS = ("owasp_llm", "owasp_mcp", "owasp_agentic")


def render_sarif(
    results: Sequence[ProbeRunResult],
    *,
    observation_mode: str = SINGLE_OBSERVATION_MODE,
    selection: Mapping[str, object] | None = None,
    judge: Mapping[str, object] | None = None,
) -> dict[str, Any]:
    """Render failed findings as a SARIF 2.1.0 document."""

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
    # Advisory opinions of an LLM judge; the gate never reads them.
    if judge:
        run_properties["judge"] = dict(judge)
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
                        "rules": [_rule(probe) for probe in _failed_probes(results)],
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
    judge: Mapping[str, object] | None = None,
) -> str:
    """Render SARIF as stable pretty JSON."""

    document = render_sarif(
        results, observation_mode=observation_mode, selection=selection, judge=judge
    )
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def _check_id(result: ProbeRunResult, finding: Finding) -> str:
    expectation = result.probe.expectations[finding.expectation_index]
    return expectation_id(result.probe.id, expectation)


def _failed_probes(results: Sequence[ProbeRunResult]) -> list[Probe]:
    """Each probe with a finding, once, in run order."""

    seen: set[str] = set()
    probes: list[Probe] = []
    for result in results:
        if result.findings and result.probe.id not in seen:
            seen.add(result.probe.id)
            probes.append(result.probe)
    return probes


def _owasp_tags(finding: Finding) -> dict[str, str]:
    tags = {
        "owasp_llm": finding.owasp_llm,
        "owasp_mcp": finding.owasp_mcp,
        "owasp_agentic": finding.owasp_agentic,
    }
    return {key: value for key, value in tags.items() if value}


def _rule(probe: Probe) -> dict[str, Any]:
    owasp = {key: probe.metadata[key] for key in OWASP_KEYS if probe.metadata.get(key)}
    rule: dict[str, Any] = {
        "id": probe.id,
        "name": probe.title,
        "shortDescription": {"text": probe.title},
        "fullDescription": {"text": _description(probe)},
        "help": {"text": _help(probe, markdown=False), "markdown": _help(probe, markdown=True)},
        "properties": {
            "category": probe.category,
            "severity": probe.severity,
            **owasp,
            "security-severity": SECURITY_SEVERITY[probe.severity],
            "tags": ["security", "ai-agent", probe.category, *owasp.values()],
        },
    }
    if probe.references:
        rule["helpUri"] = probe.references[0]
    return rule


def _description(probe: Probe) -> str:
    if probe.judge:
        return f"{probe.title}. The probe fails when the agent shows this behavior: {probe.judge}"
    return f"{probe.title}. The probe fails when the agent's reply or tool calls break its rule."


def _help(probe: Probe, *, markdown: bool) -> str:
    """What the rule checks, how to reproduce one failure, and where to read more."""

    code = (lambda text: f"`{text}`") if markdown else (lambda text: text)
    owasp = ", ".join(probe.metadata[key] for key in OWASP_KEYS if probe.metadata.get(key))
    lines = [
        _description(probe),
        "",
        f"Probe {code(probe.id)}, category {probe.category}, severity {probe.severity}"
        + (f", OWASP {owasp}." if owasp else "."),
        "",
        "Read the probe and rerun it alone against your target:",
        "",
        code(f"aiasec probes show {probe.id}"),
        code(f"aiasec run --target <target config> --execute --probe-id {probe.id}"),
    ]
    if probe.references:
        lines += ["", "References:", *(f"- {reference}" for reference in probe.references)]
    return "\n".join(lines)


def _result(finding: Finding, check: str) -> dict[str, Any]:
    properties: dict[str, str] = {
        "category": finding.category,
        "expectation": finding.expectation,
        "expectationId": check,
        "severity": finding.severity,
        **_owasp_tags(finding),
    }

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


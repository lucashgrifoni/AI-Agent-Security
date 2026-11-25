"""SARIF 2.1.0 for an MCP tool definition audit, readable by `aiasec gate`.

Each audit rule is one check run against every tool, so the run records the rules as
executed probes and their count as `probesExecuted`: the gate can then tell "nothing
matched" from "nothing ran", as it does for probe reports.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from typing import Any

from aiasec import __version__
from aiasec.mcp.audit import ALL_RULES, AuditFinding, AuditRule
from aiasec.outputs.sarif import FINGERPRINT_KEY, SECURITY_SEVERITY, _sarif_level

AUDIT_MODE = "mcp-tools-audit"


def render_audit_sarif_json(
    findings: Sequence[AuditFinding], *, tools: Sequence[str], source: str
) -> str:
    """The audit as pretty, stable SARIF JSON. `source` is the file the tools came from."""

    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "aiasec",
                        "version": __version__,
                        "informationUri": "https://github.com/lucashgrifoni/AI-Agent-Security",
                        "rules": [_rule(rule) for rule in ALL_RULES],
                    }
                },
                "invocations": [{"executionSuccessful": True}],
                "properties": {
                    "aiasec": {
                        "observationMode": AUDIT_MODE,
                        "probesExecuted": len(ALL_RULES),
                        "probesFailed": len({finding.rule.id for finding in findings}),
                        "executedProbes": [rule.id for rule in ALL_RULES],
                        "auditedTools": list(tools),
                    }
                },
                "results": [_result(finding, source) for finding in findings],
            }
        ],
    }
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def _rule(rule: AuditRule) -> dict[str, Any]:
    return {
        "id": rule.id,
        "name": rule.title,
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.help},
        "help": {"text": rule.help, "markdown": rule.help},
        "properties": {
            "severity": rule.severity,
            "security-severity": SECURITY_SEVERITY[rule.severity],
            "tags": ["security", "mcp", "tool-definition"],
        },
    }


def _result(finding: AuditFinding, source: str) -> dict[str, Any]:
    identity = f"{finding.rule.id}:{finding.tool}:{finding.field}"
    fingerprint = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return {
        "ruleId": finding.rule.id,
        "level": _sarif_level(finding.rule.severity),
        "message": {
            "text": f"{finding.rule.title}: tool {finding.tool!r}, {finding.field}: "
            f"{finding.excerpt}"
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": source},
                    "region": {"startLine": 1},
                }
            }
        ],
        "partialFingerprints": {
            "primaryLocationLineHash": fingerprint,
            FINGERPRINT_KEY: fingerprint,
        },
        "properties": {
            "severity": finding.rule.severity,
            "tool": finding.tool,
            "field": finding.field,
        },
    }

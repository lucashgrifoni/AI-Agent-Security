"""Markdown report renderer."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence

from aiasec.core.verdict import ProbeRunResult
from aiasec.outputs.sarif import OBSERVATION_MODE


def render_markdown(results: Sequence[ProbeRunResult]) -> str:
    """Render probe results as a compact Markdown report."""

    total = len(results)
    failed_results = [result for result in results if not result.passed]
    finding_count = sum(len(result.findings) for result in failed_results)
    severity_counts = Counter(finding.severity for result in results for finding in result.findings)

    lines = [
        "# aiasec report",
        "",
        "## Summary",
        "",
        f"- Probes: {total}",
        f"- Failed probes: {len(failed_results)}",
        f"- Findings: {finding_count}",
        f"- Observation mode: {OBSERVATION_MODE}",
        "",
        "Every probe was scored against the same supplied observation. A passing probe means",
        "that observation did not trigger it, not that its attack was sent to a target.",
        "",
        "## Severity",
        "",
    ]

    for severity in ("critical", "high", "medium", "low"):
        lines.append(f"- {severity}: {severity_counts.get(severity, 0)}")

    lines.extend(["", "## Results", ""])
    if not failed_results:
        lines.append("No failed probes.")
        return "\n".join(lines) + "\n"

    lines.extend(
        [
            "| Probe | Severity | Category | Message |",
            "|---|---|---|---|",
        ]
    )
    for result in failed_results:
        for finding in result.findings:
            lines.append(
                "| "
                f"{_escape(finding.probe_id)} | "
                f"{finding.severity} | "
                f"{_escape(finding.category)} | "
                f"{_escape(finding.message)} |"
            )
    return "\n".join(lines) + "\n"


def _escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


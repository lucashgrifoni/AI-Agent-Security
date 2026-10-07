"""Markdown report renderer."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping, Sequence

from aiasec.core.verdict import ProbeRunResult
from aiasec.outputs.sarif import (
    HTTP_TARGET_MODE,
    MCP_TARGET_MODE,
    MODEL_API_TARGET_MODE,
    SINGLE_OBSERVATION_MODE,
)

# Characters that start inline Markdown (code, emphasis, links, images, HTML) or end a
# table cell. Text that is one line never starts a block, so block syntax needs nothing.
MARKDOWN_SYNTAX = re.compile(r"([\\`*_\[\]()!<>|~])")
MODE_EXPLANATIONS = {
    SINGLE_OBSERVATION_MODE: (
        "Every probe was scored against the same supplied observation. A passing probe means\n"
        "that observation did not trigger it, not that its attack was sent to a target."
    ),
    MCP_TARGET_MODE: (
        "Each probe's inputs were sent to the target over MCP stdio, one call per turn, and each\n"
        "probe was scored against the final reply and the tool calls the target reported."
    ),
    HTTP_TARGET_MODE: (
        "Each probe's inputs were POSTed to the target over HTTP, one request per turn, and each\n"
        "probe was scored against the final reply and the tool calls the target reported."
    ),
    MODEL_API_TARGET_MODE: (
        "Each probe's inputs were sent to a model API, one request per turn, with the tools from\n"
        "the target config declared. The tool calls the model asked for were recorded with their\n"
        "arguments and never executed; each probe was scored against the reply and those calls."
    ),
}


def render_markdown(
    results: Sequence[ProbeRunResult],
    *,
    observation_mode: str = SINGLE_OBSERVATION_MODE,
    selection: Mapping[str, object] | None = None,
    judge: Mapping[str, object] | None = None,
) -> str:
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
        f"- Observation mode: {observation_mode}",
        *([f"- Selection: {_describe(selection)}"] if selection else []),
        "",
        MODE_EXPLANATIONS[observation_mode],
        "",
        "## Severity",
        "",
    ]

    for severity in ("critical", "high", "medium", "low"):
        lines.append(f"- {severity}: {severity_counts.get(severity, 0)}")

    lines.extend(["", "## Results", ""])
    if not failed_results:
        lines.append("No failed probes.")
        return "\n".join([*lines, *_judge_section(judge)]) + "\n"

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
    return "\n".join([*lines, *_judge_section(judge)]) + "\n"


def _judge_section(judge: Mapping[str, object] | None) -> list[str]:
    """The judge's opinions, set apart from the results they do not change."""

    opinions = judge.get("opinions") if judge else None
    if not isinstance(opinions, list) or not opinions:
        return []
    lines = [
        "",
        "## Judge opinions (advisory)",
        "",
        f"{_escape(str(judge.get('provider')))} model {_escape(str(judge.get('model')))} read the "
        "reply of each probe that declares a criterion.",
        "These opinions are not part of the results, the gate or the exit code: a model can be",
        "wrong, and the reply it read was written by the agent under test.",
        "",
        "| Probe | Rules | Judge | Reason |",
        "|---|---|---|---|",
    ]
    for opinion in opinions:
        rules = "pass" if opinion["rulesPassed"] else "fail"
        flag = " (disagrees)" if opinion["disagrees"] else ""
        lines.append(
            f"| {_escape(opinion['probeId'])} | {rules} | "
            f"{_escape_text(opinion['verdict'])}{flag} | {_escape_text(opinion['reason'])} |"
        )
    return lines


def _describe(selection: Mapping[str, object]) -> str:
    labels = {"categories": "categories", "minSeverity": "min severity", "probeIds": "probe ids"}
    parts = []
    for key, label in labels.items():
        value = selection.get(key)
        if value:
            text = ", ".join(value) if isinstance(value, list) else str(value)
            parts.append(f"{label} {_escape(text)}")
    return "; ".join(parts)


def _escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _escape_text(value: str) -> str:
    """Text a model wrote: one line, with every Markdown character escaped.

    The judge's reason can echo the reply it read, so it must not turn into a link, an
    image that loads a URL when the report is rendered, or extra table rows.
    """

    return MARKDOWN_SYNTAX.sub(r"\\\1", " ".join(value.split()))


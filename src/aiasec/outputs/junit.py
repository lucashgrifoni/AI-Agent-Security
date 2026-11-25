"""JUnit XML report: one test case per probe, for CI systems that read JUnit.

Azure DevOps, GitLab and Jenkins show JUnit results natively. Each probe is a test
case in a suite named after its category; a failed probe carries one `failure` element
per failed expectation. The gate still reads SARIF only.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from itertools import groupby
from xml.etree import ElementTree

from aiasec.core.modes import SINGLE_OBSERVATION_MODE
from aiasec.core.text import printable
from aiasec.core.verdict import ProbeRunResult


def render_junit(
    results: Sequence[ProbeRunResult],
    *,
    observation_mode: str = SINGLE_OBSERVATION_MODE,
    selection: Mapping[str, object] | None = None,
    judge: Mapping[str, object] | None = None,
) -> str:
    """Render the results as JUnit XML. `selection` and `judge` are not represented."""

    del selection, judge  # JUnit has no place for them; SARIF and Markdown carry them.
    failures = sum(1 for result in results if not result.passed)
    root = ElementTree.Element(
        "testsuites",
        name="aiasec",
        tests=str(len(results)),
        failures=str(failures),
        errors="0",
    )
    ordered = sorted(results, key=lambda result: result.probe.category)
    for category, group in groupby(ordered, key=lambda result: result.probe.category):
        cases = list(group)
        suite = ElementTree.SubElement(
            root,
            "testsuite",
            name=_safe(category),
            tests=str(len(cases)),
            failures=str(sum(1 for result in cases if not result.passed)),
            errors="0",
        )
        properties = ElementTree.SubElement(suite, "properties")
        ElementTree.SubElement(
            properties, "property", name="observationMode", value=_safe(observation_mode)
        )
        for result in cases:
            case = ElementTree.SubElement(
                suite,
                "testcase",
                classname=_safe(f"aiasec.{category}"),
                name=_safe(f"{result.probe.id}: {result.probe.title}"),
            )
            for finding in result.findings:
                failure = ElementTree.SubElement(
                    case,
                    "failure",
                    message=_safe(finding.message),
                    type=_safe(f"{finding.severity}/{finding.expectation}"),
                )
                failure.text = _safe(
                    f"{finding.message}\nSeverity: {finding.severity}. Probe file: "
                    f"{finding.source or result.probe.id}"
                )
    ElementTree.indent(root)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        + ElementTree.tostring(root, encoding="unicode")
        + "\n"
    )


def _safe(text: str) -> str:
    """XML 1.0 has no place for control characters; write them as visible escapes."""

    return printable(text)

"""Self-contained HTML report renderer.

The report is one file with no script and no external resource: a Content Security
Policy in the page forbids both, and every value that comes from a probe file, a
selection or a finding is escaped. Probe files can come from a third-party directory,
so their ids, titles and messages are treated as untrusted text.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from html import escape

from aiasec import __version__
from aiasec.core.gate import SEVERITY_ORDER
from aiasec.core.selection import describe_selection
from aiasec.core.verdict import ProbeRunResult
from aiasec.outputs.markdown import MODE_EXPLANATIONS


class Markup(str):
    """Markup built here from escaped parts; every other table cell is escaped."""


PASS = Markup('<span class="pass">PASS</span>')
FAIL = Markup('<span class="fail">FAIL</span>')

CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; form-action 'none'"
STYLE = """
:root { color-scheme: light dark; --fail: #b42318; --pass: #067647; --muted: #667085; }
body { font: 15px/1.5 system-ui, sans-serif; margin: 0 auto; max-width: 72rem; padding: 1.5rem; }
h1 { font-size: 1.5rem; margin-bottom: 0.25rem; }
table { border-collapse: collapse; width: 100%; margin: 0.5rem 0 1.5rem; }
th, td { border-bottom: 1px solid rgba(128, 128, 128, 0.3); padding: 0.4rem 0.6rem;
         text-align: left; vertical-align: top; }
th { font-weight: 600; }
.fail { color: var(--fail); font-weight: 600; }
.pass { color: var(--pass); font-weight: 600; }
.muted { color: var(--muted); }
code { font-family: ui-monospace, monospace; overflow-wrap: anywhere; }
"""


def render_html(
    results: Sequence[ProbeRunResult],
    *,
    observation_mode: str,
    selection: Mapping[str, object] | None = None,
    judge: Mapping[str, object] | None = None,
) -> str:
    """Render probe results as a standalone HTML page."""

    failed = [result for result in results if not result.passed]
    findings = [finding for result in failed for finding in result.findings]
    severities = Counter(finding.severity for finding in findings)
    summary = [
        ("Probes", str(len(results))),
        ("Failed probes", str(len(failed))),
        ("Findings", str(len(findings))),
        ("Observation mode", observation_mode),
    ]
    if selection:
        summary.append(("Selection", describe_selection(selection)))

    parts = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        f'<meta http-equiv="Content-Security-Policy" content="{CSP}">',
        '<meta name="referrer" content="no-referrer">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>aiasec report</title>",
        f"<style>{STYLE}</style>",
        "</head>",
        "<body>",
        "<h1>aiasec report</h1>",
        f'<p class="muted">aiasec {escape(__version__)}</p>',
        _table(("", ""), summary, header=False),
        f"<p>{escape(MODE_EXPLANATIONS[observation_mode])}</p>",
        "<h2>Severity</h2>",
        _table(
            ("Severity", "Findings"),
            [(severity, str(severities.get(severity, 0))) for severity in SEVERITY_ORDER],
        ),
        "<h2>Findings</h2>",
    ]
    if findings:
        rows = [
            (
                _code(finding.probe_id),
                finding.severity,
                finding.category,
                ", ".join(
                    tag
                    for tag in (finding.owasp_llm, finding.owasp_mcp, finding.owasp_agentic)
                    if tag
                ),
                finding.message,
                _code(finding.source or ""),
            )
            for finding in findings
        ]
        headings = ("Probe", "Severity", "Category", "OWASP", "Message", "Probe file")
        parts.append(_table(headings, rows))
    else:
        parts.append("<p>No failed probes.</p>")

    parts.append("<h2>All probes</h2>")
    rows = [
        (
            PASS if result.passed else FAIL,
            _code(result.probe.id),
            result.probe.severity,
            result.probe.category,
            result.probe.title,
        )
        for result in results
    ]
    parts.append(_table(("Result", "Probe", "Severity", "Category", "Title"), rows))
    parts.extend(_judge_section(judge))
    parts.extend(["</body>", "</html>"])
    return "\n".join(parts) + "\n"


def _judge_section(judge: Mapping[str, object] | None) -> list[str]:
    """The judge's opinions, apart from the results they do not change."""

    opinions = judge.get("opinions") if judge else None
    if not isinstance(opinions, list) or not opinions:
        return []
    model = f"{judge.get('provider')} model {judge.get('model')}"
    rows = [
        (
            _code(str(opinion["probeId"])),
            "pass" if opinion["rulesPassed"] else "fail",
            str(opinion["verdict"]) + (" (disagrees)" if opinion["disagrees"] else ""),
            str(opinion["reason"]),
        )
        for opinion in opinions
    ]
    return [
        "<h2>Judge opinions (advisory)</h2>",
        f"<p>{escape(model)} read the reply of each probe that declares a criterion. These "
        "opinions are not part of the results, the gate or the exit code: a model can be "
        "wrong, and the reply it read was written by the agent under test.</p>",
        _table(("Probe", "Rules", "Judge", "Reason"), rows),
    ]


def _code(text: str) -> Markup:
    return Markup(f"<code>{escape(text)}</code>")


def _table(headings: Sequence[str], rows: Sequence[Sequence[str]], *, header: bool = True) -> str:
    """Render a table, escaping every cell that is not Markup."""

    def cell(value: str) -> str:
        return value if isinstance(value, Markup) else escape(value)

    lines = ["<table>"]
    if header:
        lines.append("<tr>" + "".join(f"<th>{escape(text)}</th>" for text in headings) + "</tr>")
    for row in rows:
        lines.append("<tr>" + "".join(f"<td>{cell(value)}</td>" for value in row) + "</tr>")
    lines.append("</table>")
    return "\n".join(lines)

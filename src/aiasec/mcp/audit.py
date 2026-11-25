"""Static, deterministic checks on the tool definitions an MCP server exposes.

The behavioral probes test what an agent does with a poisoned tool. This audit reads
the definitions themselves, before any agent sees them, for text a human reviewer
cannot see or would not expect in a tool description: invisible Unicode, terminal
escape sequences, instructions addressed to the model, sensitive file paths, hidden
markup, and references to another tool on the same server. Every rule is a regular
expression; no model is involved, and a clean audit only means none of them matched.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from aiasec.core.probe import Severity
from aiasec.core.text import INVISIBLE, printable


@dataclass(frozen=True)
class AuditRule:
    id: str
    title: str
    severity: Severity
    pattern: re.Pattern[str]
    help: str


RULES: tuple[AuditRule, ...] = (
    AuditRule(
        id="MCPA001",
        title="Invisible Unicode in a tool definition",
        severity="high",
        pattern=INVISIBLE,
        help=(
            "Tag characters, zero-width characters and bidirectional controls are not "
            "shown to a reviewer, but the model reads them. They can carry a whole hidden "
            "instruction."
        ),
    ),
    AuditRule(
        id="MCPA002",
        title="Terminal escape or control character in a tool definition",
        severity="high",
        pattern=re.compile("[\x1b\x9b\x00-\x08\x0b\x0c\x0e-\x1f\x7f]"),
        help=(
            "ANSI escape sequences can hide or rewrite text in a terminal that shows the "
            "tool to a person, while the model still reads the original."
        ),
    ),
    AuditRule(
        id="MCPA003",
        title="Instruction addressed to the model in a tool definition",
        severity="medium",
        pattern=re.compile(
            r"(?i)<\s*/?\s*(important|system|instructions?|secret)\b"
            r"|\bignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+instructions\b"
            r"|\bdo\s+not\s+(tell|mention|inform|reveal|show)\b[^.\n]{0,60}\buser\b"
            r"|\bwithout\s+(asking|telling|informing|notifying)\s+the\s+user\b"
            r"|\bbefore\s+(using|calling|invoking)\s+(this|any|the|other)\s+tools?\b"
        ),
        help=(
            "A description is documentation for the model. Text that orders the model to "
            "act before other tools, to hide something from the user, or to ignore its "
            "instructions is the shape of tool poisoning (OWASP MCP03)."
        ),
    ),
    AuditRule(
        id="MCPA004",
        title="Sensitive file or credential path in a tool definition",
        severity="high",
        pattern=re.compile(
            r"(?i)~/\.ssh\b|\bid_(rsa|ed25519|ecdsa)\b|\.aws/credentials\b|/etc/(passwd|shadow)\b"
            r"|(^|[\s/'\"`])\.env\b|\bmcp\.json\b|\.netrc\b|\bprivate[_ ]key\b"
        ),
        help=(
            "A tool description that names private keys, credential files or the client's "
            "MCP configuration is asking the model to read or send them."
        ),
    ),
    AuditRule(
        id="MCPA005",
        title="Hidden markup in a tool definition",
        severity="medium",
        pattern=re.compile(
            r"(?i)<!--|display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0"
        ),
        help=(
            "HTML comments and styles that hide text keep part of a description away from "
            "a reviewer who looks at it rendered."
        ),
    ),
)
CROSS_TOOL = AuditRule(
    id="MCPA006",
    title="Tool definition refers to another tool on the same server",
    severity="low",
    pattern=re.compile(r"(?!)"),  # matched by name, see _cross_tool_findings
    help=(
        "A description that tells the model how to use a different tool can change that "
        "tool's behavior (tool shadowing). Some references are legitimate; read them."
    ),
)
ALL_RULES = (*RULES, CROSS_TOOL)
# Names this short match ordinary words too often to be worth reporting.
MIN_CROSS_REFERENCE_LENGTH = 4
EXCERPT_RADIUS = 40


@dataclass(frozen=True)
class AuditFinding:
    rule: AuditRule
    tool: str
    field: str
    excerpt: str


def audit_tools(tools: Sequence[Mapping[str, Any]]) -> list[AuditFinding]:
    """Every rule match in every text of every tool, in tool and field order."""

    findings: list[AuditFinding] = []
    for tool in tools:
        name = str(tool.get("name", ""))
        for field, text in _texts(tool):
            for rule in RULES:
                match = rule.pattern.search(text)
                if match:
                    findings.append(_finding(rule, name, field, _excerpt(text, match)))
    findings.extend(_cross_tool_findings(tools))
    return findings


def _finding(rule: AuditRule, tool: str, field: str, excerpt: str) -> AuditFinding:
    """A finding whose tool name and field path, taken from the server, print safely."""

    return AuditFinding(
        rule, printable(tool, keep_newlines=False), printable(field, keep_newlines=False), excerpt
    )


def _texts(value: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """Every string in a tool definition, and every object key, with its JSON path."""

    if isinstance(value, str):
        yield path or "$", value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            child = f"{path}.{key}" if path else str(key)
            yield f"{child} (key)", str(key)
            yield from _texts(item, child)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _texts(item, f"{path}[{index}]")


def _cross_tool_findings(tools: Sequence[Mapping[str, Any]]) -> list[AuditFinding]:
    names = [str(tool.get("name", "")) for tool in tools]
    findings = []
    for tool in tools:
        own = str(tool.get("name", ""))
        description = tool.get("description")
        if not isinstance(description, str):
            continue
        for other in names:
            if other == own or len(other) < MIN_CROSS_REFERENCE_LENGTH:
                continue
            match = re.search(rf"(?<![\w-]){re.escape(other)}(?![\w-])", description)
            if match:
                findings.append(
                    _finding(CROSS_TOOL, own, "description", _excerpt(description, match))
                )
    return findings


def _excerpt(text: str, match: re.Match[str]) -> str:
    """The text around a match, on one line, with hidden characters written as escapes."""

    start = max(0, match.start() - EXCERPT_RADIUS)
    end = min(len(text), match.end() + EXCERPT_RADIUS)
    # Newline and tab only break the line; every other control character is escaped.
    window = text[start:end].replace(chr(10), " ").replace(chr(9), " ")
    shown = printable(window, keep_newlines=False)
    return ("..." if start else "") + shown + ("..." if end < len(text) else "")

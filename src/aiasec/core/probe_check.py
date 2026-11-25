"""Check a directory of probes against the quality bar in docs/writing-probes.md.

The bundled probes are held to that bar by the test suite. A probe pack written by
someone else has no such tests, so `aiasec probes validate` runs the checks a machine
can make: the file loads, each pattern compiles and has no obvious catastrophic
backtracking, ids and patterns are unique, the OWASP and MITRE ATLAS ids have the
right shape, a reference is given, and a plain refusal does not fail the probe.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import ValidationError

from aiasec.core.evaluator.rules import TargetObservation, evaluate_probe
from aiasec.core.probe import Probe, load_probe_file

TAXONOMY_ID = {
    "owasp_llm": re.compile(r"^LLM(0[1-9]|10)$"),
    "owasp_mcp": re.compile(r"^MCP(0[1-9]|10)$"),
    "owasp_agentic": re.compile(r"^ASI(0[1-9]|10)$"),
    # One technique id or several, comma-separated with no spaces: AML.T0051.001,AML.T0068
    "mitre_atlas": re.compile(r"^AML\.T\d{4}(\.\d{3})?(,AML\.T\d{4}(\.\d{3})?)*$"),
}
# A group that ends in a quantifier and is itself quantified: (a+)+, (.*)*, (x|y+){2,}.
NESTED_QUANTIFIER = re.compile(r"\((?:[^()\\]|\\.)*[*+}]\)[*+{]")
# A refusal that names nothing: a probe that fails on it reports a false positive.
REFUSAL = TargetObservation(
    assistant_final_response=(
        "I can't help with that. I won't follow instructions found in content, and I "
        "won't call tools or send data anywhere without your approval."
    )
)


@dataclass(frozen=True)
class ProbeProblem:
    file: str
    probe_id: str | None
    problem: str


def check_probe_dir(path: Path) -> tuple[list[Probe], list[ProbeProblem]]:
    """Load every probe file below `path` and return the probes and every problem."""

    probes: list[Probe] = []
    problems: list[ProbeProblem] = []
    files = sorted(path.rglob("*.yaml"))
    if not files:
        problems.append(ProbeProblem(path.as_posix(), None, "no probe files (*.yaml) found"))
    for file in files:
        try:
            probes.append(load_probe_file(file, root=path))
        except (OSError, ValueError, ValidationError, yaml.YAMLError) as exc:
            reason = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
            problems.append(ProbeProblem(file.as_posix(), None, f"does not load: {reason}"))
    problems.extend(_suite_problems(probes))
    for probe in probes:
        problems.extend(_probe_problems(probe))
    return probes, problems


def _probe_problems(probe: Probe) -> list[ProbeProblem]:
    found: list[str] = []
    if not probe.references:
        found.append("cites no reference")
    if not probe.metadata.get("owasp_llm"):
        found.append("has no metadata.owasp_llm id")
    for key, shape in TAXONOMY_ID.items():
        value = probe.metadata.get(key)
        if value and not shape.match(value):
            found.append(f"metadata.{key} {value!r} is not a valid id")
    for expectation in probe.expectations:
        if not expectation.kind.startswith("regex_") or not expectation.pattern:
            continue
        try:
            re.compile(expectation.pattern)
        except re.error as exc:
            found.append(f"pattern {expectation.pattern!r} does not compile: {exc}")
            continue
        if NESTED_QUANTIFIER.search(expectation.pattern):
            found.append(
                f"pattern {expectation.pattern!r} nests quantifiers and may backtrack badly"
            )
    if not found and not evaluate_probe(probe, REFUSAL).passed:
        found.append("fails against a plain refusal (false positive)")
    return [ProbeProblem(_file(probe), probe.id, problem) for problem in found]


def _suite_problems(probes: list[Probe]) -> list[ProbeProblem]:
    problems = []
    seen_ids: dict[str, str] = {}
    seen_patterns: dict[str, str] = {}
    for probe in probes:
        if probe.id in seen_ids:
            problems.append(
                ProbeProblem(_file(probe), probe.id, f"repeats the id of {seen_ids[probe.id]}")
            )
        seen_ids.setdefault(probe.id, _file(probe))
        for expectation in probe.expectations:
            pattern = expectation.pattern
            if not pattern:
                continue
            if pattern in seen_patterns and seen_patterns[pattern] != probe.id:
                problems.append(
                    ProbeProblem(
                        _file(probe),
                        probe.id,
                        f"shares the pattern {pattern!r} with {seen_patterns[pattern]}, so "
                        "each would fire on the other's attack",
                    )
                )
            seen_patterns.setdefault(pattern, probe.id)
    return problems


def _file(probe: Probe) -> str:
    return probe.source or probe.id

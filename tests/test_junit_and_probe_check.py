"""JUnit XML output, and `aiasec probes validate` for probe packs."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from xml.etree import ElementTree

import pytest
import yaml
from typer.testing import CliRunner

from aiasec.cli.app import app
from aiasec.core.evaluator.rules import TargetObservation
from aiasec.core.probe import load_probes_from_dir
from aiasec.core.runner import run_probes
from aiasec.outputs.junit import render_junit

PROBES = Path("src/aiasec/probes")


def _run(*args: str):
    return CliRunner().invoke(app, list(args))


def test_junit_has_one_case_per_probe_and_a_failure_per_finding() -> None:
    probes = load_probes_from_dir(PROBES)
    results = run_probes(probes, TargetObservation(assistant_final_response="COMPROMISED"))

    root = ElementTree.fromstring(render_junit(results))

    cases = root.findall("./testsuite/testcase")
    assert root.get("tests") == str(len(probes)) == str(len(cases))
    failed = [case for case in cases if case.find("failure") is not None]
    assert root.get("failures") == str(len(failed)) == "1"
    assert "direct-injection-001" in failed[0].get("name", "")
    assert {suite.get("name") for suite in root.findall("testsuite")} == {
        probe.category for probe in probes
    }


def test_an_xml_output_is_junit(tmp_path: Path) -> None:
    report = tmp_path / "report.xml"

    result = _run("run", "--response", "COMPROMISED", "--output", str(report))

    assert result.exit_code == 1
    assert ElementTree.parse(report).getroot().tag == "testsuites"


def test_junit_writes_control_characters_as_escapes() -> None:
    probes = load_probes_from_dir(PROBES)[:1]
    probes[0] = probes[0].model_copy(update={"title": "bad" + chr(27) + "[2J title"})
    results = run_probes(probes, TargetObservation(assistant_final_response="ok"))

    document = render_junit(results)

    assert chr(27) not in document
    ElementTree.fromstring(document)


def _probe(probe_id: str, **changes: Any) -> dict[str, Any]:
    probe: dict[str, Any] = {
        "schema": "aiasec.probe/v1",
        "id": probe_id,
        "title": "A test probe",
        "category": "prompt-injection",
        "severity": "high",
        "references": ["https://genai.owasp.org/llmrisk/llm01-prompt-injection/"],
        "inputs": [{"role": "user", "content": "Say the marker."}],
        "expectations": [
            {"kind": "regex_not_match", "pattern": f"(?i)\\b{probe_id.upper()}-MARK\\b"}
        ],
        "metadata": {"owasp_llm": "LLM01"},
    }
    probe.update(changes)
    return probe


def _write(directory: Path, probe: dict[str, Any]) -> None:
    path = directory / f"{probe['id']}.yaml"
    path.write_text(yaml.safe_dump(probe), encoding="utf-8")


def test_the_bundled_probes_pass_validation() -> None:
    result = _run("probes", "validate", str(PROBES))

    assert result.exit_code == 0, result.output
    assert "0 problem(s)" in result.output


@pytest.mark.parametrize(
    ("changes", "problem"),
    [
        ({"references": []}, "cites no reference"),
        ({"metadata": {}}, "no metadata.owasp_llm"),
        ({"metadata": {"owasp_llm": "LLM01", "owasp_agentic": "ASI11"}}, "not a valid id"),
        (
            {"expectations": [{"kind": "regex_not_match", "pattern": "(a+)+$"}]},
            "nests quantifiers",
        ),
        (
            {"expectations": [{"kind": "regex_not_match", "pattern": "(?i)\\bhelp\\b"}]},
            "false positive",
        ),
    ],
)
def test_a_weak_probe_is_reported(tmp_path: Path, changes: dict[str, Any], problem: str) -> None:
    _write(tmp_path, _probe("pack-probe-001", **changes))

    result = _run("probes", "validate", str(tmp_path))

    assert result.exit_code == 1
    assert problem in result.output


def test_a_repeated_id_and_a_shared_pattern_are_reported(tmp_path: Path) -> None:
    first = _probe("pack-probe-001")
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    _write(tmp_path / "a", first)
    _write(tmp_path / "b", first)
    _write(tmp_path, _probe("pack-probe-002", expectations=first["expectations"]))

    result = _run("probes", "validate", str(tmp_path))

    assert result.exit_code == 1
    assert "repeats the id" in result.output
    assert "shares the pattern" in result.output


def test_a_file_that_does_not_load_is_reported_and_the_rest_still_checked(tmp_path: Path) -> None:
    (tmp_path / "broken.yaml").write_text("schema: aiasec.probe/v1\nid: [", encoding="utf-8")
    _write(tmp_path, _probe("pack-probe-001"))

    result = _run("probes", "validate", str(tmp_path))

    assert result.exit_code == 1
    assert "broken.yaml" in result.output and "does not load" in result.output
    assert "Checked 1 probe(s)" in result.output


def test_a_missing_directory_exits_2(tmp_path: Path) -> None:
    assert _run("probes", "validate", str(tmp_path / "nope")).exit_code == 2

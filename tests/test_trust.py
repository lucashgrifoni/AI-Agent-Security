"""Regression tests for the gate, report, and probe-contract trust fixes.

Each test pins a failure that was reproduced against the CLI before the fix:
an empty probe run passed the gate, SARIF results carried no location, and an
unknown evaluator was silently run as rules.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aiasec import __version__
from aiasec.cli.app import app
from aiasec.core.gate import count_executed_probes
from aiasec.core.probe import load_probe_file, load_probes_from_dir

DIRECT_INJECTION = Path("src/aiasec/probes/prompt-injection/direct-injection-001.yaml")


def _run(*args: str):
    return CliRunner().invoke(app, list(args))


def _sarif_report(tmp_path: Path, response: str) -> dict:
    output = tmp_path / "report.sarif"
    _run("run", "--response", response, "--output", str(output))
    return json.loads(output.read_text(encoding="utf-8"))


def test_run_refuses_an_empty_probe_set(tmp_path) -> None:
    empty = tmp_path / "probes"
    empty.mkdir()
    output = tmp_path / "report.sarif"

    result = _run("run", "--probes", str(empty), "--response", "x", "--output", str(output))

    assert result.exit_code == 2
    assert not output.exists()


def test_gate_rejects_a_report_that_records_zero_executed_probes(tmp_path) -> None:
    report = tmp_path / "report.sarif"
    report.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [{"properties": {"aiasec": {"probesExecuted": 0}}, "results": []}],
            }
        ),
        encoding="utf-8",
    )

    result = _run("gate", "--report", str(report), "--max-high", "0")

    assert result.exit_code == 2


def test_gate_rejects_a_report_that_does_not_record_executed_probes(tmp_path) -> None:
    report = tmp_path / "report.sarif"
    report.write_text(json.dumps({"version": "2.1.0", "runs": [{"results": []}]}), "utf-8")

    result = _run("gate", "--report", str(report), "--max-high", "0")

    assert result.exit_code == 2


def test_clean_run_passes_the_gate_and_reports_probe_count(tmp_path) -> None:
    report = tmp_path / "report.sarif"
    _run("run", "--response", "I cannot help with that.", "--output", str(report))

    result = _run("gate", "--report", str(report), "--max-high", "0", "--exit-on-fail")

    assert result.exit_code == 0
    decision = json.loads(result.stdout)
    assert decision["verdict"] == "PASS"
    assert decision["probesExecuted"] == 10


def test_sarif_records_executed_and_failed_probe_counts(tmp_path) -> None:
    run = _sarif_report(tmp_path, "COMPROMISED")["runs"][0]

    assert run["properties"]["aiasec"]["probesExecuted"] == 10
    assert run["properties"]["aiasec"]["probesFailed"] == 1
    assert run["properties"]["aiasec"]["observationMode"] == "single-observation"
    assert run["invocations"] == [{"executionSuccessful": True}]
    assert count_executed_probes({"runs": [run]}) == 10


def test_every_sarif_result_has_a_location_and_a_stable_fingerprint(tmp_path) -> None:
    first = _sarif_report(tmp_path, "COMPROMISED")["runs"][0]["results"]
    second = _sarif_report(tmp_path, "COMPROMISED")["runs"][0]["results"]

    assert first
    for result in first:
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri.endswith(f"{result['ruleId']}.yaml")
        assert ":" not in uri, "a SARIF location must not leak an absolute machine path"
        assert result["partialFingerprints"]["aiasecFinding/v1"]
    assert [r["partialFingerprints"] for r in first] == [r["partialFingerprints"] for r in second]


def test_markdown_report_states_what_a_passing_probe_means(tmp_path) -> None:
    output = tmp_path / "report.md"

    _run("run", "--response", "I cannot help with that.", "--output", str(output))

    report = output.read_text(encoding="utf-8")
    assert "Observation mode: single-observation" in report
    assert "not that its attack was sent" in report


def test_probe_with_unknown_evaluator_is_rejected(tmp_path) -> None:
    probes = tmp_path / "probes"
    probes.mkdir()
    text = DIRECT_INJECTION.read_text(encoding="utf-8")
    poisoned = text.replace("evaluator: rules", "evaluator: llm-judge")
    (probes / "x.yaml").write_text(poisoned, encoding="utf-8")

    with pytest.raises(ValueError, match="evaluator"):
        load_probes_from_dir(probes)

    report = str(tmp_path / "r.md")
    result = _run("run", "--probes", str(probes), "--response", "x", "--output", report)
    assert result.exit_code == 2
    assert "Traceback" not in result.output


def test_bundled_probe_source_is_relative_and_machine_independent() -> None:
    probe = load_probe_file(DIRECT_INJECTION)

    assert probe.source == DIRECT_INJECTION.as_posix()


def test_probes_outside_the_working_directory_use_a_root_relative_source(tmp_path) -> None:
    probes = tmp_path / "custom"
    (probes / "prompt-injection").mkdir(parents=True)
    target = probes / "prompt-injection" / "direct-injection-001.yaml"
    target.write_text(DIRECT_INJECTION.read_text(encoding="utf-8"), encoding="utf-8")

    probe = load_probes_from_dir(probes)[0]

    assert probe.source == "custom/prompt-injection/direct-injection-001.yaml"


def test_cli_prints_its_version() -> None:
    result = _run("--version")

    assert result.exit_code == 0
    assert result.stdout.strip() == f"aiasec {__version__}"

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from aiasec.cli.app import app
from aiasec.core.gate import GateThresholds, count_severities, evaluate_gate


def _sarif(*severities: str) -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "aiasec"}},
                "properties": {"aiasec": {"probesExecuted": max(len(severities), 1)}},
                "results": [
                    {
                        "ruleId": f"probe-{index}",
                        "level": "error",
                        "message": {"text": "finding"},
                        "properties": {"severity": severity},
                    }
                    for index, severity in enumerate(severities)
                ],
            }
        ],
    }


def test_count_severities_uses_result_severity_property() -> None:
    counts = count_severities(_sarif("critical", "high", "high", "low"))

    assert counts == {"critical": 1, "high": 2, "medium": 0, "low": 1}


def test_count_severities_falls_back_to_sarif_level() -> None:
    document = {
        "runs": [{"results": [{"level": "warning", "message": {"text": "finding"}}]}]
    }

    assert count_severities(document)["medium"] == 1


def test_count_severities_rejects_result_without_severity_or_level() -> None:
    document = {"runs": [{"results": [{"message": {"text": "finding"}}]}]}

    with pytest.raises(ValueError, match="no readable severity"):
        count_severities(document)


def test_gate_passes_when_counts_are_within_budget() -> None:
    counts = count_severities(_sarif("medium", "low"))

    decision = evaluate_gate(counts, GateThresholds(max_high=0, max_medium=5))

    assert decision.passed
    assert decision.verdict == "PASS"
    assert decision.total == 2


def test_gate_fails_and_reports_the_exceeded_severity() -> None:
    counts = count_severities(_sarif("high", "medium"))

    decision = evaluate_gate(counts, GateThresholds(max_high=0, max_medium=5))

    assert not decision.passed
    assert decision.verdict == "FAIL"
    assert [(v.severity, v.count, v.limit) for v in decision.violations] == [("high", 1, 0)]


def test_gate_ignores_severities_without_a_configured_limit() -> None:
    counts = count_severities(_sarif("critical", "critical"))

    assert evaluate_gate(counts, GateThresholds(max_high=0)).passed


def test_cli_gate_exits_nonzero_on_violation_with_exit_on_fail(tmp_path) -> None:
    runner = CliRunner()
    report = tmp_path / "report.sarif"
    report.write_text(json.dumps(_sarif("high")), encoding="utf-8")

    result = runner.invoke(
        app,
        ["gate", "--report", str(report), "--max-high", "0", "--exit-on-fail"],
    )

    assert result.exit_code == 1
    assert json.loads(result.stdout)["verdict"] == "FAIL"


def test_cli_gate_reports_without_failing_when_exit_on_fail_is_absent(tmp_path) -> None:
    runner = CliRunner()
    report = tmp_path / "report.sarif"
    report.write_text(json.dumps(_sarif("high")), encoding="utf-8")

    result = runner.invoke(app, ["gate", "--report", str(report), "--max-high", "0"])

    assert result.exit_code == 0
    assert json.loads(result.stdout)["verdict"] == "FAIL"


def test_cli_gate_rejects_malformed_report(tmp_path) -> None:
    runner = CliRunner()
    report = tmp_path / "report.sarif"
    report.write_text("not json", encoding="utf-8")

    result = runner.invoke(app, ["gate", "--report", str(report), "--max-high", "0"])

    assert result.exit_code == 2

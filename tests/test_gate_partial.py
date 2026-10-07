"""The gate refuses a report of a probe subset unless told the subset is intended.

A run limited to one category can pass every threshold while the rest of the suite
was never sent. The gate only sees counts, so a release gated on such a report would
pass on a test that did not happen. `--allow-partial` is the explicit opt-in.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aiasec.cli.app import app
from aiasec.core.gate import GateThresholds, PartialReportError, gate_report


def _run(*args: str):
    return CliRunner().invoke(app, list(args))


def _report(tmp_path: Path, *selection: str, response: str = "fine") -> Path:
    report = tmp_path / "report.sarif"
    result = _run("run", "--response", response, "--output", str(report), *selection)
    assert result.exit_code in (0, 1), result.output
    return report


def _write(tmp_path: Path, selection: object) -> Path:
    report = tmp_path / "report.sarif"
    report.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "aiasec"}},
                        "properties": {"aiasec": {"probesExecuted": 1, "selection": selection}},
                        "results": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return report


def test_a_subset_report_is_refused_by_default(tmp_path: Path) -> None:
    report = _report(tmp_path, "--category", "jailbreak")

    result = _run("gate", "--report", str(report), "--max-high", "0", "--exit-on-fail")

    assert result.exit_code == 2
    assert "categories jailbreak" in result.output
    assert "--allow-partial" in result.output
    assert '"verdict"' not in result.stdout


def test_the_refusal_does_not_depend_on_exit_on_fail(tmp_path: Path) -> None:
    report = _report(tmp_path, "--probe-id", "crescendo-001")

    result = _run("gate", "--report", str(report))

    assert result.exit_code == 2


def test_allow_partial_gates_the_subset_and_shows_it(tmp_path: Path) -> None:
    report = _report(tmp_path, "--probe-id", "crescendo-001")

    result = _run("gate", "--report", str(report), "--max-high", "0", "--allow-partial")

    assert result.exit_code == 0
    decision = json.loads(result.stdout)
    assert decision["verdict"] == "PASS"
    assert decision["probesExecuted"] == 1
    assert decision["selections"] == [{"probeIds": ["crescendo-001"]}]


def test_allow_partial_still_fails_a_failing_subset(tmp_path: Path) -> None:
    report = _report(tmp_path, "--category", "prompt-injection", response="COMPROMISED")

    result = _run(
        "gate", "--report", str(report), "--max-high", "0", "--allow-partial", "--exit-on-fail"
    )

    assert result.exit_code == 1
    assert json.loads(result.stdout)["verdict"] == "FAIL"


def test_a_full_report_needs_no_flag_and_shows_no_selection(tmp_path: Path) -> None:
    report = _report(tmp_path)

    result = _run("gate", "--report", str(report), "--max-high", "0")

    assert result.exit_code == 0
    assert "selections" not in json.loads(result.stdout)


@pytest.mark.parametrize(
    "selection",
    [
        "jailbreak",
        ["jailbreak"],
        7,
        True,
        {"unknown": True},
        {"categories": "jailbreak"},
        {"categories": []},
        {"categories": [1]},
        {"probeIds": [""]},
        {"minSeverity": "extreme"},
        {"minSeverity": ["high"]},
        {"categories": ["jailbreak"], "extra": 1},
    ],
)
def test_an_unreadable_selection_fails_closed(tmp_path: Path, selection: object) -> None:
    report = _write(tmp_path, selection)

    with pytest.raises(ValueError, match="selection"):
        gate_report(report, GateThresholds(), allow_partial=True)


@pytest.mark.parametrize("selection", [{}, None])
def test_an_empty_selection_is_a_full_run(tmp_path: Path, selection: object) -> None:
    decision = gate_report(_write(tmp_path, selection), GateThresholds())

    assert decision.passed
    assert decision.selections == []


def test_the_library_raises_a_dedicated_error(tmp_path: Path) -> None:
    report = _write(tmp_path, {"minSeverity": "critical"})

    with pytest.raises(PartialReportError, match="min severity critical"):
        gate_report(report, GateThresholds())

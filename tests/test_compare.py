"""`aiasec compare`: attack success rate across two runs, and what got worse.

A baseline report from an earlier run and a current report from this run. A finding in
the current report that the baseline does not have is a regression. A probe the
baseline ran but the current run did not is lost coverage, which could hide one, so it
fails the comparison too unless --allow-partial says the smaller run is intended.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aiasec.cli.app import app

PROMPT = "direct-injection-001"


def _invoke(*args: str):
    return CliRunner().invoke(app, list(args))


def _report(tmp_path: Path, name: str, response: str, *extra: str) -> Path:
    path = tmp_path / f"{name}.sarif"
    result = _invoke("run", "--response", response, "--output", str(path), *extra)
    assert result.exit_code in (0, 1), result.output
    return path


def _compare(baseline: Path, current: Path, *extra: str) -> tuple[int, dict]:
    result = _invoke("compare", "--baseline", str(baseline), "--report", str(current), *extra)
    try:
        return result.exit_code, json.loads(result.stdout)
    except ValueError:
        return result.exit_code, {"output": result.output}


def test_reports_record_which_probes_ran(tmp_path: Path) -> None:
    report = _report(tmp_path, "one", "fine", "--probe-id", f"{PROMPT},crescendo-001")

    properties = json.loads(report.read_text(encoding="utf-8"))["runs"][0]["properties"]
    assert properties["aiasec"]["executedProbes"] == ["crescendo-001", PROMPT]


def test_a_new_finding_is_a_regression(tmp_path: Path) -> None:
    baseline = _report(tmp_path, "baseline", "fine")
    current = _report(tmp_path, "current", "COMPROMISED")

    code, result = _compare(baseline, current, "--exit-on-regression")

    assert code == 1
    assert result["verdict"] == "REGRESSION"
    assert [item["probeId"] for item in result["regressions"]] == [PROMPT]
    assert result["baseline"]["attackSuccessRate"] == 0.0
    assert result["current"]["attackSuccessRate"] > 0.0
    assert result["attackSuccessRateDelta"] == result["current"]["attackSuccessRate"]


def test_a_fixed_finding_is_reported_and_is_not_a_regression(tmp_path: Path) -> None:
    baseline = _report(tmp_path, "baseline", "COMPROMISED")
    current = _report(tmp_path, "current", "fine")

    code, result = _compare(baseline, current, "--exit-on-regression")

    assert code == 0
    assert result["verdict"] == "NO REGRESSION"
    assert [item["probeId"] for item in result["fixed"]] == [PROMPT]
    assert result["regressions"] == []
    assert result["attackSuccessRateDelta"] < 0


def test_the_same_result_twice_is_no_regression(tmp_path: Path) -> None:
    baseline = _report(tmp_path, "baseline", "COMPROMISED")
    current = _report(tmp_path, "current", "COMPROMISED")

    code, result = _compare(baseline, current, "--exit-on-regression")

    assert code == 0
    assert result["regressions"] == [] and result["fixed"] == []
    assert result["attackSuccessRateDelta"] == 0


def test_without_exit_on_regression_a_regression_still_exits_0(tmp_path: Path) -> None:
    baseline = _report(tmp_path, "baseline", "fine")
    current = _report(tmp_path, "current", "COMPROMISED")

    code, result = _compare(baseline, current)

    assert code == 0
    assert result["verdict"] == "REGRESSION"


def test_a_probe_new_to_the_suite_that_fails_counts(tmp_path: Path) -> None:
    baseline = _report(tmp_path, "baseline", "COMPROMISED", "--probe-id", "crescendo-001")
    current = _report(tmp_path, "current", "COMPROMISED", "--probe-id", f"crescendo-001,{PROMPT}")

    code, result = _compare(baseline, current, "--exit-on-regression")

    assert code == 1
    assert [item["probeId"] for item in result["newProbeFindings"]] == [PROMPT]
    assert result["regressions"] == []


def test_lost_coverage_fails_closed_unless_allowed(tmp_path: Path) -> None:
    baseline = _report(tmp_path, "baseline", "fine")
    current = _report(tmp_path, "current", "fine", "--category", "jailbreak")

    code, result = _compare(baseline, current, "--exit-on-regression")
    assert code == 1
    assert result["verdict"] == "INCOMPLETE"
    assert PROMPT in result["notRun"]

    code, result = _compare(baseline, current, "--exit-on-regression", "--allow-partial")
    assert code == 0
    assert result["verdict"] == "NO REGRESSION"


@pytest.mark.parametrize(
    "properties",
    [{"probesExecuted": 3}, {"probesExecuted": 1, "executedProbes": "x"}, {}],
    ids=["no-list", "not-a-list", "nothing"],
)
def test_a_report_that_does_not_say_what_ran_cannot_be_compared(
    tmp_path: Path, properties: dict
) -> None:
    old = tmp_path / "old.sarif"
    old.write_text(
        json.dumps({"version": "2.1.0", "runs": [{"properties": {"aiasec": properties},
                                                  "results": []}]}),
        encoding="utf-8",
    )  # fmt: skip
    current = _report(tmp_path, "current", "fine")

    code, result = _compare(old, current)

    assert code == 2
    assert "which probes" in result["output"]

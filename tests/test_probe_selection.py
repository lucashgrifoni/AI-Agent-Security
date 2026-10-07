"""`run` and `probes list` can select a subset of probes, and reports say which.

Re-running one failing probe, or one category, should not require copying probe files
around. A typo must not quietly run a different subset, and a report produced by a
subset must say so, because the gate only sees the counts.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aiasec.cli.app import app
from aiasec.core.probe import Probe, load_probes_from_dir

PROBES = load_probes_from_dir(Path("src/aiasec/probes"))
RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _run(*args: str):
    return CliRunner().invoke(app, list(args))


def _sarif(tmp_path: Path, *selection: str) -> tuple[int, dict]:
    report = tmp_path / "report.sarif"
    result = _run("run", "--response", "COMPROMISED", "--output", str(report), *selection)
    document = json.loads(report.read_text(encoding="utf-8")) if report.exists() else {}
    return result.exit_code, document


def _aiasec(document: dict) -> dict:
    return document["runs"][0]["properties"]["aiasec"]


def test_one_probe_can_be_run_alone(tmp_path) -> None:
    code, document = _sarif(tmp_path, "--probe-id", "direct-injection-001")

    assert code == 1
    assert _aiasec(document)["probesExecuted"] == 1
    assert [r["ruleId"] for r in document["runs"][0]["results"]] == ["direct-injection-001"]
    assert _aiasec(document)["selection"] == {"probeIds": ["direct-injection-001"]}


def test_filters_combine(tmp_path) -> None:
    expected = [
        probe for probe in PROBES if probe.category == "tool-abuse" and probe.severity == "critical"
    ]

    _, document = _sarif(tmp_path, "--category", "tool-abuse", "--min-severity", "critical")

    assert expected
    assert _aiasec(document)["probesExecuted"] == len(expected)
    assert _aiasec(document)["selection"] == {
        "categories": ["tool-abuse"],
        "minSeverity": "critical",
    }


def test_min_severity_keeps_more_severe_probes(tmp_path) -> None:
    expected = [probe for probe in PROBES if RANK[probe.severity] >= RANK["high"]]

    _, document = _sarif(tmp_path, "--min-severity", "high")

    assert _aiasec(document)["probesExecuted"] == len(expected)


def test_lists_accept_commas_and_spaces(tmp_path) -> None:
    expected = [probe for probe in PROBES if probe.category in {"jailbreak", "tool-abuse"}]

    _, document = _sarif(tmp_path, "--category", "jailbreak, tool-abuse")

    assert _aiasec(document)["probesExecuted"] == len(expected)
    assert _aiasec(document)["selection"] == {"categories": ["jailbreak", "tool-abuse"]}


def test_an_unknown_category_exits_2_and_names_it(tmp_path) -> None:
    report = str(tmp_path / "r.md")

    result = _run("run", "--response", "x", "--output", report, "--category", "nope")

    assert result.exit_code == 2
    assert "nope" in result.output
    assert not (tmp_path / "r.md").exists()


def test_an_unknown_probe_id_exits_2_and_names_it(tmp_path) -> None:
    result = _run("run", "--response", "x", "--output", str(tmp_path / "r.md"), "--probe-id", "x-1")

    assert result.exit_code == 2
    assert "x-1" in result.output


def test_a_selection_that_matches_nothing_exits_2(tmp_path) -> None:
    jailbreak = {probe.severity for probe in PROBES if probe.category == "jailbreak"}
    assert "critical" not in jailbreak

    result = _run(
        "run",
        "--response",
        "x",
        "--output",
        str(tmp_path / "r.md"),
        "--category",
        "jailbreak",
        "--min-severity",
        "critical",
    )

    assert result.exit_code == 2
    assert "No probe matches" in result.output


def test_a_full_run_records_no_selection(tmp_path) -> None:
    _, document = _sarif(tmp_path)

    assert "selection" not in _aiasec(document)
    assert _aiasec(document)["probesExecuted"] == len(PROBES)


def test_the_markdown_report_states_the_selection(tmp_path) -> None:
    selected = tmp_path / "selected.md"
    full = tmp_path / "full.md"

    _run("run", "--response", "x", "--output", str(selected), "--probe-id", "crescendo-001")
    _run("run", "--response", "x", "--output", str(full))

    assert "- Selection: probe ids crescendo-001" in selected.read_text(encoding="utf-8")
    assert "Selection" not in full.read_text(encoding="utf-8")


def test_probes_list_applies_the_same_filters() -> None:
    result = _run("probes", "list", "--category", "jailbreak")

    lines = result.stdout.strip().splitlines()
    assert result.exit_code == 0
    assert lines and all("\tjailbreak\t" in line for line in lines)


def test_the_gate_reads_a_filtered_report_unchanged(tmp_path) -> None:
    report = tmp_path / "report.sarif"
    _run("run", "--response", "fine", "--output", str(report), "--probe-id", "crescendo-001")

    result = _run("gate", "--report", str(report), "--max-high", "0", "--exit-on-fail")

    assert result.exit_code == 0
    assert json.loads(result.stdout)["probesExecuted"] == 1


@pytest.mark.parametrize("option", ["--probe-id", "--category"])
@pytest.mark.parametrize("value", ["", "   ", ",", " , "])
def test_an_option_given_with_no_names_is_refused(tmp_path, option: str, value: str) -> None:
    # An unset shell variable must not turn a filtered run into a run of the whole suite.
    code, document = _sarif(tmp_path, option, value)

    assert code == 2
    assert document == {}


@pytest.mark.parametrize("option", ["--probe-id", "--category"])
def test_probes_list_refuses_an_option_with_no_names(option: str) -> None:
    assert _run("probes", "list", option, "").exit_code == 2


@pytest.mark.parametrize("field", ["id", "category"])
@pytest.mark.parametrize("value", ["alpha,beta", " alpha", "alpha "])
def test_names_that_a_filter_cannot_select_are_rejected_at_load(field: str, value: str) -> None:
    # --probe-id and --category split on commas and trim spaces, so such a name could not
    # be selected, and "alpha,beta" would select two other probes instead.
    data = {
        "schema": "aiasec.probe/v1",
        "id": "alpha",
        "title": "t",
        "category": "tool-abuse",
        "severity": "high",
        "inputs": [{"role": "user", "content": "x"}],
        "expectations": [{"kind": "tool_not_called", "tool_name": "x"}],
        field: value,
    }

    with pytest.raises(ValueError, match="comma"):
        Probe.model_validate(data)

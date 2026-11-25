"""--repeat, --concurrency, and gate waivers."""

from __future__ import annotations

import json
import threading
from datetime import date, timedelta
from itertools import count
from pathlib import Path

import yaml
from typer.testing import CliRunner

from aiasec.cli.app import app
from aiasec.core.evaluator.rules import TargetObservation
from aiasec.core.probe import Probe, load_probe_file, load_probes_from_dir
from aiasec.core.runner import run_probes_against
from aiasec.outputs.markdown import render_markdown
from aiasec.outputs.sarif import render_sarif

PROBES = Path("src/aiasec/probes")
DIRECT = load_probe_file(PROBES / "prompt-injection" / "direct-injection-001.yaml")
GOOD_TARGET = Path("examples/target-mcp-good/aiasec-target.json")
SAFE = TargetObservation(assistant_final_response="I will not do that.")
UNSAFE = TargetObservation(assistant_final_response="COMPROMISED")


def _run(*args: str):
    return CliRunner().invoke(app, list(args))


def _flaky():
    calls = count()

    def observe(probe: Probe) -> TargetObservation:
        return UNSAFE if next(calls) % 3 == 0 else SAFE

    return observe


def test_a_probe_that_fails_one_run_in_three_fails_and_keeps_the_count() -> None:
    (result,) = run_probes_against([DIRECT], _flaky(), repeat=3)

    assert not result.passed
    assert (result.runs, result.failures) == (3, 1)
    assert len(result.findings) == len({finding.expectation_index for finding in result.findings})


def test_repeat_counts_reach_sarif_and_markdown() -> None:
    results = run_probes_against([DIRECT], _flaky(), repeat=3)

    run = render_sarif(results)["runs"][0]["properties"]["aiasec"]

    assert run["repeat"] == 3
    assert run["failedRuns"] == {"direct-injection-001": 1}
    assert "direct-injection-001 1/3" in render_markdown(results)


def test_a_single_run_records_no_repeat() -> None:
    results = run_probes_against([DIRECT], lambda probe: SAFE)

    assert "repeat" not in render_sarif(results)["runs"][0]["properties"]["aiasec"]


def test_concurrency_runs_probes_in_parallel_and_keeps_their_order() -> None:
    probes = load_probes_from_dir(PROBES)
    threads: set[int] = set()

    def observe(probe: Probe) -> TargetObservation:
        threads.add(threading.get_ident())
        return SAFE

    results = run_probes_against(probes, observe, concurrency=4)

    assert [result.probe.id for result in results] == [probe.id for probe in probes]
    assert len(threads) > 1


def test_repeat_needs_a_target() -> None:
    result = _run("run", "--response", "ok", "--repeat", "3", "--output", "x.md")

    assert result.exit_code == 2
    assert "--target" in result.output


def test_an_mcp_stdio_target_refuses_concurrency(tmp_path: Path) -> None:
    result = _run(
        "run", "--target", str(GOOD_TARGET), "--execute", "--concurrency", "4",
        "--output", str(tmp_path / "r.sarif"),
    )  # fmt: skip

    assert result.exit_code == 2
    assert "one request at a time" in result.output


def _compromised_report(tmp_path: Path) -> Path:
    report = tmp_path / "report.sarif"
    assert _run("run", "--response", "COMPROMISED", "--output", str(report)).exit_code == 1
    return report


def _waivers(tmp_path: Path, *entries: dict) -> Path:
    path = tmp_path / "waivers.yaml"
    path.write_text(yaml.safe_dump({"schema": "aiasec.waivers/v1", "waivers": list(entries)}))
    return path


def _waiver(**changes) -> dict:
    entry = {
        "probeId": "direct-injection-001",
        "reason": "Accepted until the model upgrade in the next sprint.",
        "owner": "appsec-team",
        "expires": (date.today() + timedelta(days=30)).isoformat(),
    }
    entry.update(changes)
    return entry


def _gate(report: Path, *extra: str):
    return _run("gate", "--report", str(report), "--max-high", "0", "--exit-on-fail", *extra)


def test_an_active_waiver_removes_its_result_from_the_counts(tmp_path: Path) -> None:
    report = _compromised_report(tmp_path)
    assert _gate(report).exit_code == 1

    result = _gate(report, "--waivers", str(_waivers(tmp_path, _waiver())))

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["verdict"] == "PASS"
    assert payload["waived"][0]["probeId"] == "direct-injection-001"
    assert payload["waived"][0]["results"] == 1


def test_an_expired_waiver_does_not_apply_and_is_reported(tmp_path: Path) -> None:
    report = _compromised_report(tmp_path)
    expired = _waiver(expires=(date.today() - timedelta(days=1)).isoformat())

    result = _gate(report, "--waivers", str(_waivers(tmp_path, expired)))

    assert result.exit_code == 1
    assert json.loads(result.output)["expiredWaivers"][0]["probeId"] == "direct-injection-001"


def test_a_waiver_for_another_expectation_does_not_apply(tmp_path: Path) -> None:
    report = _compromised_report(tmp_path)

    result = _gate(report, "--waivers", str(_waivers(tmp_path, _waiver(expectationId="nope"))))

    assert result.exit_code == 1


def test_a_waiver_without_a_real_reason_or_an_end_is_refused(tmp_path: Path) -> None:
    report = _compromised_report(tmp_path)
    too_long = (date.today() + timedelta(days=400)).isoformat()

    no_reason = _gate(report, "--waivers", str(_waivers(tmp_path, _waiver(reason="ok"))))
    forever = _gate(report, "--waivers", str(_waivers(tmp_path, _waiver(expires=too_long))))

    assert no_reason.exit_code == 2
    assert "reason" in no_reason.output
    assert forever.exit_code == 2
    assert "366 days" in forever.output

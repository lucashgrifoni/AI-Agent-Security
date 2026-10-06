import json
from pathlib import Path

from aiasec.core.evaluator.rules import TargetObservation, evaluate_probe
from aiasec.core.probe import load_probe_file
from aiasec.outputs.markdown import render_markdown
from aiasec.outputs.sarif import render_sarif_json


def test_markdown_report_contains_failed_probe_summary() -> None:
    probe = load_probe_file(
        Path("src/aiasec/probes/prompt-injection/direct-injection-001.yaml")
    )
    result = evaluate_probe(probe, TargetObservation(assistant_final_response="COMPROMISED"))

    report = render_markdown([result])

    assert "Failed probes: 1" in report
    assert "direct-injection-001" in report


def test_sarif_report_contains_failed_result() -> None:
    probe = load_probe_file(
        Path("src/aiasec/probes/prompt-injection/direct-injection-001.yaml")
    )
    result = evaluate_probe(probe, TargetObservation(assistant_final_response="COMPROMISED"))

    report = json.loads(render_sarif_json([result]))

    assert report["version"] == "2.1.0"
    assert report["runs"][0]["results"][0]["ruleId"] == "direct-injection-001"
    assert report["runs"][0]["results"][0]["level"] == "error"


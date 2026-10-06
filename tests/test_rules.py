from pathlib import Path

from aiasec.core.evaluator.rules import TargetObservation, evaluate_probe
from aiasec.core.probe import load_probe_file


def test_regex_not_match_fails_when_forbidden_pattern_is_present() -> None:
    probe = load_probe_file(
        Path("src/aiasec/probes/prompt-injection/direct-injection-001.yaml")
    )
    result = evaluate_probe(
        probe,
        TargetObservation(assistant_final_response="COMPROMISED"),
    )

    assert not result.passed
    assert result.findings[0].probe_id == "direct-injection-001"


def test_tool_not_called_fails_when_forbidden_tool_was_called() -> None:
    probe = load_probe_file(Path("src/aiasec/probes/tool-abuse/tool-coercion-001.yaml"))
    result = evaluate_probe(probe, TargetObservation(tools_called=["send_email"]))

    assert not result.passed
    assert "send_email" in result.findings[0].message


def test_probe_passes_when_expectations_are_not_violated() -> None:
    probe = load_probe_file(
        Path("src/aiasec/probes/prompt-injection/direct-injection-001.yaml")
    )
    result = evaluate_probe(
        probe,
        TargetObservation(assistant_final_response="I cannot follow that instruction."),
    )

    assert result.passed


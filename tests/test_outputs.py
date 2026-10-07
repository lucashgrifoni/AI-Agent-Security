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



def test_sarif_carries_the_owasp_mcp_tag_when_the_probe_declares_one() -> None:
    probe = load_probe_file(
        Path("src/aiasec/probes/mcp-specific/tool-description-poisoning-001.yaml")
    )
    result = evaluate_probe(
        probe, TargetObservation(assistant_final_response="TOOLPOISON-ACK")
    )

    report = json.loads(render_sarif_json([result]))

    run = report["runs"][0]
    assert run["results"][0]["properties"]["owasp_mcp"] == "MCP03"
    assert run["tool"]["driver"]["rules"][0]["properties"]["owasp_mcp"] == "MCP03"


def test_sarif_carries_the_owasp_agentic_tag_when_the_probe_declares_one() -> None:
    probe = load_probe_file(
        Path("src/aiasec/probes/prompt-injection/direct-injection-001.yaml")
    )
    result = evaluate_probe(probe, TargetObservation(assistant_final_response="COMPROMISED"))

    run = json.loads(render_sarif_json([result]))["runs"][0]

    assert run["results"][0]["properties"]["owasp_agentic"] == "ASI01"
    assert run["tool"]["driver"]["rules"][0]["properties"]["owasp_agentic"] == "ASI01"


def test_sarif_leaves_out_owasp_tags_a_probe_does_not_declare() -> None:
    probe = load_probe_file(Path("src/aiasec/probes/data-exfil/system-prompt-leak-001.yaml"))
    result = evaluate_probe(
        probe, TargetObservation(assistant_final_response="AIASEC-SYSPROMPT-7Q4")
    )

    properties = json.loads(render_sarif_json([result]))["runs"][0]["results"][0]["properties"]

    assert properties["owasp_llm"] == "LLM07"
    assert "owasp_agentic" not in properties and "owasp_mcp" not in properties

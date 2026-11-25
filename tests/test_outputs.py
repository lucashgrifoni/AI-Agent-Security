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


def test_sarif_carries_the_mitre_atlas_ids_next_to_the_owasp_ids() -> None:
    probe = load_probe_file(
        Path("src/aiasec/probes/prompt-injection/encoding-injection-001.yaml")
    )
    result = evaluate_probe(probe, TargetObservation(assistant_final_response="PWNED_B64"))

    run = json.loads(render_sarif_json([result]))["runs"][0]
    rule = run["tool"]["driver"]["rules"][0]["properties"]

    assert run["results"][0]["properties"]["mitre_atlas"] == "AML.T0051.000,AML.T0068"
    assert rule["mitre_atlas"] == "AML.T0051.000,AML.T0068"
    assert {"LLM01", "ASI01", "AML.T0051.000", "AML.T0068"} <= set(rule["tags"])


def test_sarif_leaves_out_owasp_tags_a_probe_does_not_declare() -> None:
    probe = load_probe_file(Path("src/aiasec/probes/data-exfil/system-prompt-leak-001.yaml"))
    result = evaluate_probe(
        probe, TargetObservation(assistant_final_response="AIASEC-SYSPROMPT-7Q4")
    )

    properties = json.loads(render_sarif_json([result]))["runs"][0]["results"][0]["properties"]

    assert properties["owasp_llm"] == "LLM07"
    assert "owasp_agentic" not in properties and "owasp_mcp" not in properties


def _sarif_rule(probe_path: str, reply: str) -> dict:
    probe = load_probe_file(Path(probe_path))
    result = evaluate_probe(probe, TargetObservation(assistant_final_response=reply))
    return json.loads(render_sarif_json([result]))["runs"][0]["tool"]["driver"]["rules"][0]


def test_a_sarif_rule_carries_the_security_severity_code_scanning_ranks_by() -> None:
    rule = _sarif_rule(
        "src/aiasec/probes/prompt-injection/direct-injection-001.yaml", "COMPROMISED"
    )

    assert rule["properties"]["security-severity"] == "8.0"
    assert {"security", "prompt-injection", "LLM01", "ASI01"} <= set(rule["properties"]["tags"])


def test_a_sarif_rule_tells_the_reader_what_failed_and_how_to_reproduce_it() -> None:
    rule = _sarif_rule(
        "src/aiasec/probes/prompt-injection/direct-injection-001.yaml", "COMPROMISED"
    )

    assert rule["fullDescription"]["text"]
    help_text = rule["help"]["markdown"]
    assert "aiasec probes show direct-injection-001" in help_text
    assert "--probe-id direct-injection-001" in help_text
    assert "https://owasp.org/www-project-top-10-for-large-language-model-applications/" in (
        help_text
    )
    assert rule["help"]["text"]
    assert rule["helpUri"] == (
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
    )


def test_each_severity_maps_to_a_code_scanning_band() -> None:
    from aiasec.outputs.sarif import SECURITY_SEVERITY

    # GitHub reads > 9.0 as critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low.
    assert {name: float(score) for name, score in SECURITY_SEVERITY.items()} == {
        "critical": 9.5,
        "high": 8.0,
        "medium": 5.5,
        "low": 3.0,
    }

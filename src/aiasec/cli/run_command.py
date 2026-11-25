"""`aiasec run`: send the probes to a target or score a supplied response."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from aiasec.cli.common import (
    CategoryOption,
    MinSeverityOption,
    OutputFormat,
    ProbeIdOption,
    _load_probes,
    _probe_root,
    _resolve_format,
    _select_probes,
    _validation_message,
)
from aiasec.core.conversation import parse_tool_calls
from aiasec.core.evaluator.rules import TargetObservation, ToolCall
from aiasec.core.modes import SINGLE_OBSERVATION_MODE
from aiasec.core.probe import Probe
from aiasec.core.runner import run_probes, run_probes_against
from aiasec.core.text import printable
from aiasec.core.verdict import ProbeRunResult
from aiasec.httptarget import HttpTargetError
from aiasec.judge import JudgeConfigError, Opinion, judge_results, load_judge
from aiasec.modeltarget import ModelAgentTarget, ModelTargetConfig
from aiasec.outputs.html import render_html
from aiasec.outputs.markdown import render_markdown
from aiasec.outputs.sarif import render_sarif_json
from aiasec.targets import TARGET_ERRORS, kind_of, load_target_config


def _read_response(response: str | None, response_file: Path | None) -> str:
    if response is not None and response_file is not None:
        raise typer.BadParameter("Use either --response or --response-file, not both.")
    if response_file is not None:
        return response_file.read_text(encoding="utf-8")
    return response or ""


def _parse_tools(tools_called: str | None) -> list[str]:
    if not tools_called:
        return []
    return [tool.strip() for tool in tools_called.split(",") if tool.strip()]


def _read_tool_calls(tool_calls_file: Path | None) -> list[ToolCall]:
    """Read observed tool calls in the target contract's toolsCalled shape.

    Errors never repeat the file's content: an argument may hold the secret the agent
    was tricked into sending.
    """

    if tool_calls_file is None:
        return []
    try:
        # Deep nesting exhausts the decoder's stack with RecursionError, not ValueError.
        reported = json.loads(tool_calls_file.read_text(encoding="utf-8"))
        return parse_tool_calls(reported)
    except (OSError, ValueError, RecursionError) as exc:
        if isinstance(exc, OSError):
            reason = "it cannot be read"
        elif isinstance(exc, (json.JSONDecodeError, UnicodeDecodeError, RecursionError)):
            reason = "it is not JSON"
        else:
            reason = str(exc)
        typer.echo(f"Invalid tool calls file {tool_calls_file}: {reason}.", err=True)
        raise typer.Exit(code=2) from exc


def _recording(
    observe: Callable[[Probe], TargetObservation], kept: dict[str, TargetObservation]
) -> Callable[[Probe], TargetObservation]:
    """Keep each probe's observation for the judge."""

    def observe_and_keep(probe: Probe) -> TargetObservation:
        kept[probe.id] = observation = observe(probe)
        return observation

    return observe_and_keep


def _run_against_target(
    probes: list[Probe],
    target: Path,
    *,
    execute: bool,
    kept: dict[str, TargetObservation],
) -> tuple[list[ProbeRunResult], str]:
    try:
        config = load_target_config(target)
    except ValidationError as exc:
        typer.echo(f"Invalid target config {target}:\n{_validation_message(exc)}", err=True)
        raise typer.Exit(code=2) from exc
    except (OSError, ValueError) as exc:
        typer.echo(f"Invalid target config {target}: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    kind = kind_of(config)
    if not execute:
        typer.echo(
            f"Refusing to {kind.action(config)} from {target}. Review the target config, "
            "then pass --execute to let aiasec run it.",
            err=True,
        )
        raise typer.Exit(code=2)
    try:
        with kind.start(config) as agent:
            typer.echo(kind.announcement.format(label=agent.label))
            return run_probes_against(probes, _recording(agent.observe, kept)), kind.mode
    except TARGET_ERRORS as exc:
        typer.echo(f"Target run failed: {printable(str(exc))}", err=True)
        raise typer.Exit(code=2) from exc


def run(
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Report path. Uses suffix for --format auto."),
    ] = Path("aiasec-report.md"),
    probes_dir: Annotated[
        Path | None,
        typer.Option("--probes", help="Directory with probe YAML files."),
    ] = None,
    response: Annotated[
        str | None,
        typer.Option("--response", help="Observed assistant final response."),
    ] = None,
    response_file: Annotated[
        Path | None,
        typer.Option(
            "--response-file",
            help="File containing observed assistant final response.",
            exists=True,
            dir_okay=False,
            readable=True,
        ),
    ] = None,
    tools_called: Annotated[
        str | None,
        typer.Option("--tools-called", help="Comma-separated observed tool names."),
    ] = None,
    tool_calls_file: Annotated[
        Path | None,
        typer.Option(
            "--tool-calls-file",
            help="JSON list of observed tool calls: names or {name, arguments} objects.",
            exists=True,
            dir_okay=False,
            readable=True,
        ),
    ] = None,
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", help="Report format."),
    ] = OutputFormat.auto,
    target: Annotated[
        Path | None,
        typer.Option(
            "--target",
            help="Target config (MCP stdio or HTTP) of the agent under test.",
        ),
    ] = None,
    execute: Annotated[
        bool,
        typer.Option(
            "--execute",
            help="Allow aiasec to start the --target process or send probes to its URL.",
        ),
    ] = False,
    category: CategoryOption = None,
    min_severity: MinSeverityOption = None,
    probe_id: ProbeIdOption = None,
    judge_config: Annotated[
        Path | None,
        typer.Option(
            "--judge",
            help="Model API config of an LLM judge for probes that declare a criterion. "
            "Advisory: the judge never changes results, the gate or the exit code.",
        ),
    ] = None,
) -> None:
    """Run probes against a live MCP target or a supplied observation."""

    observed = (response, response_file, tools_called, tool_calls_file)
    if target is not None and any(value is not None for value in observed):
        typer.echo(
            "--target sends each probe to the target; it cannot be combined with "
            "--response, --response-file, --tools-called, or --tool-calls-file.",
            err=True,
        )
        raise typer.Exit(code=2)
    if tools_called is not None and tool_calls_file is not None:
        typer.echo("Use either --tools-called or --tool-calls-file, not both.", err=True)
        raise typer.Exit(code=2)

    probes = _load_probes(probes_dir)
    if not probes:
        typer.echo(
            f"No probes found under {_probe_root(probes_dir)}; refusing to write a report "
            "that tested nothing.",
            err=True,
        )
        raise typer.Exit(code=2)
    probes, selection = _select_probes(probes, category, min_severity, probe_id)
    # Start the judge first: a missing key must not surface after the target run.
    judge = _start_judge(judge_config) if judge_config is not None else None

    kept: dict[str, TargetObservation] = {}
    if target is not None:
        results, observation_mode = _run_against_target(probes, target, execute=execute, kept=kept)
    else:
        observation = TargetObservation(
            assistant_final_response=_read_response(response, response_file),
            tools_called=_parse_tools(tools_called),
            tool_calls=_read_tool_calls(tool_calls_file),
        )
        results = run_probes(probes, observation)
        kept = {probe.id: observation for probe in probes}
        observation_mode = SINGLE_OBSERVATION_MODE
    opinions = None
    if judge is not None:
        asked = sum(1 for probe in probes if probe.judge)
        typer.echo(f"Asking the judge, the {judge.label}, about {asked} probe(s).")
        opinions = _opinions(judge, judge_results(results, kept, judge))

    renderers: dict[OutputFormat, Callable[..., str]] = {
        OutputFormat.sarif: render_sarif_json,
        OutputFormat.html: render_html,
        OutputFormat.markdown: render_markdown,
    }
    renderer = renderers[_resolve_format(output, output_format)]
    report = renderer(
        results, observation_mode=observation_mode, selection=selection, judge=opinions
    )

    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(report, encoding="utf-8")
    except OSError as exc:
        # Exit 1 means "a probe failed"; a report that was never written is a broken run.
        typer.echo(f"Could not write the report to {output}: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    failed = sum(1 for result in results if not result.passed)
    typer.echo(f"Wrote {output} with {failed} failed probe(s).")
    if failed:
        raise typer.Exit(code=1)


def _start_judge(judge_config: Path) -> ModelAgentTarget:
    try:
        config = ModelTargetConfig.model_validate(
            json.loads(judge_config.read_text(encoding="utf-8"))
        )
        return load_judge(config)
    except ValidationError as exc:
        typer.echo(f"Invalid judge config {judge_config}:\n{_validation_message(exc)}", err=True)
        raise typer.Exit(code=2) from exc
    except (OSError, ValueError, HttpTargetError, JudgeConfigError) as exc:
        typer.echo(f"Invalid judge config {judge_config}: {exc}", err=True)
        raise typer.Exit(code=2) from exc


def _opinions(judge: ModelAgentTarget, opinions: list[Opinion]) -> dict[str, object]:
    disagreements = sum(1 for opinion in opinions if opinion.disagrees)
    errors = sum(1 for opinion in opinions if opinion.verdict == "error")
    typer.echo(
        f"The judge gave {len(opinions)} opinion(s); {disagreements} disagree with the rules"
        + (f", {errors} could not be obtained" if errors else "")
        + ". They do not change the results."
    )
    return {
        "provider": judge.provider,
        "model": judge.model,
        "opinions": [
            {
                "probeId": opinion.probe_id,
                "criterion": opinion.criterion,
                "rulesPassed": opinion.rules_passed,
                "verdict": opinion.verdict,
                "reason": opinion.reason,
                "disagrees": opinion.disagrees,
            }
            for opinion in opinions
        ],
    }

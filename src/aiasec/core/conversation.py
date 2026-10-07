"""Turn a probe into the calls a target receives.

Each `user` input opens a turn; other inputs (retrieved documents, tool output) belong
to the turn of the user input before them, or to the first turn when no user input
precedes them. The target gets one call per turn, carrying the whole conversation so
far, including its own earlier replies as `assistant` inputs. Targets are stateless:
everything a turn needs travels in the call.

A probe is scored on the final reply and on every tool called in any turn.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from aiasec.core.evaluator.rules import TargetObservation, ToolCall
from aiasec.core.probe import Probe, ProbeInput

# One call: (arguments) -> (final text of that turn, tools called in that turn, as calls
# or as bare names).
SendTurn = Callable[[dict[str, Any]], tuple[str, Sequence[ToolCall | str]]]


def parse_tool_calls(reported: object) -> list[ToolCall]:
    """Read the tool calls a target reported for one turn.

    Each entry is a tool name, or an object with a `name` and optional `arguments` (a JSON
    object, or a string as some SDKs deliver them). Other keys are ignored. Errors never
    repeat what the target sent: an argument may hold a secret the agent was tricked into
    leaking.
    """

    if not isinstance(reported, list):
        raise ValueError("expected a list of tool names or {name, arguments} objects")
    calls: list[ToolCall] = []
    for entry in reported:
        # A blank name matches no tool, so it would hide a call from every check.
        if isinstance(entry, str) and entry.strip():
            calls.append(ToolCall(name=entry))
            continue
        name = entry.get("name") if isinstance(entry, dict) else None
        arguments = entry.get("arguments") if isinstance(entry, dict) else None
        if (
            not isinstance(name, str)
            or not name.strip()
            or not isinstance(arguments, dict | str | None)
        ):
            raise ValueError(
                "each tool call must be a tool name or an object with a non-empty string name "
                "and arguments that are an object or a string"
            )
        calls.append(ToolCall(name=name, arguments=arguments))
    return calls


def split_turns(inputs: Sequence[ProbeInput]) -> list[list[ProbeInput]]:
    """Group probe inputs into turns, one per `user` input."""

    turns: list[list[ProbeInput]] = []
    leading: list[ProbeInput] = []
    for item in inputs:
        if item.role == "user":
            turns.append([*leading, item])
            leading = []
        elif turns:
            turns[-1].append(item)
        else:
            leading.append(item)
    if leading:
        turns.append(leading)
    return turns


def drive_conversation(probe: Probe, send: SendTurn) -> TargetObservation:
    """Send a probe turn by turn and return what the target did across all turns."""

    turns = split_turns(probe.inputs)
    history: list[dict[str, Any]] = []
    calls: list[ToolCall] = []
    reply = ""
    for number, turn in enumerate(turns, start=1):
        history.extend(item.model_dump(exclude_none=True, exclude_defaults=True) for item in turn)
        reply, called = send(
            {"probeId": probe.id, "turn": number, "turns": len(turns), "inputs": list(history)}
        )
        calls.extend(call if isinstance(call, ToolCall) else ToolCall(name=call) for call in called)
        if number < len(turns):
            history.append({"role": "assistant", "content": reply})
    return TargetObservation(assistant_final_response=reply, tool_calls=calls)

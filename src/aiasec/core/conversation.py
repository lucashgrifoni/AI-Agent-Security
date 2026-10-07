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

from aiasec.core.evaluator.rules import TargetObservation
from aiasec.core.probe import Probe, ProbeInput

# One call: (arguments) -> (final text of that turn, tool names called in that turn).
SendTurn = Callable[[dict[str, Any]], tuple[str, list[str]]]


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
    tools: list[str] = []
    reply = ""
    for number, turn in enumerate(turns, start=1):
        history.extend(item.model_dump(exclude_none=True, exclude_defaults=True) for item in turn)
        reply, called = send(
            {"probeId": probe.id, "turn": number, "turns": len(turns), "inputs": list(history)}
        )
        tools.extend(called)
        if number < len(turns):
            history.append({"role": "assistant", "content": reply})
    return TargetObservation(assistant_final_response=reply, tools_called=tools)

"""Fuzz the tool calls a target reports (aiasec.core.conversation.parse_tool_calls).

HTTP targets, MCP targets and `aiasec run --tool-calls-file` hand over JSON the agent
under test produced. The harness decodes it as they do (their callers already turn
ValueError and RecursionError from the decoder into an error), then parses the calls,
which may raise ValueError (pydantic's ValidationError is one), and walks every
argument value as an argument check does. Anything else is a crash.

Oracles: every entry becomes one call with a non-blank name, and the observation built
from the calls counts every called tool.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from contextlib import nullcontext

try:
    import atheris
except ImportError:  # Linux only; tests/test_fuzz_harnesses.py replays the seeds without it
    atheris = None

# Coverage feedback comes from aiasec's own code only: instrumenting the libraries too
# made a single deeply nested input take minutes.
with atheris.instrument_imports(include=["aiasec"]) if atheris else nullcontext():
    from aiasec.core import conversation
    from aiasec.core.evaluator import rules


def test_one_input(data: bytes) -> None:
    try:
        reported = json.loads(data.decode("utf-8"))
    except (ValueError, RecursionError):
        return
    try:
        calls = conversation.parse_tool_calls(reported)
    except ValueError:
        return
    if len(calls) != len(reported) or not all(call.name.strip() for call in calls):
        raise AssertionError("a reported call was lost or kept a blank name")
    observation = rules.TargetObservation(tool_calls=calls)
    if Counter(observation.tools_called) != Counter(call.name for call in calls):
        raise AssertionError("the observation does not count every called tool")
    for call in calls:
        if call.arguments is not None:
            for _ in rules._argument_values(call.arguments):
                pass


def main() -> None:  # pragma: no cover - runs under atheris, on Linux only
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

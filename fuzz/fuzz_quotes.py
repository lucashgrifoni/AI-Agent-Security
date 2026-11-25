"""Fuzz the quote stripping behind `ignore_quoted` (aiasec.core.evaluator.rules).

A target's reply decides whether a probe passes, and `_without_quotes` removes what the
reply quotes before a pattern runs. It takes any text and raises nothing, so every
exception is a crash; a timeout points at a regular expression that backtracks.

Oracle: removing quotes never makes the reply longer. Each quote becomes one space and
code blocks are kept whole, so a longer result means text was invented.
"""

from __future__ import annotations

import sys
from contextlib import nullcontext

try:
    import atheris
except ImportError:  # Linux only; tests/test_fuzz_harnesses.py replays the seeds without it
    atheris = None

# Coverage feedback comes from aiasec's own code only: instrumenting the libraries too
# made a single deeply nested input take minutes.
with atheris.instrument_imports(include=["aiasec"]) if atheris else nullcontext():
    from aiasec.core.evaluator import rules


def test_one_input(data: bytes) -> None:
    reply = data.decode("utf-8", errors="replace")
    stripped = rules._without_quotes(reply)
    if len(stripped) > len(reply):
        raise AssertionError("quote stripping made the reply longer")


def main() -> None:  # pragma: no cover - runs under atheris, on Linux only
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

"""Fuzz the reading of an LLM judge's answer (aiasec.judge._parse).

The answer is written by a model that read text from the agent under test, so it is
untrusted. `_parse` maps anything that is not a well-formed verdict to "unclear" and
raises nothing, so every exception is a crash.

Oracle: the verdict is one of the three a judge may give, and the reason stays within
the length the report allows.
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
    from aiasec import judge


def test_one_input(data: bytes) -> None:
    verdict, reason = judge._parse(data.decode("utf-8", errors="replace"))
    if verdict not in ("yes", "no", "unclear") or len(reason) > judge.MAX_REASON:
        raise AssertionError(f"unexpected judge reading: {verdict!r}, {len(reason)} characters")


def main() -> None:  # pragma: no cover - runs under atheris, on Linux only
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

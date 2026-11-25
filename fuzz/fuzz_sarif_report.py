"""Fuzz the reading of SARIF reports by the release gate and `aiasec compare`.

`aiasec gate` and `aiasec compare` read reports written by aiasec or by anything else,
and turn ValueError (UnicodeDecodeError included) into exit code 2. Every reader is
called on its own, so one rejecting the document does not hide a crash in the next;
anything other than ValueError is a crash.

Oracles: the gate counts every result exactly once, and a run compared with itself
shows no difference.
"""

from __future__ import annotations

import sys
from contextlib import nullcontext, suppress
from typing import Any

try:
    import atheris
except ImportError:  # Linux only; tests/test_fuzz_harnesses.py replays the seeds without it
    atheris = None

# Coverage feedback comes from aiasec's own code only: instrumenting the libraries too
# made a single deeply nested input take minutes.
with atheris.instrument_imports(include=["aiasec"]) if atheris else nullcontext():
    from aiasec.core import compare, gate, sarif_reader


def test_one_input(data: bytes) -> None:
    try:
        document = gate.parse_sarif(data.decode("utf-8"))
    except ValueError:
        return
    for read in (gate.count_executed_probes, gate.read_selections, _count, _self_compare):
        with suppress(ValueError):
            read(document)


def _count(document: Any) -> None:
    counts = gate.count_severities(document)
    if sum(counts.values()) != sum(1 for _ in sarif_reader.iter_results(document)):
        raise AssertionError("the gate did not count every result exactly once")


def _self_compare(document: Any) -> None:
    summary = compare.summarize(document)
    result = compare.compare(summary, summary)
    if result.regressions or result.new_findings or result.fixed or result.not_run:
        raise AssertionError("a run compared with itself shows a difference")
    if result.not_evaluated:
        raise AssertionError("a run compared with itself has checks it did not evaluate")


def main() -> None:  # pragma: no cover - runs under atheris, on Linux only
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

"""Walk a SARIF document read from disk, failing on any part that has the wrong shape.

The gate and the comparison read reports written by aiasec or by anything else, so
each level is checked before it is trusted.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any


def iter_runs(document: Any) -> Iterator[dict[str, Any]]:
    """Each run of the document; ValueError when the document or a run is malformed."""

    if not isinstance(document, dict):
        raise ValueError("SARIF document must be a JSON object")

    runs = document.get("runs")
    if not isinstance(runs, list):
        raise ValueError("SARIF document must contain a runs list")

    for run in runs:
        if not isinstance(run, dict):
            raise ValueError("SARIF run must be a JSON object")
        yield run


def iter_results(document: Any) -> Iterator[dict[str, Any]]:
    """Each result of every run; ValueError when a results list or a result is malformed."""

    for run in iter_runs(document):
        results = run.get("results", [])
        if not isinstance(results, list):
            raise ValueError("SARIF run results must be a list")
        for result in results:
            if not isinstance(result, dict):
                raise ValueError("SARIF result must be a JSON object")
            yield result

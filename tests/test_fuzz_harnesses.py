"""Replay the seed corpus of every fuzz harness, without atheris, on every platform.

Atheris builds on Linux only, and ClusterFuzzLite runs the harnesses in fuzz/ there
(docs/testing.md). These tests import each harness as plain Python and feed it its
seeds, so a harness that stops importing, crashes on its own seeds, no longer reaches
the code it fuzzes, or swallows the errors it exists to surface fails here first.
"""

from __future__ import annotations

import importlib
import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

FUZZ = Path("fuzz")
HARNESSES = sorted(FUZZ.glob("fuzz_*.py"))
# The functions each harness exists to reach, by dotted name.
TARGETS = {
    "fuzz_judge_reply": ["aiasec.judge._parse"],
    "fuzz_mcp_tools": [
        "aiasec.mcp.audit.audit_tools",
        "aiasec.mcp.tooldefs.make_snapshot",
        "aiasec.mcp.tooldefs.compare_snapshots",
    ],
    "fuzz_probe_yaml": ["aiasec.core.probe.parse_probe"],
    "fuzz_quotes": ["aiasec.core.evaluator.rules._without_quotes"],
    "fuzz_sarif_report": [
        "aiasec.core.gate.parse_sarif",
        "aiasec.core.gate.count_executed_probes",
        "aiasec.core.gate.read_selections",
        "aiasec.core.gate.count_severities",
        "aiasec.core.compare.summarize",
    ],
    "fuzz_tool_calls": [
        "aiasec.core.conversation.parse_tool_calls",
        "aiasec.core.evaluator.rules._argument_values",
    ],
}


class Planted(Exception):
    """Not one of the exceptions any harness expects, so it must escape."""


def _harness(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _seeds(path: Path) -> list[Path]:
    corpus = FUZZ / "corpus" / path.stem
    return sorted(corpus.iterdir()) if corpus.is_dir() else []


def test_every_harness_is_listed_with_the_functions_it_fuzzes() -> None:
    assert HARNESSES, "no harness found; run the tests from the repository root"
    assert {path.stem for path in HARNESSES} == set(TARGETS)


@pytest.mark.parametrize("path", HARNESSES, ids=lambda path: path.stem)
def test_the_seed_corpus_replays_without_a_crash(path: Path) -> None:
    harness = _harness(path)
    seeds = _seeds(path)

    assert seeds, f"{path.stem} has no seed corpus in {FUZZ / 'corpus' / path.stem}"
    for seed in seeds:
        harness.test_one_input(seed.read_bytes())


@pytest.mark.parametrize(
    ("path", "target"),
    [(path, target) for path in HARNESSES for target in TARGETS.get(path.stem, [])],
    ids=lambda value: value.stem if isinstance(value, Path) else value.rsplit(".", 1)[1],
)
def test_an_unexpected_exception_in_the_target_crashes_the_harness(
    path: Path, target: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Proves the harness fit: some seed reaches the target, and what the target raises
    # outside its documented errors reaches the fuzzer as a crash.
    module, name = target.rsplit(".", 1)

    def planted(*args: object, **kwargs: object) -> None:
        raise Planted(target)

    monkeypatch.setattr(importlib.import_module(module), name, planted)
    harness = _harness(path)
    crashed = 0
    for seed in _seeds(path):
        try:
            harness.test_one_input(seed.read_bytes())
        except Planted:
            crashed += 1

    assert crashed, f"no seed of {path.stem} reaches {target}, or the harness swallows it"

"""Fuzz probe loading from YAML (aiasec.core.probe.parse_probe).

`aiasec run --probes-dir` and `aiasec probes validate` load probe files a contributor or
a third-party pack wrote. The loaders' callers expect ValueError (pydantic's
ValidationError and UnicodeDecodeError are ValueErrors) and yaml.YAMLError; anything
else is a crash.

Oracle: a probe that loads has the identity, inputs and expectations the model requires.
"""

from __future__ import annotations

import sys
from contextlib import nullcontext

import yaml

try:
    import atheris
except ImportError:  # Linux only; tests/test_fuzz_harnesses.py replays the seeds without it
    atheris = None

# Coverage feedback comes from aiasec's own code only: instrumenting the libraries too
# made a single deeply nested input take minutes.
with atheris.instrument_imports(include=["aiasec"]) if atheris else nullcontext():
    from aiasec.core import probe


def test_one_input(data: bytes) -> None:
    try:
        loaded = probe.parse_probe(data.decode("utf-8"))
    except (ValueError, yaml.YAMLError):
        return
    if not (loaded.id.strip() and loaded.inputs and loaded.expectations):
        raise AssertionError("a probe without identity, inputs or expectations loaded")


def main() -> None:  # pragma: no cover - runs under atheris, on Linux only
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

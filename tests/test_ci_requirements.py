"""Every package the workflows and the composite action install is pinned by hash.

A version range or a bare `pip install tool==1.2` trusts whatever the index serves at
run time. The workflows install from hash-locked files in .github/requirements instead,
build the package without fetching a build backend, and install npm packages with
`npm ci`. These tests read the YAML so a new install step cannot slip back.
"""

from __future__ import annotations

import re
import shlex
import tomllib
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml

LOCKS = Path(".github/requirements")
RUN_FILES = [*sorted(Path(".github/workflows").glob("*.yml")), Path("action.yml")]
PINNED = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==\S+")


def _run_scripts(path: Path) -> Iterator[str]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    jobs = document.get("jobs") or {"action": document.get("runs") or {}}
    for job in jobs.values():
        for step in job.get("steps") or []:
            if isinstance(step.get("run"), str):
                yield step["run"]


def _commands(name: str) -> list[tuple[str, list[str]]]:
    found = []
    for path in RUN_FILES:
        for script in _run_scripts(path):
            for line in re.sub(r"\\\n\s*", " ", script).splitlines():
                if name in line:
                    found.append((f"{path}: {line.strip()}", shlex.split(line, comments=True)))
    return found


def _args_after(words: list[str], marker: list[str]) -> list[str]:
    for start in range(len(words) - len(marker) + 1):
        if words[start : start + len(marker)] == marker:
            return words[start + len(marker) :]
    return []


def test_every_pip_install_is_hash_locked_or_resolves_nothing() -> None:
    commands = _commands("pip install")
    assert commands, "no pip install found; the parser is broken"
    for where, words in commands:
        args = _args_after(words, ["pip", "install"])
        packages = [arg for arg in args if not arg.startswith("-")]
        locked = "--require-hashes" in args and ("-r" in args or "--requirement" in args)
        # The package itself, with no dependency resolution and no build backend download.
        local = "--no-deps" in args and "--no-build-isolation" in args
        # The user-journey steps install the built wheel exactly as a user would.
        wheel_only = bool(packages) and all(arg.endswith(".whl") for arg in packages)
        assert locked or local or wheel_only, where


def test_every_build_uses_the_locked_backend() -> None:
    commands = _commands("-m build")
    assert commands
    for where, words in commands:
        assert "--no-isolation" in words, where


def test_npm_installs_only_from_the_lockfile() -> None:
    for where, words in _commands("npm "):
        assert _args_after(words, ["npm"])[:1] == ["ci"], where


def _pins(lock: str) -> dict[str, int]:
    """Map each pinned package to how many hashes the lock records for it."""

    pins: dict[str, int] = {}
    current = None
    for line in (LOCKS / lock).read_text(encoding="utf-8").splitlines():
        if match := PINNED.match(line):
            current = match.group(1).lower().replace("_", "-")
            pins[current] = 0
        elif current and line.strip().startswith("--hash=sha256:"):
            pins[current] += 1
    return pins


@pytest.mark.parametrize("lock", sorted(path.name for path in LOCKS.glob("*.txt")))
def test_every_locked_package_carries_a_hash(lock: str) -> None:
    pins = _pins(lock)
    assert pins
    assert all(count > 0 for count in pins.values()), lock
    header = (LOCKS / lock).read_text(encoding="utf-8").splitlines()[1]
    # Dependabot re-runs the recorded command; without these flags it would drop hashes
    # or resolve for one platform only.
    assert "uv pip compile" in header and "--generate-hashes" in header, header
    assert "--universal" in header, header


def _names(requirements: list[str]) -> set[str]:
    return {re.split(r"[<>=!~;\[ ]", item, maxsplit=1)[0].lower() for item in requirements}


def test_the_locks_cover_what_pyproject_declares() -> None:
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    runtime = _names(project["project"]["dependencies"])
    dev = _names(project["project"]["optional-dependencies"]["dev"])
    backend = _names(project["build-system"]["requires"])

    assert runtime | backend <= set(_pins("action.txt"))
    assert runtime | dev | backend <= set(_pins("ci.txt"))
    assert backend <= set(_pins("build.txt"))

"""Every package the workflows and the composite action install is pinned by hash.

A version range or a bare `pip install tool==1.2` trusts whatever the index serves at
run time. The workflows install from hash-locked files that Dependabot keeps current,
build the package without fetching a build backend, and install npm packages with
`npm ci`. These tests read the YAML so a new install step cannot slip back.
"""

from __future__ import annotations

import re
import shlex
import tomllib
from collections.abc import Iterator
from itertools import pairwise
from pathlib import Path

import pytest
import yaml

LOCKS = Path(".github/requirements")
# The directories of the uv entries in dependabot.yml, where the hash-locked files live.
LOCK_DIRS = [
    Path(update["directory"].strip("/"))
    for update in yaml.safe_load(Path(".github/dependabot.yml").read_text(encoding="utf-8"))[
        "updates"
    ]
    if update["package-ecosystem"] == "uv"
]
RUN_FILES = [*sorted(Path(".github/workflows").glob("*.yml")), Path("action.yml")]
PINNED = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==(\S+)")


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


def _normal(name: str) -> str:
    return name.lower().replace("_", "-")


def _pins(lock: Path) -> dict[str, int]:
    """Map each pinned package to how many hashes the lock records for it."""

    pins: dict[str, int] = {}
    current = None
    for line in lock.read_text(encoding="utf-8").splitlines():
        if match := PINNED.match(line):
            current = _normal(match.group(1))
            pins[current] = 0
        elif current and line.strip().startswith("--hash=sha256:"):
            pins[current] += 1
    return pins


def _versions(lock: Path) -> dict[str, str]:
    matches = [PINNED.match(line) for line in lock.read_text(encoding="utf-8").splitlines()]
    return {_normal(match.group(1)): match.group(2) for match in matches if match}


def _read_together(directory: Path, suffix: str) -> list[Path]:
    """The files one Dependabot uv entry reads: its directory and immediate subdirectories."""

    return sorted([*directory.glob(f"*{suffix}"), *directory.glob(f"*/*{suffix}")])


@pytest.mark.parametrize(
    "lock", [lock for directory in LOCK_DIRS for lock in _read_together(directory, ".txt")], ids=str
)
def test_every_locked_package_carries_a_hash(lock: Path) -> None:
    pins = _pins(lock)
    assert pins
    assert all(count > 0 for count in pins.values()), lock
    header = lock.read_text(encoding="utf-8").splitlines()[1]
    # Dependabot re-runs the recorded command; without these flags it would drop hashes
    # or resolve for one platform only.
    assert "uv pip compile" in header and "--generate-hashes" in header, header
    assert "--universal" in header, header


def _names(requirements: list[str]) -> set[str]:
    return {_normal(re.split(r"[<>=!~;\[ ]", item, maxsplit=1)[0]) for item in requirements}


@pytest.mark.parametrize("directory", LOCK_DIRS, ids=str)
def test_a_direct_requirement_has_one_version_in_its_dependabot_directory(directory: Path) -> None:
    # Dependabot moves a package to one new version in every lock of the directory at once.
    # A lock that holds the package back makes the resolution fail and ends the whole update
    # job without a pull request: semgrep held jsonschema below the version ci.txt used.
    lines = [
        line.strip()
        for source in _read_together(directory, ".in")
        for line in source.read_text(encoding="utf-8").splitlines()
    ]
    direct = _names([line for line in lines if line and not line.startswith(("#", "-"))])
    locks = {lock: _versions(lock) for lock in _read_together(directory, ".txt")}
    assert direct and locks, directory
    for name in sorted(direct):
        versions = {str(lock): pins[name] for lock, pins in locks.items() if name in pins}
        assert len(set(versions.values())) == 1, f"{name}: {versions}"


def test_every_lock_the_workflows_read_is_kept_current_by_dependabot() -> None:
    locks = set()
    for _, words in _commands("pip"):
        for flag, value in pairwise(words):
            if flag in ("-r", "--requirement"):
                locks.add(Path(value.removeprefix("$GITHUB_ACTION_PATH/")))
    assert locks, "no requirements file found; the parser is broken"
    for lock in sorted(locks):
        assert lock.is_file(), lock
        assert lock.parent in LOCK_DIRS or lock.parent.parent in LOCK_DIRS, lock


def test_the_locks_cover_what_pyproject_declares() -> None:
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    runtime = _names(project["project"]["dependencies"])
    dev = _names(project["project"]["optional-dependencies"]["dev"])
    backend = _names(project["build-system"]["requires"])

    assert runtime | backend <= set(_pins(LOCKS / "action.txt"))
    assert runtime | dev | backend <= set(_pins(LOCKS / "ci.txt"))
    assert backend <= set(_pins(LOCKS / "build.txt"))

"""The composite action and its self-test cover Linux, macOS and Windows runners.

A virtualenv keeps its executables in `bin/` on POSIX and in `Scripts/` on Windows, and
a Windows runner's default shell is PowerShell. These tests read the YAML so a step that
assumes one layout or one shell cannot slip back.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

ACTION = Path("action.yml")
SELFTEST = Path(".github/workflows/action-selftest.yml")
HARDEN_RUNNER = "step-security/harden-runner@"
# The required status checks of master name these jobs; the Linux leg keeps the name.
REQUIRED_CHECKS = ["Action - good target passes", "Action - vulnerable target fails"]
EGRESS_ALLOWLIST = {
    "api.github.com:443",
    "files.pythonhosted.org:443",
    "github.com:443",
    "objects.githubusercontent.com:443",
    "pypi.org:443",
    "release-assets.githubusercontent.com:443",
}


def _load(path: Path) -> dict[str, Any]:
    document: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
    return document


def _action_steps() -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = _load(ACTION)["runs"]["steps"]
    return steps


def _selftest_jobs() -> dict[str, dict[str, Any]]:
    jobs: dict[str, dict[str, Any]] = _load(SELFTEST)["jobs"]
    return jobs


def test_no_action_step_assumes_the_posix_virtualenv_layout() -> None:
    for step in _action_steps():
        assert "/bin/" not in step.get("run", ""), step["name"]


def test_the_install_step_picks_the_venv_directory_by_runner_os() -> None:
    install = next(step for step in _action_steps() if step.get("id") == "install")
    script = install["run"]
    assert re.search(r'if \[ "\$RUNNER_OS" = "Windows" \]; then bin="\$venv/Scripts"', script)
    assert 'else bin="$venv/bin"; fi' in script
    assert 'echo "bin=$bin" >> "$GITHUB_OUTPUT"' in script


def test_the_aiasec_steps_run_the_executable_the_install_step_reports() -> None:
    steps = {step.get("id"): step for step in _action_steps()}
    for step_id in ("run", "gate"):
        step = steps[step_id]
        assert step["env"]["AIASEC_BIN"] == "${{ steps.install.outputs.bin }}", step_id
        assert '"$AIASEC_BIN/aiasec" "${args[@]}"' in step["run"], step_id


def test_every_action_script_runs_in_bash_and_reads_inputs_only_from_env() -> None:
    for step in _action_steps():
        if "run" in step:
            assert step["shell"] == "bash", step["name"]
            # An expression inside the script would splice an input value into shell.
            assert "${{" not in step["run"], step["name"]


def test_the_selftest_runs_each_job_on_linux_and_windows() -> None:
    for job_id, job in _selftest_jobs().items():
        assert job["runs-on"] == "${{ matrix.os }}", job_id
        assert job["strategy"]["matrix"]["os"] == ["ubuntu-latest", "windows-latest"], job_id
        assert job["strategy"]["fail-fast"] is False, job_id


def test_the_linux_legs_keep_the_required_check_names() -> None:
    names = [job["name"] for job in _selftest_jobs().values()]
    suffix = "${{ matrix.os == 'windows-latest' && ' (Windows)' || '' }}"
    assert names == [f"{check}{suffix}" for check in REQUIRED_CHECKS]


def test_harden_runner_runs_on_linux_only_with_the_exact_allowlist() -> None:
    for job_id, job in _selftest_jobs().items():
        guards = [step for step in job["steps"] if step.get("uses", "").startswith(HARDEN_RUNNER)]
        assert len(guards) == 1, job_id
        (guard,) = guards
        assert guard["if"] == "runner.os == 'Linux'", job_id
        assert guard["with"]["egress-policy"] == "block", job_id
        assert set(guard["with"]["allowed-endpoints"].split()) == EGRESS_ALLOWLIST, job_id


def test_the_selftest_scripts_run_in_bash_with_the_setup_python_interpreter() -> None:
    assert _load(SELFTEST)["defaults"]["run"]["shell"] == "bash"
    for job_id, job in _selftest_jobs().items():
        for step in job["steps"]:
            # setup-python puts `python` on PATH on every runner; `python3` is not portable.
            assert "python3" not in step.get("run", ""), (job_id, step["name"])

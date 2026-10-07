"""The harness templates in examples/harness are safe to copy and fail closed.

A template that has not been connected to an agent must fail the aiasec run: a stub
that answered something would pass every probe without testing anything. The
templates also stay standard-library only, so they can be copied into any project.
"""

from __future__ import annotations

import ast
import json
import re
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aiasec.cli.app import app
from aiasec.core.probe import Probe, load_probes_from_dir

HARNESS = Path("examples/harness")
PROBES = Path("src/aiasec/probes")
TEMPLATES = sorted(HARNESS.glob("*.py"))


def _run_target(tmp_path: Path, config: dict[str, object]):
    target = tmp_path / "target.json"
    target.write_text(json.dumps(config), encoding="utf-8")
    output = tmp_path / "report.sarif"
    result = CliRunner().invoke(
        app, ["run", "--target", str(target), "--execute", "--output", str(output),
              "--probe-id", "direct-injection-001"],
    )  # fmt: skip
    return result, output


@pytest.mark.parametrize("template", TEMPLATES, ids=lambda path: path.name)
def test_templates_import_only_the_standard_library(template: Path) -> None:
    tree = ast.parse(template.read_text(encoding="utf-8"))
    modules = {
        (node.module or "").split(".")[0] if isinstance(node, ast.ImportFrom) else alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import | ast.ImportFrom)
        for alias in node.names
    }

    assert modules <= set(sys.stdlib_module_names) | {"__future__"}, modules


def test_an_unconnected_mcp_template_fails_the_run(tmp_path: Path) -> None:
    config = {
        "transport": "stdio",
        "command": [sys.executable, str(HARNESS / "mcp_stdio_harness.py")],
    }

    result, output = _run_target(tmp_path, config)

    assert result.exit_code == 2, result.output
    assert "tool error" in result.output
    assert not output.exists()


@pytest.fixture
def http_template() -> Iterator[str]:
    with socket.socket() as probe_socket:
        probe_socket.bind(("127.0.0.1", 0))
        port = probe_socket.getsockname()[1]
    process = subprocess.Popen(
        [sys.executable, str(HARNESS / "http_harness.py"), "--port", str(port)],
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            with socket.socket() as client:
                if client.connect_ex(("127.0.0.1", port)) == 0:
                    break
            time.sleep(0.1)
        yield f"http://127.0.0.1:{port}/chat"
    finally:
        process.terminate()
        process.wait(timeout=5)


def _readme_example() -> str:
    readme = (HARNESS / "README.md").read_text(encoding="utf-8")
    match = re.search(r"```python\n(.*?)```", readme, re.S)
    assert match, "examples/harness/README.md lost its adapter example"
    return match.group(1)


@pytest.mark.parametrize("probe", load_probes_from_dir(PROBES), ids=lambda probe: probe.id)
def test_the_readme_example_hands_every_input_to_the_agent(probe: Probe) -> None:
    """A copied adapter that drops a role lets that role's probes pass untested."""

    received: list[object] = []

    class FakeAgent:
        def run(self, *args: object, **kwargs: object) -> tuple[str, list[object]]:
            received.append((args, kwargs))
            return "ok", []

    namespace: dict[str, object] = {"my_agent": FakeAgent()}
    exec(_readme_example(), namespace)  # noqa: S102 - this repository's own example
    inputs = [item.model_dump(exclude_none=True) for item in probe.inputs]

    namespace["run_agent"](inputs)  # type: ignore[operator]

    handed_over = json.dumps(received)
    for item in probe.inputs:
        texts = [item.content, *(doc.injected for doc in item.documents)]
        for text in filter(None, texts):
            assert json.dumps(text)[1:-1] in handed_over, (probe.id, item.role)


def test_an_unconnected_http_template_fails_the_run(tmp_path: Path, http_template: str) -> None:
    result, output = _run_target(tmp_path, {"transport": "http", "url": http_template})

    assert result.exit_code == 2, result.output
    assert "HTTP 500" in result.output
    assert not output.exists()

"""The harness templates in examples/harness are safe to copy and fail closed.

A template that has not been connected to an agent must fail the aiasec run: a stub
that answered something would pass every probe without testing anything. The
templates also stay standard-library only (one may reuse another), so they can be
copied into any project.
"""

from __future__ import annotations

import ast
import importlib
import json
import re
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
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

    siblings = {path.stem for path in TEMPLATES}
    assert modules <= set(sys.stdlib_module_names) | {"__future__"} | siblings, modules


def test_an_unconnected_mcp_template_fails_the_run(tmp_path: Path) -> None:
    config = {
        "transport": "stdio",
        "command": [sys.executable, str(HARNESS / "mcp_stdio_harness.py")],
    }

    result, output = _run_target(tmp_path, config)

    assert result.exit_code == 2, result.output
    assert "tool error" in result.output
    assert not output.exists()


def test_an_unconnected_mcp_http_template_fails_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # In process: a subprocess listener was unreachable on the macOS CI runner.
    monkeypatch.syspath_prepend(str(HARNESS.resolve()))
    server = importlib.import_module("mcp_http_harness").make_server(port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/mcp"
        result, output = _run_target(tmp_path, {"transport": "mcp-http", "url": url})
    finally:
        server.shutdown()
        server.server_close()

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


def test_the_readme_example_keeps_system_inputs_in_order() -> None:
    received: list[object] = []

    class FakeAgent:
        def run(self, messages: list[dict[str, str]], **_: object) -> tuple[str, list[object]]:
            received.extend(message["content"] for message in messages)
            return "ok", []

    namespace: dict[str, object] = {"my_agent": FakeAgent()}
    exec(_readme_example(), namespace)  # noqa: S102 - this repository's own example
    inputs = [
        {"role": "system", "content": "first"},
        {"role": "user", "content": "hello"},
        {"role": "system", "content": "second"},
    ]

    namespace["run_agent"](inputs)  # type: ignore[operator]

    assert received == ["first", "second", "hello"]


@pytest.fixture(params=["http_harness", "mcp_http_harness"])
def template_server(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.syspath_prepend(str(HARNESS.resolve()))
    module = importlib.import_module(request.param)
    if request.param == "http_harness":
        server = ThreadingHTTPServer(("127.0.0.1", 0), module.make_handler(module.run_agent))
        path = "/chat"
    else:
        server = module.make_server(port=0)
        path = "/mcp"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield server.server_address[1], path
    finally:
        server.shutdown()
        server.server_close()


def _status_of_raw_post(port: int, path: str, length_header: str) -> int | None:
    """Send a POST's headers only, then wait; the status, or None when none comes.

    No body follows, as from a client that holds the connection open: a harness that
    trusted the length would wait for bytes that never arrive.
    """

    request = f"POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{length_header}\r\n\r\n".encode()
    with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
        client.sendall(request)
        try:
            status_line = client.recv(64)
        except (TimeoutError, ConnectionError):
            return None
    parts = status_line.split()
    return int(parts[1]) if len(parts) > 1 else None


@pytest.mark.parametrize(
    ("length_header", "expected"),
    [
        ("Content-Length: -1", 400),
        ("Content-Length: abc", 400),
        ("Content-Length: +5", 400),
        ("Content-Length: 2097152", 413),
        ("X-No-Length: 1", 411),
    ],
    ids=["negative", "not-a-number", "signed", "too-large", "missing"],
)
def test_a_template_refuses_a_bad_content_length_before_reading(
    template_server: tuple[int, str], length_header: str, expected: int
) -> None:
    port, path = template_server

    status = _status_of_raw_post(port, path, length_header)

    assert status == expected

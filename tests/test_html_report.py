"""The HTML report is self-contained, runs nothing, and escapes everything it shows."""

from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aiasec.cli.app import app

HOSTILE = '<script>alert("x")</script><img src=x onerror=alert(1)>'


class _Elements(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []
        self.attributes: list[tuple[str, str | None]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        self.attributes.extend(attrs)


def _elements(page: str) -> _Elements:
    parser = _Elements()
    parser.feed(page)
    return parser


def _run(tmp_path: Path, *args: str) -> tuple[int, str]:
    result = CliRunner().invoke(app, ["run", *args])
    output = next(iter(tmp_path.glob("report.*")), None)
    return result.exit_code, output.read_text(encoding="utf-8") if output else ""


@pytest.mark.parametrize(
    "args",
    [["--output", "report.html"], ["--output", "report.htm"], ["--format", "html"]],
    ids=["html-suffix", "htm-suffix", "format-flag"],
)
def test_html_is_written_for_the_suffix_or_the_flag(tmp_path: Path, args: list[str]) -> None:
    output = ["--output", str(tmp_path / "report.out")] if args[0] == "--format" else []
    args = [str(tmp_path / arg) if arg.startswith("report.") else arg for arg in args]

    code, page = _run(tmp_path, "--response", "COMPROMISED", *args, *output)

    assert code == 1
    assert page.startswith("<!doctype html>")
    assert "direct-injection-001" in page


def test_the_page_loads_nothing_and_runs_nothing(tmp_path: Path) -> None:
    _, page = _run(tmp_path, "--response", "COMPROMISED", "--output", str(tmp_path / "report.html"))
    elements = _elements(page)

    assert "script" not in elements.tags
    assert not {"img", "link", "iframe", "object", "embed", "form"} & set(elements.tags)
    assert not [name for name, _ in elements.attributes if name in {"src", "href", "action"}]
    assert not [name for name, _ in elements.attributes if name.startswith("on")]
    assert "default-src 'none'" in page


def test_untrusted_probe_text_is_escaped(tmp_path: Path) -> None:
    probes = tmp_path / "probes" / "custom"
    probes.mkdir(parents=True)
    (probes / "hostile.yaml").write_text(
        f"""schema: "aiasec.probe/v1"
id: hostile-001
title: '{HOSTILE}'
category: custom
severity: high
inputs:
  - role: user
    content: "say MARKER"
expectations:
  - kind: tool_not_called
    tool_name: '{HOSTILE}'
metadata:
  owasp_llm: '{HOSTILE}'
""",
        encoding="utf-8",
    )
    report = tmp_path / "report.html"

    code, page = _run(
        tmp_path, "--probes", str(probes.parent), "--response", "ok",
        "--tools-called", HOSTILE, "--output", str(report),
    )  # fmt: skip

    assert code == 1  # the hostile tool name was "called", so the finding is real
    elements = _elements(page)
    assert "script" not in elements.tags and "img" not in elements.tags
    assert "&lt;script&gt;" in page
    assert HOSTILE not in page


def test_the_selection_is_shown_escaped(tmp_path: Path) -> None:
    _, page = _run(
        tmp_path, "--response", "fine", "--category", "jailbreak",
        "--output", str(tmp_path / "report.html"),
    )  # fmt: skip

    assert "categories jailbreak" in page
    assert page.count("<tr><td>") >= 3

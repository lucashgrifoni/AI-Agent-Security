"""Fuzz the static audit and the snapshots of MCP tool definitions.

`aiasec mcp audit` and `aiasec mcp snapshot` read the `tools/list` result of a server
that may be hostile. The input is that list as JSON; like McpStdioAdapter.list_tools,
anything but a list of objects is rejected before the audit. `audit_tools` raises
nothing and `make_snapshot` raises ValueError for a missing or repeated name; anything
else is a crash.

Oracles: what the audit reports about the server (tool name, field path, excerpt) has
no control or invisible character left; a snapshot equals the snapshot of its own
definitions, and compared with itself it is UNCHANGED.

Python's decoder accepts NaN and Infinity, which JSON does not have. NaN never equals
itself, so a tool carrying one compares as changed against an identical snapshot; that
known false positive is reported in docs/testing.md, and these constants are left out
here so the oracle keeps finding new defects.
"""

from __future__ import annotations

import json
import sys
from contextlib import nullcontext

try:
    import atheris
except ImportError:  # Linux only; tests/test_fuzz_harnesses.py replays the seeds without it
    atheris = None

# Coverage feedback comes from aiasec's own code only: instrumenting the libraries too
# made a single deeply nested input take minutes.
with atheris.instrument_imports(include=["aiasec"]) if atheris else nullcontext():
    from aiasec.core.text import INVISIBLE
    from aiasec.mcp import audit, tooldefs


def test_one_input(data: bytes) -> None:
    try:
        tools = json.loads(data.decode("utf-8"), parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        return
    if not isinstance(tools, list) or not all(isinstance(tool, dict) for tool in tools):
        return
    for finding in audit.audit_tools(tools):
        if any(map(_hidden, finding.tool + finding.field + finding.excerpt)):
            raise AssertionError(f"{finding.rule.id} reports a hidden character unescaped")
    try:
        snapshot = tooldefs.make_snapshot({"name": "fuzz"}, tools)
    except ValueError:
        return
    if tooldefs.make_snapshot({"name": "fuzz"}, tooldefs.tools_of(snapshot)) != snapshot:
        raise AssertionError("a snapshot differs from the snapshot of its own definitions")
    if tooldefs.compare_snapshots(snapshot, snapshot)["verdict"] != "UNCHANGED":
        raise AssertionError("a snapshot compared with itself is not UNCHANGED")


def _reject_constant(name: str) -> float:
    raise ValueError(f"{name} is not JSON")


def _hidden(char: str) -> bool:
    code = ord(char)
    return code < 0x20 or code == 0x7F or 0x80 <= code < 0xA0 or bool(INVISIBLE.match(char))


def main() -> None:  # pragma: no cover - runs under atheris, on Linux only
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

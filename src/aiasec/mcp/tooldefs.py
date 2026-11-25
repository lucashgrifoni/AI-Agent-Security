"""Snapshot the tool definitions an MCP server exposes, and compare two snapshots.

MCP does not pin a tool's definition: a server approved with a harmless description
can change it later (a "rug pull"), and the model reads the new text on the next
connection. A snapshot records a SHA-256 of each definition; a diff of two snapshots
names every tool that was added, removed or changed, and which fields changed.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

SNAPSHOT_SCHEMA = "aiasec.tools-snapshot/v1"
# The parts of a tool definition the model reads or a client enforces.
DEFINITION_FIELDS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")


def definition(tool: Mapping[str, Any]) -> dict[str, Any]:
    """The fields of a tool that make up its definition, without anything else."""

    return {field: tool[field] for field in DEFINITION_FIELDS if field in tool}


def digest(tool: Mapping[str, Any]) -> str:
    """SHA-256 of the definition in canonical JSON: key order and spacing do not count."""

    canonical = json.dumps(definition(tool), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def make_snapshot(server_info: Mapping[str, Any], tools: Sequence[Mapping[str, Any]]) -> dict:
    """A snapshot of the tools, sorted by name. A name listed twice is an error."""

    names = [tool.get("name") for tool in tools]
    if not all(isinstance(name, str) and name for name in names):
        raise ValueError("every tool must have a non-empty string name")
    valid = [str(name) for name in names]
    repeated = sorted({name for name in valid if valid.count(name) > 1})
    if repeated:
        raise ValueError(f"the server lists these tool names more than once: {repeated}")
    return {
        "schema": SNAPSHOT_SCHEMA,
        "server": {key: server_info[key] for key in ("name", "version") if key in server_info},
        "tools": [
            {"name": tool["name"], "sha256": digest(tool), "definition": definition(tool)}
            for tool in sorted(tools, key=lambda tool: tool["name"])
        ],
    }


def load_snapshot(path: Path) -> dict:
    """Read a snapshot file; ValueError when it is not one aiasec wrote."""

    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("schema") != SNAPSHOT_SCHEMA:
        raise ValueError(f"{path} is not an aiasec tools snapshot ({SNAPSHOT_SCHEMA})")
    tools = document.get("tools")
    if not isinstance(tools, list) or not all(
        isinstance(tool, dict)
        and isinstance(tool.get("name"), str)
        and isinstance(tool.get("definition"), dict)
        for tool in tools
    ):
        raise ValueError(f"{path} has a malformed tools list")
    return document


def tools_of(snapshot: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The tool definitions stored in a snapshot."""

    return [dict(tool["definition"]) for tool in snapshot["tools"]]


def compare_snapshots(baseline: Mapping[str, Any], current: Mapping[str, Any]) -> dict:
    """What changed between two snapshots, tool by tool and field by field."""

    before = {tool["name"]: tool["definition"] for tool in baseline["tools"]}
    after = {tool["name"]: tool["definition"] for tool in current["tools"]}
    changed = []
    for name in sorted(before.keys() & after.keys()):
        fields = [
            field
            for field in DEFINITION_FIELDS
            if before[name].get(field) != after[name].get(field)
        ]
        if fields:
            changed.append({"name": name, "fields": fields})
    added = sorted(after.keys() - before.keys())
    removed = sorted(before.keys() - after.keys())
    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "verdict": "CHANGED" if added or removed or changed else "UNCHANGED",
    }

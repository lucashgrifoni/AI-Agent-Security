"""docs/owasp-mapping.md must list every bundled probe exactly as its YAML declares it."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from aiasec.core.probe import load_probes_from_dir

PROBES = load_probes_from_dir(Path("src/aiasec/probes"))
ROW = re.compile(
    r"^\| `([a-z0-9-]+)` \| (\w+) \| (LLM\d+)[^|]*\|\s*(MCP\d+)?[^|]*\|\s*(ASI\d+)?",
    re.MULTILINE,
)
ID_FORMATS = {"owasp_llm": r"LLM(0[1-9]|10)", "owasp_mcp": r"MCP(0[1-9]|10)",
              "owasp_agentic": r"ASI(0[1-9]|10)"}  # fmt: skip


def test_the_owasp_mapping_table_matches_the_bundled_probes() -> None:
    declared = {
        probe.id: (
            probe.severity,
            probe.metadata.get("owasp_llm"),
            probe.metadata.get("owasp_mcp"),
            probe.metadata.get("owasp_agentic"),
        )
        for probe in PROBES
    }
    documented = {
        probe_id: (severity, llm, mcp or None, agentic or None)
        for probe_id, severity, llm, mcp, agentic in ROW.findall(
            Path("docs/owasp-mapping.md").read_text(encoding="utf-8")
        )
    }

    assert documented == declared


@pytest.mark.parametrize("probe", PROBES, ids=lambda probe: probe.id)
def test_bundled_owasp_ids_are_well_formed(probe) -> None:
    for key, pattern in ID_FORMATS.items():
        value = probe.metadata.get(key)
        assert value is None or re.fullmatch(pattern, value), (probe.id, key, value)

"""docs/owasp-mapping.md must list every bundled probe exactly as its YAML declares it."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from aiasec.core.probe import load_probes_from_dir

PROBES = load_probes_from_dir(Path("src/aiasec/probes"))
MAPPING = Path("docs/owasp-mapping.md").read_text(encoding="utf-8")
ROW = re.compile(
    r"^\| `([a-z0-9-]+)` \| (\w+) \| (LLM\d+)[^|]*\|\s*(MCP\d+)?[^|]*\|\s*(ASI\d+)?[^|]*"
    r"\|\s*([^|]*?)\s*\|",
    re.MULTILINE,
)
# A row of the ATLAS basis table: | AML.T0051.001 LLM Prompt Injection: Indirect | ...
ATLAS_BASIS_ROW = re.compile(r"^\| (AML\.T\d{4}(?:\.\d{3})?) [^|]+\|", re.MULTILINE)
ID_FORMATS = {"owasp_llm": r"LLM(0[1-9]|10)", "owasp_mcp": r"MCP(0[1-9]|10)",
              "owasp_agentic": r"ASI(0[1-9]|10)",
              "mitre_atlas": r"AML\.T\d{4}(\.\d{3})?(,AML\.T\d{4}(\.\d{3})?)*"}  # fmt: skip


def _atlas_ids(value: str | None) -> frozenset[str]:
    return frozenset(part.strip() for part in (value or "").split(",") if part.strip())


def test_the_owasp_mapping_table_matches_the_bundled_probes() -> None:
    declared = {
        probe.id: (
            probe.severity,
            probe.metadata.get("owasp_llm"),
            probe.metadata.get("owasp_mcp"),
            probe.metadata.get("owasp_agentic"),
            _atlas_ids(probe.metadata.get("mitre_atlas")),
        )
        for probe in PROBES
    }
    documented = {
        probe_id: (severity, llm, mcp or None, agentic or None, _atlas_ids(atlas))
        for probe_id, severity, llm, mcp, agentic, atlas in ROW.findall(MAPPING)
    }

    assert documented == declared


def test_every_bundled_probe_declares_mitre_atlas_techniques() -> None:
    assert [probe.id for probe in PROBES if not probe.metadata.get("mitre_atlas")] == []


def test_the_atlas_basis_lists_each_technique_the_probes_use() -> None:
    used = set().union(*(_atlas_ids(probe.metadata.get("mitre_atlas")) for probe in PROBES))
    explained = set(ATLAS_BASIS_ROW.findall(MAPPING))

    assert explained == used


@pytest.mark.parametrize("probe", PROBES, ids=lambda probe: probe.id)
def test_bundled_owasp_ids_are_well_formed(probe) -> None:
    for key, pattern in ID_FORMATS.items():
        value = probe.metadata.get(key)
        assert value is None or re.fullmatch(pattern, value), (probe.id, key, value)

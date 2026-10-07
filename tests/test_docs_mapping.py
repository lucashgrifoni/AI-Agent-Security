"""docs/owasp-mapping.md must list every bundled probe exactly as its YAML declares it."""

from __future__ import annotations

import re
from pathlib import Path

from aiasec.core.probe import load_probes_from_dir

ROW = re.compile(r"^\| `([a-z0-9-]+)` \| (\w+) \| (LLM\d+)[^|]*\|\s*(MCP\d+)?", re.MULTILINE)


def test_the_owasp_mapping_table_matches_the_bundled_probes() -> None:
    probes = {
        probe.id: (probe.severity, probe.metadata.get("owasp_llm"), probe.metadata.get("owasp_mcp"))
        for probe in load_probes_from_dir(Path("src/aiasec/probes"))
    }
    documented = {
        probe_id: (severity, llm, mcp or None)
        for probe_id, severity, llm, mcp in ROW.findall(
            Path("docs/owasp-mapping.md").read_text(encoding="utf-8")
        )
    }

    assert documented == probes

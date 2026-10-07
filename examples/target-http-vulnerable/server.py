"""Deliberately vulnerable HTTP target for aiasec.

The HTTP counterpart of examples/target-mcp-vulnerable: serves `vulnerable_agent` from
examples/reference_agents.py through the HTTP harness template
(examples/harness/http_harness.py). No LLM is involved, so every bundled probe fails
against it on every run.

Serves POST /chat on 127.0.0.1 only. Standard library only.
Run: python examples/target-http-vulnerable/server.py --port 8765
"""

from __future__ import annotations

import sys
from pathlib import Path

EXAMPLES = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(EXAMPLES), str(EXAMPLES / "harness")]

from http_harness import main  # noqa: E402
from reference_agents import vulnerable_agent  # noqa: E402

if __name__ == "__main__":
    main(vulnerable_agent)

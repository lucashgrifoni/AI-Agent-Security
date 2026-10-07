"""Well-behaved MCP stdio target for aiasec.

Serves `good_agent` from examples/reference_agents.py through the MCP stdio harness
template (examples/harness/mcp_stdio_harness.py): an agent that treats prompts,
retrieved documents, and tool output as data. No LLM is involved, so every bundled
probe passes against it on every run.

Standard library only. Run: python examples/target-mcp-good/server.py
"""

from __future__ import annotations

import sys
from pathlib import Path

EXAMPLES = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(EXAMPLES), str(EXAMPLES / "harness")]

from mcp_stdio_harness import serve  # noqa: E402
from reference_agents import good_agent  # noqa: E402

if __name__ == "__main__":
    serve(good_agent, server_name="aiasec-target-good")

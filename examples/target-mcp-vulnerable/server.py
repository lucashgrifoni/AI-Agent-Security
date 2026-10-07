"""Deliberately vulnerable MCP stdio target for aiasec.

Serves `vulnerable_agent` from examples/reference_agents.py through the MCP stdio
harness template (examples/harness/mcp_stdio_harness.py): an agent that repeats
attacker-controlled text and calls any tool that text names. No LLM is involved, so
every bundled probe fails against it on every run. Use it to see what a failing report
looks like.

Standard library only. Run: python examples/target-mcp-vulnerable/server.py
"""

from __future__ import annotations

import sys
from pathlib import Path

EXAMPLES = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(EXAMPLES), str(EXAMPLES / "harness")]

from mcp_stdio_harness import serve  # noqa: E402
from reference_agents import vulnerable_agent  # noqa: E402

if __name__ == "__main__":
    serve(vulnerable_agent, server_name="aiasec-target-vulnerable")

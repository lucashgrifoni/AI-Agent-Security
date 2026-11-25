"""Well-behaved MCP Streamable HTTP target for aiasec.

The HTTP counterpart of examples/target-mcp-good: serves `good_agent` from
examples/reference_agents.py through the MCP HTTP harness template
(examples/harness/mcp_http_harness.py). No LLM is involved, so every bundled probe
passes against it on every run.

Serves POST /mcp on 127.0.0.1 only. Standard library only.
Run: python examples/target-mcp-http-good/server.py --port 8766
"""

from __future__ import annotations

import sys
from pathlib import Path

EXAMPLES = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(EXAMPLES), str(EXAMPLES / "harness")]

from mcp_http_harness import main  # noqa: E402
from reference_agents import good_agent  # noqa: E402

if __name__ == "__main__":
    main(good_agent, server_name="aiasec-target-mcp-http-good")

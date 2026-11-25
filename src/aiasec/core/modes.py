"""How a run observed the agent; every report states which mode produced it."""

from __future__ import annotations

# Every probe scored against one supplied observation; no attack was sent anywhere.
SINGLE_OBSERVATION_MODE = "single-observation"
# Each probe's inputs were sent to a live target over MCP stdio.
MCP_TARGET_MODE = "mcp-stdio-target"
# Each probe's inputs were POSTed to a live target over HTTP.
HTTP_TARGET_MODE = "http-target"
# Each probe's inputs were sent to a model API; tool calls were recorded, never run.
MODEL_API_TARGET_MODE = "model-api-target"

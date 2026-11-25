"""Pick and start the live target a config file describes.

The CLI reads a target config and needs three things from it: what aiasec is about to
do (shown when --execute is missing), how to start the target, and the observation
mode its report records. Each kind of target answers them here, so the CLI does not
branch on config types and a new kind of target is one entry in KINDS.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aiasec.core.modes import HTTP_TARGET_MODE, MCP_TARGET_MODE, MODEL_API_TARGET_MODE
from aiasec.core.target import AgentTarget
from aiasec.httptarget import HttpAgentTarget, HttpTargetConfig, HttpTargetError
from aiasec.mcp.config import McpStdioConfig
from aiasec.mcp.stdio import McpProtocolError, McpRemoteError
from aiasec.mcp.target import McpAgentTarget, McpTargetError
from aiasec.mcp.transport import McpTransportError
from aiasec.modeltarget import PROVIDERS, ModelAgentTarget, ModelTargetConfig

TargetConfig = McpStdioConfig | HttpTargetConfig | ModelTargetConfig

# What a started target may raise: the run stops with exit code 2.
TARGET_ERRORS: tuple[type[Exception], ...] = (
    HttpTargetError,
    McpProtocolError,
    McpRemoteError,
    McpTargetError,
    McpTransportError,
    OSError,
    ValueError,
)


@dataclass(frozen=True)
class TargetKind:
    """How one kind of target config is described, started and reported."""

    start: Callable[[Any], AgentTarget]
    mode: str
    # Printed once the target is up; `{label}` is the target's own label.
    announcement: str
    # What aiasec would do with this config, for the message that asks for --execute.
    action: Callable[[Any], str]


KINDS: dict[type, TargetKind] = {
    HttpTargetConfig: TargetKind(
        start=HttpAgentTarget.start,
        mode=HTTP_TARGET_MODE,
        announcement="Target is {label}.",
        action=lambda config: f"send probes to {config.url}",
    ),
    ModelTargetConfig: TargetKind(
        start=ModelAgentTarget.start,
        mode=MODEL_API_TARGET_MODE,
        announcement="Target is the {label}.",
        action=lambda config: (
            f"send probes to the {config.transport} model {config.model} at {config.endpoint}"
        ),
    ),
    McpStdioConfig: TargetKind(
        start=McpAgentTarget.start,
        mode=MCP_TARGET_MODE,
        announcement="Target speaks {label}.",
        action=lambda config: f"start {config.command!r}",
    ),
}


def load_target_config(path: Path) -> TargetConfig:
    """Read a target config; `transport` selects HTTP, a model API, or MCP stdio.

    Raises OSError or ValueError when the file cannot be read or parsed, and pydantic's
    ValidationError when a field is invalid.
    """

    raw = json.loads(path.read_text(encoding="utf-8"))
    transport = raw.get("transport") if isinstance(raw, dict) else None
    if transport == "http":
        return HttpTargetConfig.model_validate(raw)
    if isinstance(transport, str) and transport in PROVIDERS:
        return ModelTargetConfig.model_validate(raw)
    return McpStdioConfig.model_validate(raw)


def kind_of(config: TargetConfig) -> TargetKind:
    """The kind entry for a loaded config."""

    return KINDS[type(config)]

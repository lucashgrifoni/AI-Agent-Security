"""MCP stdio configuration models."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class McpStdioConfig(BaseModel):
    """Validated MCP stdio process configuration.

    The CLI currently validates this shape for dry-runs only. Process execution remains
    behind lower-level APIs so tests and default commands cannot spawn arbitrary servers.
    """

    model_config = ConfigDict(extra="forbid")

    transport: Literal["stdio"] = "stdio"
    command: list[str]
    cwd: Path | None = None
    env: dict[str, str] = Field(default_factory=dict)

    @field_validator("command")
    @classmethod
    def require_argv_command(cls, value: list[str]) -> list[str]:
        """Require an argv-style command instead of a shell string."""

        if not value:
            raise ValueError("command must contain at least one argument")
        if any(not part.strip() for part in value):
            raise ValueError("command arguments must not be empty")
        if any("\x00" in part for part in value):
            raise ValueError("command arguments must not contain null bytes")
        return value

    @field_validator("env")
    @classmethod
    def require_safe_env_shape(cls, value: dict[str, str]) -> dict[str, str]:
        """Reject malformed environment entries before any process execution is possible."""

        for key, item in value.items():
            if not key.strip():
                raise ValueError("env keys must not be empty")
            if "\x00" in key or "\x00" in item:
                raise ValueError("env keys and values must not contain null bytes")
        return value


def load_stdio_config(path: Path) -> McpStdioConfig:
    """Load a JSON MCP stdio configuration file."""

    try:
        raw_config = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"MCP stdio config is not valid JSON: {path}") from exc
    return McpStdioConfig.model_validate(raw_config)

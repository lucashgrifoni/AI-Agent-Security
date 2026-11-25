"""MCP target configuration models: a stdio process or a Streamable HTTP endpoint."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aiasec.httptarget import carries_credential, check_headers, check_http_url, is_loopback
from aiasec.mcp.http_transport import PROTOCOL_HEADERS


class McpTargetSettings(BaseModel):
    """What every MCP target config sets, whatever carries the messages."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    # The MCP tool that runs the agent under test on one probe (see docs/target-contract.md).
    agent_tool: str = Field(default="aiasec_agent", alias="agentTool", min_length=1)
    # Upper bound on waiting for any single message, so a hung target cannot hang CI.
    timeout_seconds: float = Field(default=30.0, alias="timeoutSeconds", gt=0, le=600)
    # auto probes with server/discover and falls back to initialize for a legacy server.
    # legacy skips the probe, for servers that ignore unknown methods instead of erroring.
    protocol: Literal["auto", "modern", "legacy"] = "auto"


class McpStdioConfig(McpTargetSettings):
    """Validated MCP stdio process configuration.

    `aiasec mcp tools list --config` only validates this shape. `aiasec run --target`
    starts the command, and only when the caller also passes `--execute`.
    """

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


class McpHttpConfig(McpTargetSettings):
    """Validated MCP Streamable HTTP endpoint configuration.

    `aiasec run --target` POSTs to the endpoint only when the caller passes `--execute`.
    """

    transport: Literal["mcp-http"]
    url: str
    # Values may reference environment variables as ${NAME}; keep secrets there, not here.
    headers: dict[str, str] = Field(default_factory=dict)

    @field_validator("url")
    @classmethod
    def require_http_url_with_host(cls, value: str) -> str:
        return check_http_url(value)

    @field_validator("headers")
    @classmethod
    def reject_malformed_or_protocol_headers(cls, value: dict[str, str]) -> dict[str, str]:
        """Reject headers that could split the request or that the transport sets."""

        taken = sorted(name for name in check_headers(value) if name.lower() in PROTOCOL_HEADERS)
        if taken:
            raise ValueError(f"aiasec sets itself the headers {taken}; remove them")
        return value

    @model_validator(mode="after")
    def keep_credentials_off_plain_http(self) -> McpHttpConfig:
        """A credential header may travel over http only to this machine."""

        parts = urlsplit(self.url)
        if parts.scheme == "http" and not is_loopback(parts.hostname or ""):
            sent = sorted(name for name, v in self.headers.items() if carries_credential(name, v))
            if sent:
                raise ValueError(
                    f"url uses http to another host; the credential headers {sent} would "
                    "travel unencrypted"
                )
        return self


def load_stdio_config(path: Path) -> McpStdioConfig:
    """Load a JSON MCP stdio configuration file."""

    try:
        raw_config = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"MCP stdio config is not valid JSON: {path}") from exc
    return McpStdioConfig.model_validate(raw_config)

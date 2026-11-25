"""Model API target configuration: provider, model, key variable, tools and limits."""

from __future__ import annotations

import re
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aiasec.httptarget import HttpTargetError, is_loopback

Provider = Literal["anthropic", "openai", "ollama"]
PROVIDERS: dict[str, tuple[str, str | None]] = {
    # provider: (default endpoint, default API key variable)
    "anthropic": ("https://api.anthropic.com/v1/messages", "ANTHROPIC_API_KEY"),
    "openai": ("https://api.openai.com/v1/chat/completions", "OPENAI_API_KEY"),
    "ollama": ("http://127.0.0.1:11434/api/chat", None),
}


TOOL_NAME = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
# Longest tool name each API accepts: Anthropic 128, OpenAI 64. Ollama documents no
# limit and keeps OpenAI's.
TOOL_NAME_LIMIT: dict[str, int] = {"anthropic": 128, "openai": 64, "ollama": 64}


class ModelTargetError(HttpTargetError):
    """Raised when a model API call fails or its reply cannot be read."""


class ModelTool(BaseModel):
    """A tool the model may call. aiasec records the calls and never runs them."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    name: str = Field(pattern=TOOL_NAME.pattern)
    description: str = ""
    input_schema: dict[str, Any] = Field(
        default_factory=lambda: {"type": "object"}, alias="inputSchema"
    )


class ModelTargetConfig(BaseModel):
    """Validated model API target configuration."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    transport: Provider
    model: str = Field(min_length=1)
    # Full endpoint URL; defaults to the provider's public API (Ollama: local server).
    url: str | None = None
    # Name of the environment variable holding the API key, never the key itself.
    api_key_env: str | None = Field(default=None, alias="apiKeyEnv")
    # Anthropic only: the workspace a key that may act in several workspaces runs in.
    # Such a key gets HTTP 400 without it; a key bound to one workspace needs none.
    workspace_id: str | None = Field(
        default=None, alias="workspaceId", pattern=r"^wrkspc_[A-Za-z0-9]+$"
    )
    system: str = ""
    tools: list[ModelTool] = Field(default_factory=list)
    # Thinking and reasoning tokens count toward it, and models such as Claude Sonnet 5.5
    # think by default, so the default leaves room beyond the reply itself.
    max_tokens: int = Field(default=16000, alias="maxTokens", gt=0, le=65536)
    # Not sent unless set: Claude models released after Opus 4.6 reject any value but
    # 1.0, and some OpenAI reasoning models accept only their default. Set 0 for a model
    # that accepts it, to reduce variation between runs.
    temperature: float | None = Field(default=None, ge=0, le=2)
    timeout_seconds: float = Field(default=60.0, alias="timeoutSeconds", gt=0, le=600)
    # Extra attempts after a rate limit or a server error; 0 sends each request once.
    max_retries: int = Field(default=2, alias="maxRetries", ge=0, le=5)

    @field_validator("url")
    @classmethod
    def require_http_url_with_host(cls, value: str | None) -> str | None:
        if value is not None:
            parts = urlsplit(value)
            if parts.scheme not in {"http", "https"} or not parts.hostname:
                raise ValueError("url must be an http or https URL with a host")
        return value

    @model_validator(mode="after")
    def keep_the_key_off_plain_http(self) -> ModelTargetConfig:
        """An API key may travel over http only to this machine."""

        parts = urlsplit(self.endpoint)
        if self.key_variable and parts.scheme == "http" and not is_loopback(parts.hostname or ""):
            raise ValueError("url uses http to another host; the API key would travel unencrypted")
        return self

    @model_validator(mode="after")
    def keep_the_workspace_to_anthropic(self) -> ModelTargetConfig:
        if self.workspace_id is not None and self.transport != "anthropic":
            raise ValueError("workspaceId applies only to the anthropic transport")
        return self

    @model_validator(mode="after")
    def check_tool_names(self) -> ModelTargetConfig:
        """Each name fits the provider and is used once, so no tool hides another."""

        limit = TOOL_NAME_LIMIT[self.transport]
        seen: set[str] = set()
        for index, tool in enumerate(self.tools):
            if len(tool.name) > limit:
                raise ValueError(
                    f"tools[{index}].name is longer than the {limit} characters "
                    f"the {self.transport} API accepts"
                )
            if tool.name in seen:
                raise ValueError(f"tools[{index}].name repeats the name of an earlier tool")
            seen.add(tool.name)
        return self

    @property
    def endpoint(self) -> str:
        return self.url or PROVIDERS[self.transport][0]

    @property
    def key_variable(self) -> str | None:
        """The key's variable: the configured one, none for an explicit null, else the default."""

        if "api_key_env" in self.model_fields_set:
            return self.api_key_env
        return PROVIDERS[self.transport][1]

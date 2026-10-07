"""Send probes straight to a model API: Anthropic, OpenAI (or a compatible server), Ollama.

The target config names the model, an optional system prompt and the tools the model
may call. For each probe turn aiasec sends the conversation so far as one request. The
model's text is the reply; the tool calls it asks for are recorded with their arguments
and never executed, so the turn ends there.

Probe input roles reach the model like this:

- `system`: appended to the config's system prompt;
- `user` and `assistant`: messages;
- `rag_corpus`: a user message holding the retrieved documents;
- `tool_output`: a call the model is shown to have made, followed by its result. The
  tool is named after a `tool://<name>/...` document path (otherwise `read_document`)
  and declared to the model if the config does not declare it;
- `tool_catalog`: tool definitions the model sees, named after the last segment of the
  document path, with the document's text (including the injected part) as description.

An API key is read from the environment variable the config names, and is only sent
over https or to a loopback address. Requests use the same deadline, no-redirect and
size rules as HTTP targets (aiasec.httptarget.post_json).
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from types import TracebackType
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aiasec.core.conversation import drive_conversation
from aiasec.core.evaluator.rules import TargetObservation, ToolCall
from aiasec.core.probe import Probe
from aiasec.httptarget import HttpTargetError, connection_for, post_json, request_path

Provider = Literal["anthropic", "openai", "ollama"]
PROVIDERS: dict[str, tuple[str, str | None]] = {
    # provider: (default endpoint, default API key variable)
    "anthropic": ("https://api.anthropic.com/v1/messages", "ANTHROPIC_API_KEY"),
    "openai": ("https://api.openai.com/v1/chat/completions", "OPENAI_API_KEY"),
    "ollama": ("http://127.0.0.1:11434/api/chat", None),
}
ANTHROPIC_VERSION = "2023-06-01"
TOOL_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
DEFAULT_TOOL = "read_document"


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
    system: str = ""
    tools: list[ModelTool] = Field(default_factory=list)
    max_tokens: int = Field(default=1024, alias="maxTokens", gt=0, le=65536)
    # Not sent unless set: Claude models released after Opus 4.6 reject any value but
    # 1.0, and some OpenAI reasoning models accept only their default. Set 0 for a model
    # that accepts it, to reduce variation between runs.
    temperature: float | None = Field(default=None, ge=0, le=2)
    timeout_seconds: float = Field(default=60.0, alias="timeoutSeconds", gt=0, le=600)

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
        if self.key_variable and parts.scheme == "http" and not _is_loopback(parts.hostname or ""):
            raise ValueError("url uses http to another host; the API key would travel unencrypted")
        return self

    @property
    def endpoint(self) -> str:
        return self.url or PROVIDERS[self.transport][0]

    @property
    def key_variable(self) -> str | None:
        return self.api_key_env or PROVIDERS[self.transport][1]


class ModelAgentTarget:
    """A model reached through its API, one request per probe turn."""

    def __init__(self, config: ModelTargetConfig, api_key: str | None) -> None:
        self._config = config
        self._api_key = api_key

    @classmethod
    def start(cls, config: ModelTargetConfig) -> ModelAgentTarget:
        """Read the API key before any request is sent."""

        variable = config.key_variable
        if variable is None:
            return cls(config, None)
        # A key read from a file often ends with a newline; anything else that is not
        # printable would make http.client fail with the key in its message.
        key = (os.environ.get(variable) or "").strip()
        if not key:
            raise ModelTargetError(f"The API key variable {variable} is not set")
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in key):
            raise ModelTargetError(f"The API key in {variable} contains a control character")
        return cls(config, key)

    @property
    def label(self) -> str:
        host = urlsplit(self._config.endpoint).netloc
        return f"{self._config.transport} model {self._config.model} at {host}"

    def observe(self, probe: Probe) -> TargetObservation:
        """Send a probe to the model, one request per turn, and return what it did."""

        return drive_conversation(probe, lambda arguments: self._send(arguments["inputs"]))

    def close(self) -> None:
        """Nothing to release; each request uses its own connection."""

    def __enter__(self) -> ModelAgentTarget:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def _send(self, inputs: list[dict[str, Any]]) -> tuple[str, list[ToolCall]]:
        transcript = build_transcript(inputs, self._config)
        provider = self._config.transport
        body = RENDERERS[provider](transcript, self._config)
        endpoint = self._config.endpoint
        status, payload = post_json(
            connection_for(endpoint, self._config.timeout_seconds),
            request_path(endpoint),
            body,
            self._headers(),
            self._config.timeout_seconds,
        )
        if status != 200:
            reason = _reason(payload, self._api_key)
            raise ModelTargetError(f"The {provider} API answered HTTP {status}{reason}")
        try:
            reply = json.loads(payload)
            text, calls, cut = PARSERS[provider](reply)
        except (
            ValueError, RecursionError, KeyError, IndexError, TypeError, AttributeError
        ) as exc:
            raise ModelTargetError(f"The {provider} API reply could not be read") from exc
        # The part past a cut could hold what a probe looks for; scoring the rest would
        # pass a probe on half an answer.
        if cut == "context":
            raise ModelTargetError(
                f"The {provider} reply was cut because the conversation filled the model's "
                "context window; use a model with a larger one"
            )
        if cut:
            raise ModelTargetError(
                f"The {provider} reply was cut at maxTokens ({self._config.max_tokens}); "
                "raise maxTokens in the target config so the whole reply is scored"
            )
        return text, calls

    def _headers(self) -> dict[str, str]:
        if self._config.transport == "anthropic":
            headers = {"anthropic-version": ANTHROPIC_VERSION}
            if self._api_key:
                headers["x-api-key"] = self._api_key
            return headers
        return {"Authorization": f"Bearer {self._api_key}"} if self._api_key else {}


class Transcript(BaseModel):
    """A probe conversation in provider-neutral form."""

    system: str
    tools: list[ModelTool]
    # Entries: {"kind": "user"|"assistant", "text"} | {"kind": "call", "id", "name"}
    #          | {"kind": "result", "id", "name", "text"}
    entries: list[dict[str, str]]


def build_transcript(inputs: list[dict[str, Any]], config: ModelTargetConfig) -> Transcript:
    """Map probe inputs to messages, tool calls with results, and tool definitions."""

    system = [config.system] if config.system else []
    tools = {tool.name: tool for tool in config.tools}
    entries: list[dict[str, str]] = []
    for item in inputs:
        role = item.get("role")
        content = item.get("content") or ""
        documents = item.get("documents") or []
        if role == "system":
            system.append(content)
        elif role in ("user", "assistant"):
            text = "\n\n".join(filter(None, [content, _documents_text(documents)]))
            # An earlier empty reply (a refusal the API signalled) has nothing to replay,
            # and providers reject an empty message.
            if text or role == "user":
                entries.append({"kind": role, "text": text})
        elif role == "rag_corpus":
            text = "Retrieved documents:\n\n" + _documents_text(documents)
            entries.append({"kind": "user", "text": text})
        elif role == "tool_output":
            name = _tool_name_from_path(documents)
            tools.setdefault(name, ModelTool(name=name, description="Returns requested content."))
            call_id = f"aiasec_call_{len(entries) + 1}"
            text = "\n\n".join(filter(None, [content, _documents_text(documents)]))
            entries.append({"kind": "call", "id": call_id, "name": name})
            entries.append({"kind": "result", "id": call_id, "name": name, "text": text})
        elif role == "tool_catalog":
            for document in documents:
                name = _last_path_segment(document.get("path") or "")
                description = " ".join(
                    filter(None, [document.get("content"), document.get("injected")])
                )
                tools[name] = ModelTool(name=name, description=description)
        else:
            # A role with no route would never reach the model, and its probe would pass.
            raise ModelTargetError(f"Probe input role {role!r} has no route to a model API")
    return Transcript(system="\n\n".join(system), tools=list(tools.values()), entries=entries)


def _documents_text(documents: list[dict[str, Any]]) -> str:
    parts = []
    for document in documents:
        body = "\n".join(filter(None, [document.get("content"), document.get("injected")]))
        parts.append(f"[{document.get('path') or 'document'}]\n{body}")
    return "\n\n".join(parts)


def _tool_name_from_path(documents: list[dict[str, Any]]) -> str:
    for document in documents:
        parts = urlsplit(document.get("path") or "")
        if parts.scheme == "tool" and TOOL_NAME.match(parts.netloc):
            return parts.netloc
    return DEFAULT_TOOL


def _last_path_segment(path: str) -> str:
    segment = path.rstrip("/").rsplit("/", 1)[-1]
    return segment if TOOL_NAME.match(segment) else DEFAULT_TOOL


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _reason(payload: bytes, secret: str | None) -> str:
    """The provider's error message, if it gave one, with the key redacted, shortened."""

    try:
        error = json.loads(payload).get("error")
    except (ValueError, RecursionError, AttributeError):
        return ""
    message = error.get("message") if isinstance(error, dict) else error
    if not isinstance(message, str) or not message:
        return ""
    if secret:  # an error message may quote the key back; redact before cutting it
        message = message.replace(secret, "[redacted]")
    return f": {message[:200]}"


def _observed(text: Any, calls: list[ToolCall], *, refused: bool) -> tuple[str, list[ToolCall]]:
    """Check what a reply carried before it is scored.

    The text must be a string, and a reply with no text and no tool call is a contract
    error, not a pass: it would pass every pattern check without the model having
    answered. Only a refusal the API itself signals counts as an empty answer.
    """

    if text is None:
        text = ""
    if not isinstance(text, str):
        raise ValueError("the reply text is not a string")
    if not text and not calls and not refused:
        raise ValueError("the reply has no text and no tool call")
    return text, calls


def _call(name: Any, arguments: Any) -> ToolCall:
    """A tool call the model asked for; a blank name would match no check."""

    if not isinstance(name, str) or not name.strip():
        raise ValueError("a tool call has no name")
    return ToolCall(name=name, arguments=arguments)


# Anthropic Messages API: https://platform.claude.com/docs/en/api/messages
def _anthropic_body(transcript: Transcript, config: ModelTargetConfig) -> dict[str, Any]:
    messages: list[dict[str, Any]] = []
    for entry in transcript.entries:
        if entry["kind"] in ("user", "assistant"):
            messages.append({"role": entry["kind"], "content": entry["text"]})
        elif entry["kind"] == "call":
            block = {"type": "tool_use", "id": entry["id"], "name": entry["name"], "input": {}}
            messages.append({"role": "assistant", "content": [block]})
        else:
            block = {"type": "tool_result", "tool_use_id": entry["id"], "content": entry["text"]}
            messages.append({"role": "user", "content": [block]})
    body: dict[str, Any] = {
        "model": config.model,
        "max_tokens": config.max_tokens,
        "messages": messages,
    }
    if config.temperature is not None:
        body["temperature"] = config.temperature
    if transcript.system:
        body["system"] = transcript.system
    if transcript.tools:
        body["tools"] = [
            {"name": tool.name, "description": tool.description, "input_schema": tool.input_schema}
            for tool in transcript.tools
        ]
    return body


# Why a reply stopped early: "length" (maxTokens), "context" (context window), or None.
Cut = str | None


def _anthropic_reply(reply: dict[str, Any]) -> tuple[str, list[ToolCall], Cut]:
    texts, calls = [], []
    for block in reply["content"]:
        if block["type"] == "text":
            texts.append(block["text"])
        elif block["type"] == "tool_use":
            calls.append(_call(block["name"], block["input"]))
    text, calls = _observed(
        "\n".join(texts), calls, refused=reply.get("stop_reason") == "refusal"
    )
    stop = reply.get("stop_reason")
    cut = {"max_tokens": "length", "model_context_window_exceeded": "context"}.get(stop)
    return text, calls, cut


def _openai_tools(transcript: Transcript) -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.input_schema,
            },
        }
        for tool in transcript.tools
    ]


def _chat_messages(transcript: Transcript, *, ollama: bool) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    if transcript.system:
        messages.append({"role": "system", "content": transcript.system})
    for entry in transcript.entries:
        if entry["kind"] in ("user", "assistant"):
            messages.append({"role": entry["kind"], "content": entry["text"]})
        elif entry["kind"] == "call" and ollama:
            call = {"function": {"name": entry["name"], "arguments": {}}}
            messages.append({"role": "assistant", "content": "", "tool_calls": [call]})
        elif entry["kind"] == "call":
            function = {"name": entry["name"], "arguments": "{}"}
            call = {"id": entry["id"], "type": "function", "function": function}
            messages.append({"role": "assistant", "content": None, "tool_calls": [call]})
        elif ollama:
            messages.append({"role": "tool", "tool_name": entry["name"], "content": entry["text"]})
        else:
            messages.append({"role": "tool", "tool_call_id": entry["id"], "content": entry["text"]})
    return messages


# OpenAI Chat Completions API (and servers that implement it).
def _openai_body(transcript: Transcript, config: ModelTargetConfig) -> dict[str, Any]:
    body: dict[str, Any] = {
        "model": config.model,
        "messages": _chat_messages(transcript, ollama=False),
        "max_completion_tokens": config.max_tokens,
    }
    if config.temperature is not None:
        body["temperature"] = config.temperature
    if transcript.tools:
        body["tools"] = _openai_tools(transcript)
    return body


def _openai_reply(reply: dict[str, Any]) -> tuple[str, list[ToolCall], Cut]:
    choice = reply["choices"][0]
    message = choice["message"]
    calls = []
    for call in message.get("tool_calls") or []:
        if call["type"] != "function":
            raise ValueError("unsupported tool call type")
        function = call["function"]
        # The arguments are a JSON string, possibly invalid; the evaluator handles both.
        calls.append(_call(function["name"], function["arguments"]))
    # A refusal arrives as message.refusal, with no content; it is the model's reply.
    refusal = message.get("refusal")
    text = refusal if isinstance(refusal, str) and refusal else message.get("content")
    refused = choice.get("finish_reason") == "content_filter"
    cut = "length" if choice.get("finish_reason") == "length" else None
    return *_observed(text, calls, refused=refused), cut


# Ollama /api/chat: https://docs.ollama.com/api/chat
def _ollama_body(transcript: Transcript, config: ModelTargetConfig) -> dict[str, Any]:
    options: dict[str, Any] = {"num_predict": config.max_tokens}
    if config.temperature is not None:
        options["temperature"] = config.temperature
    body: dict[str, Any] = {
        "model": config.model,
        "messages": _chat_messages(transcript, ollama=True),
        "stream": False,
        "options": options,
    }
    if transcript.tools:
        body["tools"] = _openai_tools(transcript)
    return body


def _ollama_reply(reply: dict[str, Any]) -> tuple[str, list[ToolCall], Cut]:
    message = reply["message"]
    calls = [
        _call(call["function"]["name"], call["function"].get("arguments"))
        for call in message.get("tool_calls") or []
    ]
    cut = "length" if reply.get("done_reason") == "length" else None
    return *_observed(message.get("content"), calls, refused=False), cut


RENDERERS = {"anthropic": _anthropic_body, "openai": _openai_body, "ollama": _ollama_body}
PARSERS = {"anthropic": _anthropic_reply, "openai": _openai_reply, "ollama": _ollama_reply}

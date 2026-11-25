"""Turn a probe into the provider-neutral conversation sent to a model API."""

from __future__ import annotations

import json
from collections.abc import Container
from typing import Any, NamedTuple
from urllib.parse import urlsplit

from pydantic import BaseModel

from aiasec.core.evaluator.rules import ToolCall
from aiasec.modeltarget.config import (
    TOOL_NAME,
    TOOL_NAME_LIMIT,
    ModelTargetConfig,
    ModelTargetError,
    ModelTool,
)

DEFAULT_TOOL = "read_document"
# The result replayed for a tool call the model made on an earlier turn.
NOT_RUN = "aiasec did not run this tool: it records tool calls without running them."


class Transcript(BaseModel):
    """A probe conversation in provider-neutral form."""

    system: str
    tools: list[ModelTool]
    # Entries: {"kind": "user"|"assistant", "text"}
    #          | {"kind": "blocks", "blocks"} (an Anthropic reply's content, as returned)
    #          | {"kind": "call", "id", "name", "arguments", "joins"}
    #            (joins: the call continues the model reply in the message before it)
    #          | {"kind": "result", "id", "name", "text"}
    entries: list[dict[str, Any]]


class EarlierReply(NamedTuple):
    """A model reply replayed on later turns.

    blocks holds an Anthropic reply's content blocks exactly as returned, thinking
    blocks included; it is None for the other providers.
    """

    calls: list[ToolCall]
    blocks: list[dict[str, Any]] | None


def build_transcript(
    inputs: list[dict[str, Any]],
    config: ModelTargetConfig,
    earlier: dict[int, EarlierReply] | None = None,
) -> Transcript:
    """Map probe inputs to messages, tool calls with results, and tool definitions.

    earlier maps the position in inputs of each earlier model reply to that reply; its
    tool calls follow it, each with a result saying the tool was not run. A
    probe-authored assistant input has no entry.
    """

    system = [config.system] if config.system else []
    tools = {tool.name: tool for tool in config.tools}
    entries: list[dict[str, Any]] = []
    for index, item in enumerate(inputs):
        role = item.get("role")
        content = item.get("content") or ""
        documents = item.get("documents") or []
        if role == "system":
            system.append(content)
        elif role in ("user", "assistant"):
            text = "\n\n".join(filter(None, [content, _documents_text(documents)]))
            reply = (earlier or {}).get(index) if role == "assistant" else None
            if reply is not None and reply.blocks is not None:
                # Anthropic requires a reply's thinking blocks back, complete and in
                # order, whenever a tool result follows; the whole reply goes back.
                if reply.blocks:
                    entries.append({"kind": "blocks", "blocks": reply.blocks})
                for block in reply.blocks:
                    if block["type"] == "tool_use":
                        tools.setdefault(block["name"], ModelTool(name=block["name"]))
                        entries.append(
                            {"kind": "result", "id": block["id"], "name": block["name"],
                             "text": NOT_RUN}
                        )  # fmt: skip
                continue
            # An earlier blank reply (a refusal the API signalled, or text beside tool
            # calls) has nothing to replay, and providers reject a blank message.
            if text.strip() or role == "user":
                entries.append({"kind": role, "text": text})
            if role == "assistant":
                calls = reply.calls if reply else []
                ids = [f"aiasec_reply{index}_call{n}" for n in range(1, len(calls) + 1)]
                # A reply's calls stay together, as one response, then all their results.
                # They join the reply's own text when it has some, never a message the
                # probe wrote before it.
                for number, (call_id, call) in enumerate(zip(ids, calls, strict=True)):
                    tools.setdefault(call.name, ModelTool(name=call.name))
                    entries.append(
                        {"kind": "call", "id": call_id, "name": call.name,
                         "arguments": call.arguments, "joins": number > 0 or bool(text.strip())}
                    )  # fmt: skip
                for call_id, call in zip(ids, calls, strict=True):
                    entries.append(
                        {"kind": "result", "id": call_id, "name": call.name, "text": NOT_RUN}
                    )
        elif role == "rag_corpus":
            text = "Retrieved documents:\n\n" + _documents_text(documents)
            entries.append({"kind": "user", "text": text})
        elif role == "tool_output":
            name = _tool_name_from_path(documents, config.transport)
            tools.setdefault(name, ModelTool(name=name, description="Returns requested content."))
            call_id = f"aiasec_call_{len(entries) + 1}"
            text = "\n\n".join(filter(None, [content, _documents_text(documents)]))
            entries.append({"kind": "call", "id": call_id, "name": name})
            entries.append({"kind": "result", "id": call_id, "name": name, "text": text})
        elif role == "tool_catalog":
            for document in documents:
                # Each document becomes its own tool and replaces no tool already
                # declared, so the configured tools reach the model as they are.
                segment = _last_path_segment(document.get("path") or "", config.transport)
                name = _unused(segment, tools, config.transport)
                description = " ".join(
                    filter(None, [document.get("content"), document.get("injected")])
                )
                tools[name] = ModelTool(name=name, description=description)
        else:
            # A role with no route would never reach the model, and its probe would pass.
            raise ModelTargetError(f"Probe input role {role!r} has no route to a model API")
    return Transcript(system="\n\n".join(system), tools=list(tools.values()), entries=entries)


def _arguments_object(arguments: Any) -> dict[str, Any]:
    """Tool call arguments as the object a tool_use block needs."""

    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except (ValueError, RecursionError):
            return {}
    return arguments if isinstance(arguments, dict) else {}


def _documents_text(documents: list[dict[str, Any]]) -> str:
    parts = []
    for document in documents:
        body = "\n".join(filter(None, [document.get("content"), document.get("injected")]))
        parts.append(f"[{document.get('path') or 'document'}]\n{body}")
    return "\n\n".join(parts)


def _fits(name: str, provider: str) -> bool:
    """Whether the provider's API accepts this tool name."""

    # fullmatch: $ alone would also accept a name ending in a newline.
    return bool(TOOL_NAME.fullmatch(name)) and len(name) <= TOOL_NAME_LIMIT[provider]


def _tool_name_from_path(documents: list[dict[str, Any]], provider: str) -> str:
    for document in documents:
        parts = urlsplit(document.get("path") or "")
        if parts.scheme == "tool" and _fits(parts.netloc, provider):
            return parts.netloc
    return DEFAULT_TOOL


def _last_path_segment(path: str, provider: str) -> str:
    segment = path.rstrip("/").rsplit("/", 1)[-1]
    return segment if _fits(segment, provider) else DEFAULT_TOOL


def _unused(name: str, taken: Container[str], provider: str) -> str:
    """The name, or the name with the first free _2, _3... suffix within the limit."""

    candidate, number = name, 1
    while candidate in taken:
        number += 1
        suffix = f"_{number}"
        candidate = name[: TOOL_NAME_LIMIT[provider] - len(suffix)] + suffix
    return candidate

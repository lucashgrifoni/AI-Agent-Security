"""Each provider's request body and reply format, and the checks on a reply."""

from __future__ import annotations

import json
from typing import Any

from aiasec.core.evaluator.rules import ToolCall
from aiasec.modeltarget.config import (
    ModelTargetConfig,
)
from aiasec.modeltarget.transcript import (
    Transcript,
    _arguments_object,
    _fits,
)

ANTHROPIC_VERSION = "2023-06-01"


def _observed(text: Any, calls: list[ToolCall], *, refused: bool) -> tuple[str, list[ToolCall]]:
    """Check what a reply carried before it is scored.

    The text must be a string, and a reply with only blank text and no tool call is a
    contract error, not a pass: it would pass every pattern check without the model
    having answered. Only a refusal the API itself signals counts as an empty answer.
    """

    if text is None:
        text = ""
    if not isinstance(text, str):
        raise ValueError("the reply text is not a string")
    if not text.strip() and not calls and not refused:
        raise ValueError("the reply has no text and no tool call")
    return text, calls


def _replay_blocks(reply: dict[str, Any]) -> list[dict[str, Any]]:
    """An Anthropic reply's content blocks to send back unchanged, thinking included.

    Blank text blocks are left out: the API rejects them, and they carry nothing.
    """

    return [block for block in reply["content"] if block["type"] != "text" or block["text"].strip()]


def _call(name: Any, arguments: Any, provider: str) -> ToolCall:
    """A tool call the model asked for, under a name the provider's API accepts.

    Any other name (blank, padded, too long) was never declared, and it would slip past a
    check for the tool the model meant.
    """

    if not isinstance(name, str) or not _fits(name, provider):
        raise ValueError("a tool call has a name the API does not accept")
    return ToolCall(name=name, arguments=arguments)


# Anthropic Messages API: https://platform.claude.com/docs/en/api/messages
def _anthropic_body(transcript: Transcript, config: ModelTargetConfig) -> dict[str, Any]:
    messages: list[dict[str, Any]] = []
    for entry in transcript.entries:
        if entry["kind"] in ("user", "assistant"):
            messages.append({"role": entry["kind"], "content": entry["text"]})
        elif entry["kind"] == "blocks":
            messages.append({"role": "assistant", "content": entry["blocks"]})
        elif entry["kind"] == "call":
            block = {
                "type": "tool_use",
                "id": entry["id"],
                "name": entry["name"],
                "input": _arguments_object(entry.get("arguments")),
            }
            # A call of the reply before it joins that message: one response, one message.
            if entry.get("joins") and messages and messages[-1]["role"] == "assistant":
                previous = messages[-1]
                if isinstance(previous["content"], str):
                    previous["content"] = [{"type": "text", "text": previous["content"]}]
                previous["content"].append(block)
            else:
                messages.append({"role": "assistant", "content": [block]})
        else:
            block = {"type": "tool_result", "tool_use_id": entry["id"], "content": entry["text"]}
            # The results of one response go back together in one user message.
            if (
                messages
                and messages[-1]["role"] == "user"
                and isinstance(messages[-1]["content"], list)
            ):
                messages[-1]["content"].append(block)
            else:
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


# Why a reply is not whole: "length" (maxTokens), "context" (context window),
# "unfinished" (no stop reason that marks a complete reply), or None.
Cut = str | None

# Stop reasons of a complete reply (None) and of a cut one. Any other value, or none,
# means the reply is not finished: Anthropic sends one in every reply, and pause_turn
# asks for the turn to be continued.
ANTHROPIC_STOPS: dict[str, Cut] = {
    "end_turn": None,
    "stop_sequence": None,
    "tool_use": None,
    "refusal": None,
    "max_tokens": "length",
    "model_context_window_exceeded": "context",
}
OPENAI_STOPS: dict[str, Cut] = {
    "stop": None,
    "tool_calls": None,
    "function_call": None,
    "content_filter": None,
    "length": "length",
}


def _anthropic_reply(reply: dict[str, Any]) -> tuple[str, list[ToolCall], Cut]:
    texts, calls = [], []
    for block in reply["content"]:
        if block["type"] == "text":
            texts.append(block["text"])
        elif block["type"] == "tool_use":
            # The id goes back with the call's result on later turns.
            if not isinstance(block.get("id"), str) or not block["id"].strip():
                raise ValueError("a tool call has no id")
            calls.append(_call(block["name"], block["input"], "anthropic"))
    if reply.get("stop_reason") == "tool_use" and not calls:
        raise ValueError("the reply stopped for a tool call but carries none")
    text, calls = _observed("\n".join(texts), calls, refused=reply.get("stop_reason") == "refusal")
    return text, calls, ANTHROPIC_STOPS.get(str(reply.get("stop_reason")), "unfinished")


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
        elif entry["kind"] == "call":
            call: dict[str, Any]
            if ollama:
                arguments = _arguments_object(entry.get("arguments"))
                call = {"function": {"name": entry["name"], "arguments": arguments}}
            else:
                raw = entry.get("arguments")
                wire = raw if isinstance(raw, str) else json.dumps(_arguments_object(raw))
                function = {"name": entry["name"], "arguments": wire}
                call = {"id": entry["id"], "type": "function", "function": function}
            # A call of the reply before it joins that message: one response, one message.
            if entry.get("joins") and messages and messages[-1]["role"] == "assistant":
                messages[-1].setdefault("tool_calls", []).append(call)
            else:
                content = "" if ollama else None
                messages.append({"role": "assistant", "content": content, "tool_calls": [call]})
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
        # Some compatible servers leave the type out; any other type is not a function.
        if call.get("type", "function") != "function":
            raise ValueError("unsupported tool call type")
        function = call["function"]
        # The arguments are a JSON string, possibly invalid; the evaluator handles both.
        calls.append(_call(function["name"], function["arguments"], "openai"))
    # The deprecated single call, announced by finish_reason "function_call".
    legacy = message.get("function_call")
    if legacy is not None:
        calls.append(_call(legacy["name"], legacy.get("arguments"), "openai"))
    reason = choice.get("finish_reason")
    if reason in ("tool_calls", "function_call") and not calls:
        raise ValueError("the reply stopped for a tool call but carries none")
    # A refusal arrives as message.refusal, with no content; it is the model's reply.
    refusal = message.get("refusal")
    text = refusal if isinstance(refusal, str) and refusal else message.get("content")
    observed = _observed(text, calls, refused=reason == "content_filter")
    return *observed, OPENAI_STOPS.get(reason, "unfinished")


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
        _call(call["function"]["name"], call["function"].get("arguments"), "ollama")
        for call in message.get("tool_calls") or []
    ]
    # A non-streamed reply always says done; anything else is a part of a reply.
    cut: Cut
    if reply.get("done") is not True:
        cut = "unfinished"
    else:
        cut = "length" if reply.get("done_reason") == "length" else None
    return *_observed(message.get("content"), calls, refused=False), cut


RENDERERS = {"anthropic": _anthropic_body, "openai": _openai_body, "ollama": _ollama_body}
PARSERS = {"anthropic": _anthropic_reply, "openai": _openai_reply, "ollama": _ollama_reply}

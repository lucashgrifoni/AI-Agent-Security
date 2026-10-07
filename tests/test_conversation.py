"""Multi-turn probes: one call per user turn, with the conversation so far."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aiasec.core.conversation import drive_conversation, split_turns
from aiasec.core.probe import ProbeInput, load_probe_file

CRESCENDO = Path("src/aiasec/probes/jailbreak/crescendo-001.yaml")
RAG = Path("src/aiasec/probes/indirect-injection/rag-doc-poison-001.yaml")


def _roles(turns: list[list[ProbeInput]]) -> list[list[str]]:
    return [[item.role for item in turn] for turn in turns]


def test_each_user_input_opens_a_turn_and_context_stays_with_its_turn() -> None:
    inputs = [
        ProbeInput(role="rag_corpus", content="doc before any user turn"),
        ProbeInput(role="user", content="first"),
        ProbeInput(role="tool_output", content="tool result"),
        ProbeInput(role="user", content="second"),
    ]

    assert _roles(split_turns(inputs)) == [["rag_corpus", "user", "tool_output"], ["user"]]


def test_a_single_turn_probe_is_one_call() -> None:
    probe = load_probe_file(RAG)
    calls: list[dict[str, Any]] = []

    observation = drive_conversation(probe, lambda args: calls.append(args) or ("ok", ["search"]))

    assert len(calls) == 1
    assert calls[0]["turn"] == 1 and calls[0]["turns"] == 1
    assert [item["role"] for item in calls[0]["inputs"]] == ["user", "rag_corpus"]
    assert observation.assistant_final_response == "ok"
    assert observation.tools_called == ["search"]


def test_a_multi_turn_probe_sends_each_turn_with_the_replies_so_far() -> None:
    probe = load_probe_file(CRESCENDO)
    calls: list[dict[str, Any]] = []
    replies = iter([("reply one", []), ("reply two", ["lookup"]), ("final reply", ["send"])])

    def send(arguments: dict[str, Any]) -> tuple[str, list[str]]:
        calls.append(arguments)
        return next(replies)

    observation = drive_conversation(probe, send)

    assert [call["turn"] for call in calls] == [1, 2, 3]
    assert all(call["turns"] == 3 for call in calls)
    assert [item["role"] for item in calls[2]["inputs"]] == [
        "user",
        "assistant",
        "user",
        "assistant",
        "user",
    ]
    assert calls[2]["inputs"][1]["content"] == "reply one"
    assert calls[2]["inputs"][3]["content"] == "reply two"
    assert observation.assistant_final_response == "final reply"
    assert observation.tools_called == ["lookup", "send"]

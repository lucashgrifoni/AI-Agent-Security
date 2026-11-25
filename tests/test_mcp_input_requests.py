"""MCP 2026-07-28 multi round-trip requests: a tools/call answered with input_required.

The server asks the client for input inside the result; the client sends tools/call
again with its answers. aiasec answers only what it can answer without acting for the
server: it declines every elicitation, reports no roots, and never samples a model.
"""

from __future__ import annotations

from typing import Any

import pytest

from aiasec.mcp.stdio import (
    MAX_INPUT_ROUND_TRIPS,
    MODERN_PROTOCOL_VERSION,
    McpProtocolError,
    McpStdioAdapter,
)
from aiasec.mcp.transport import JsonObject

COMPLETE = {"resultType": "complete", "content": [{"type": "text", "text": "done"}]}
ELICIT = {"method": "elicitation/create", "params": {"message": "Confirm?", "requestedSchema": {}}}


class ScriptedTransport:
    def __init__(self, results: list[JsonObject]) -> None:
        self.results = list(results)
        self.sent: list[JsonObject] = []

    def send(self, message: JsonObject, timeout: float | None = None) -> None:
        self.sent.append(message)

    def receive(self, timeout: float | None = None) -> JsonObject:
        request_id = self.sent[-1]["id"]
        return {"jsonrpc": "2.0", "id": request_id, "result": self.results.pop(0)}

    def close(self) -> None:
        pass


def _modern(results: list[JsonObject]) -> tuple[McpStdioAdapter, ScriptedTransport]:
    discover = {"resultType": "complete", "supportedVersions": [MODERN_PROTOCOL_VERSION]}
    transport = ScriptedTransport([discover, *results])
    adapter = McpStdioAdapter(transport)
    adapter.connect()
    return adapter, transport


def _input_required(**fields: Any) -> JsonObject:
    return {"resultType": "input_required", **fields}


def _calls(transport: ScriptedTransport) -> list[JsonObject]:
    return [message for message in transport.sent if message["method"] == "tools/call"]


def test_an_elicitation_is_declined_and_the_call_completes() -> None:
    adapter, transport = _modern(
        [_input_required(inputRequests={"confirm": ELICIT}, requestState="opaque-1"), COMPLETE]
    )

    result = adapter.call_tool("aiasec_agent", {"inputs": []})

    assert result == COMPLETE
    first, second = _calls(transport)
    assert second["id"] != first["id"]
    assert second["params"]["name"] == "aiasec_agent"
    assert second["params"]["arguments"] == {"inputs": []}
    assert second["params"]["inputResponses"] == {"confirm": {"action": "decline"}}
    assert second["params"]["requestState"] == "opaque-1"
    assert "_meta" in second["params"]


def test_roots_are_reported_empty_and_each_key_gets_its_answer() -> None:
    requests = {"where": {"method": "roots/list"}, "ok": ELICIT}
    adapter, transport = _modern([_input_required(inputRequests=requests), COMPLETE])

    adapter.call_tool("aiasec_agent", {})

    responses = _calls(transport)[1]["params"]["inputResponses"]
    assert responses == {"where": {"roots": []}, "ok": {"action": "decline"}}
    assert "requestState" not in _calls(transport)[1]["params"]


def test_request_state_is_echoed_verbatim_on_each_round() -> None:
    state = {"step": 2, "nested": ["a", {"b": None}]}
    adapter, transport = _modern(
        [
            _input_required(requestState="first"),
            _input_required(requestState=state, inputRequests={"x": ELICIT}),
            COMPLETE,
        ]
    )

    adapter.call_tool("aiasec_agent", {})

    states = [call["params"].get("requestState") for call in _calls(transport)]
    assert states == [None, "first", state]


@pytest.mark.parametrize("method", ["sampling/createMessage", "tools/call", "something/new"])
def test_a_request_aiasec_cannot_answer_fails_the_call(method: str) -> None:
    adapter, transport = _modern(
        [_input_required(inputRequests={"k": {"method": method, "params": {}}})]
    )

    with pytest.raises(McpProtocolError, match="never samples a model"):
        adapter.call_tool("aiasec_agent", {})

    assert len(_calls(transport)) == 1


def test_the_round_trips_are_capped() -> None:
    endless = _input_required(inputRequests={"again": ELICIT})
    adapter, transport = _modern([endless] * (MAX_INPUT_ROUND_TRIPS + 1))

    with pytest.raises(McpProtocolError, match=f"{MAX_INPUT_ROUND_TRIPS} round trips"):
        adapter.call_tool("aiasec_agent", {})

    assert len(_calls(transport)) == MAX_INPUT_ROUND_TRIPS + 1


@pytest.mark.parametrize(
    "result",
    [
        _input_required(),
        _input_required(inputRequests=["not", "a", "map"]),
        _input_required(inputRequests={"k": "not an object"}),
        _input_required(inputRequests={"k": {"params": {}}}),
    ],
    ids=["nothing-to-answer", "list", "non-object-request", "no-method"],
)
def test_a_malformed_input_required_result_fails_closed(result: JsonObject) -> None:
    adapter, _ = _modern([result])

    with pytest.raises(McpProtocolError, match="input_required"):
        adapter.call_tool("aiasec_agent", {})


def test_client_capabilities_stay_empty_on_every_round() -> None:
    adapter, transport = _modern([_input_required(inputRequests={"x": ELICIT}), COMPLETE])

    adapter.call_tool("aiasec_agent", {})

    for call in _calls(transport):
        assert call["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] == {}

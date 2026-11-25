"""Answer the input a server asks for in a multi round-trip result (MCP 2026-07-28).

A server that needs input while handling a request returns a result with
`resultType: "input_required"`, carrying `inputRequests` (key -> `{method, params}`)
and/or an opaque `requestState`. The client sends the same request again, with an
answer per key in `inputResponses` and the `requestState` echoed verbatim.

aiasec declares no client capabilities, so a conforming server asks it for nothing.
A server that asks anyway gets the answers that do not act for it: every elicitation
is declined and the client has no roots. aiasec never samples a model for a server
and never acts on a target's behalf, so any other request fails the call.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

INPUT_REQUIRED = "input_required"
# Answered rounds per request before aiasec stops: a server that keeps asking cannot
# hold a probe open forever.
MAX_INPUT_ROUND_TRIPS = 5

_ANSWERS: dict[str, dict[str, Any]] = {
    "elicitation/create": {"action": "decline"},
    "roots/list": {"roots": []},
}


class InputRequestError(ValueError):
    """Raised when an input_required result is malformed or asks what aiasec never answers."""


def answered_params(params: Mapping[str, Any], result: Mapping[str, Any]) -> dict[str, Any]:
    """The params that re-issue a request, answering its input_required result."""

    if "inputRequests" not in result and "requestState" not in result:
        raise InputRequestError(
            "input_required result carries neither inputRequests nor requestState"
        )
    requests = result.get("inputRequests", {})
    if not isinstance(requests, dict):
        raise InputRequestError("input_required result has inputRequests that is not a map")
    answered = {
        **params,
        "inputResponses": {key: _answer(key, request) for key, request in requests.items()},
    }
    if "requestState" in result:
        answered["requestState"] = result["requestState"]
    return answered


def _answer(key: str, request: Any) -> dict[str, Any]:
    method = request.get("method") if isinstance(request, dict) else None
    if not isinstance(method, str):
        raise InputRequestError(f"input_required request {key!r} must be an object with a method")
    answer = _ANSWERS.get(method)
    if answer is None:
        raise InputRequestError(
            f"The server asks for {method!r} input; aiasec never samples a model for the "
            "server and answers only elicitation/create (declined) and roots/list (no roots)"
        )
    return dict(answer)

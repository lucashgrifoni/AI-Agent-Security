"""The model API target: sends each probe turn, retries, and reports errors."""

from __future__ import annotations

import json
import os
import time
from types import TracebackType
from typing import Any
from urllib.parse import urlsplit

from aiasec.core.conversation import drive_conversation
from aiasec.core.evaluator.rules import TargetObservation, ToolCall
from aiasec.core.probe import Probe
from aiasec.httptarget import (
    HttpReply,
    connection_for,
    post_json,
    request_path,
)
from aiasec.modeltarget.config import (
    ModelTargetConfig,
    ModelTargetError,
)
from aiasec.modeltarget.transcript import (
    EarlierReply,
    Transcript,
    build_transcript,
)
from aiasec.modeltarget.wire import (
    ANTHROPIC_VERSION,
    PARSERS,
    RENDERERS,
    _replay_blocks,
)

# Longest provider error message an error report repeats.
MAX_ERROR_MESSAGE = 1000
# A rate limit (429), a server error (5xx) or Anthropic's overload (529) is retried; any
# other status is the request's fault and would fail the same way again.
RETRYABLE_STATUSES = frozenset({429, 500, 502, 503, 504, 529})
# The longest wait between two attempts, whatever Retry-After asks for.
MAX_RETRY_WAIT_SECONDS = 30.0
# Replaced in tests, so a retry costs no real time.
_sleep = time.sleep


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
    def provider(self) -> str:
        return self._config.transport

    @property
    def model(self) -> str:
        return self._config.model

    @property
    def label(self) -> str:
        host = urlsplit(self._config.endpoint).netloc
        return f"{self._config.transport} model {self._config.model} at {host}"

    def observe(self, probe: Probe) -> TargetObservation:
        """Send a probe to the model, one request per turn, and return what it did.

        The tool calls of each turn are replayed on later turns, so the model sees the
        conversation it actually had.
        """

        # Earlier replies by their position: drive_conversation appends each reply to
        # the history right after the inputs it answered.
        earlier: dict[int, EarlierReply] = {}

        def send(arguments: dict[str, Any]) -> tuple[str, list[ToolCall]]:
            inputs = arguments["inputs"]
            text, calls, blocks = self._request(build_transcript(inputs, self._config, earlier))
            earlier[len(inputs)] = EarlierReply(calls, blocks)
            return text, calls

        return drive_conversation(probe, send)

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

    def complete(self, system: str, message: str) -> str:
        """Send one user message with this system prompt and no tools; return the text."""

        transcript = Transcript(
            system=system, tools=[], entries=[{"kind": "user", "text": message}]
        )
        return self._request(transcript)[0]

    def _post(self, endpoint: str, body: dict[str, Any]) -> tuple[int, bytes, int]:
        """POST, retrying a rate limit or a server error; return status, body, attempts."""

        timeout = self._config.timeout_seconds
        attempt = 1
        while True:
            reply: HttpReply = post_json(
                connection_for(endpoint, timeout),
                request_path(endpoint),
                body,
                self._headers(),
                timeout,
            )
            if reply.status not in RETRYABLE_STATUSES or attempt > self._config.max_retries:
                return reply.status, reply.body, attempt
            _sleep(_retry_wait(reply.headers.get("retry-after"), attempt))
            attempt += 1

    def _request(
        self, transcript: Transcript
    ) -> tuple[str, list[ToolCall], list[dict[str, Any]] | None]:
        provider = self._config.transport
        body = RENDERERS[provider](transcript, self._config)
        endpoint = self._config.endpoint
        status, payload, attempts = self._post(endpoint, body)
        if status != 200:
            reason = _reason(payload, self._api_key)
            # A turn that ends with the probe's assistant input reaches Anthropic as a
            # prefill, which older Claude models accept and newer ones reject.
            last = transcript.entries[-1] if transcript.entries else {}
            if provider == "anthropic" and status == 400 and last.get("kind") == "assistant":
                reason += (
                    " (this probe turn ends with an assistant input, which Anthropic reads"
                    " as a prefill; end the turn with a user input for this model)"
                )
            if attempts > 1:
                reason += f" (after {attempts} attempts)"
            raise ModelTargetError(f"The {provider} API answered HTTP {status}{reason}")
        try:
            reply = json.loads(payload)
            text, calls, cut = PARSERS[provider](reply)
        except (ValueError, RecursionError, KeyError, IndexError, TypeError, AttributeError) as exc:
            raise ModelTargetError(f"The {provider} API reply could not be read") from exc
        # The part past a cut could hold what a probe looks for; scoring the rest would
        # pass a probe on half an answer.
        if cut == "unfinished":
            raise ModelTargetError(
                f"The {provider} reply is not finished: it does not end with a stop reason "
                "that marks a complete reply"
            )
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
        # Anthropic content blocks, thinking included, go back unchanged on later turns.
        blocks = _replay_blocks(reply) if provider == "anthropic" else None
        return text, calls, blocks

    def _headers(self) -> dict[str, str]:
        if self._config.transport == "anthropic":
            headers = {"anthropic-version": ANTHROPIC_VERSION}
            if self._api_key:
                headers["x-api-key"] = self._api_key
            if self._config.workspace_id:
                headers["anthropic-workspace-id"] = self._config.workspace_id
            return headers
        return {"Authorization": f"Bearer {self._api_key}"} if self._api_key else {}


def _retry_wait(retry_after: str | None, attempt: int) -> float:
    """Seconds before the next attempt: Retry-After when it is a number, else 1, 2, 4..."""

    try:
        asked = float(retry_after) if retry_after is not None else None
    except ValueError:  # an HTTP date, or garbage: fall back to the growing wait
        asked = None
    wait = asked if asked is not None and asked >= 0 else float(2 ** (attempt - 1))
    return min(wait, MAX_RETRY_WAIT_SECONDS)


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
    # Providers put their advice at the end of a sentence or two; keep it whole and bound
    # only a pathological body.
    if len(message) > MAX_ERROR_MESSAGE:
        message = f"{message[:MAX_ERROR_MESSAGE]} [message cut]"
    return f": {message}"

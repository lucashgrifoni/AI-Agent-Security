"""Drive an agent under test that is exposed as an HTTP endpoint.

The contract (docs/target-contract.md) mirrors the MCP agent tool: for each probe turn
aiasec POSTs JSON `{"probeId", "turn", "turns", "inputs"}` and expects
`{"response": "<reply>", "toolsCalled": [...]}` with status 200, where each tool call is a
name or `{"name", "arguments"}`.

`http.client` is used directly: it never follows a redirect (so a credential header
cannot be forwarded to another host) and it only speaks http and https.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import socket
import ssl
import threading
from contextlib import suppress
from types import TracebackType
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aiasec import __version__
from aiasec.core.conversation import drive_conversation, parse_tool_calls
from aiasec.core.evaluator.rules import TargetObservation, ToolCall
from aiasec.core.probe import Probe

MAX_RESPONSE_BYTES = 1_048_576
_ENV_REFERENCE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class HttpTargetError(RuntimeError):
    """Raised when an HTTP target does not honor the aiasec target contract."""


class HttpTargetConfig(BaseModel):
    """Validated HTTP target configuration."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    transport: Literal["http"]
    url: str
    # Values may reference environment variables as ${NAME}; keep secrets there, not here.
    headers: dict[str, str] = Field(default_factory=dict)
    timeout_seconds: float = Field(default=30.0, alias="timeoutSeconds", gt=0, le=600)

    @field_validator("url")
    @classmethod
    def require_http_url_with_host(cls, value: str) -> str:
        """Accept only http and https URLs that name a host."""

        parts = urlsplit(value)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError("url must be an http or https URL with a host")
        return value

    @field_validator("headers")
    @classmethod
    def reject_malformed_headers(cls, value: dict[str, str]) -> dict[str, str]:
        """Reject header names or values that could split the request."""

        for name, item in value.items():
            if not name.strip() or any(ch in name + item for ch in "\r\n\x00"):
                raise ValueError("header names and values must not be empty or contain CR, LF, NUL")
        return value


class HttpAgentTarget:
    """An agent under test reached through one HTTP POST per probe turn."""

    def __init__(self, config: HttpTargetConfig, headers: dict[str, str]) -> None:
        self._config = config
        self._headers = headers
        parts = urlsplit(config.url)
        self._scheme = parts.scheme
        self._host = parts.hostname or ""
        self._port = parts.port
        self._path = request_path(config.url)

    @classmethod
    def start(cls, config: HttpTargetConfig) -> HttpAgentTarget:
        """Resolve header references before any request is sent."""

        return cls(config, {name: _expand(value) for name, value in config.headers.items()})

    @property
    def label(self) -> str:
        """Short description of the target for run output."""

        return f"HTTP POST {self._scheme}://{self._host}{f':{self._port}' if self._port else ''}"

    def observe(self, probe: Probe) -> TargetObservation:
        """Send a probe to the agent, one POST per turn, and return what it did."""

        return drive_conversation(probe, lambda arguments: self._post(probe.id, arguments))

    def close(self) -> None:
        """Nothing to release; each request uses its own connection."""

    def __enter__(self) -> HttpAgentTarget:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def _post(self, probe_id: str, arguments: dict[str, Any]) -> tuple[str, list[ToolCall]]:
        status, payload = post_json(
            self._connection(), self._path, arguments, self._headers, self._config.timeout_seconds
        )
        if status != 200:
            raise HttpTargetError(
                f"Target answered HTTP {status} for probe {probe_id}; aiasec expects 200 "
                "and does not follow redirects"
            )
        return _parse_reply(payload, probe_id)

    def _connection(self) -> http.client.HTTPConnection:
        return connection_for(self._config.url, self._config.timeout_seconds)


def connection_for(url: str, timeout: float) -> http.client.HTTPConnection:
    """An unopened connection to the host of an http or https URL."""

    parts = urlsplit(url)
    host = parts.hostname or ""
    if parts.scheme == "https":
        # The audit rule below warns about Pythons older than 3.4.3, which did not verify
        # certificates. aiasec needs 3.12+ and passes a default context explicitly
        # (CERT_REQUIRED, hostname checking); tests/test_http_target.py asserts both.
        return http.client.HTTPSConnection(  # nosemgrep: httpsconnection-detected
            host, parts.port, timeout=timeout, context=ssl.create_default_context()
        )
    return http.client.HTTPConnection(host, parts.port, timeout=timeout)


def request_path(url: str) -> str:
    """The path and query of a URL, as the request line carries them."""

    parts = urlsplit(url)
    return (parts.path or "/") + (f"?{parts.query}" if parts.query else "")


def post_json(
    connection: http.client.HTTPConnection,
    path: str,
    document: dict[str, Any],
    extra_headers: dict[str, str],
    timeout: float,
) -> tuple[int, bytes]:
    """POST a JSON document and return the status and body, within one deadline.

    Redirects are never followed, so a credential header cannot reach another host.
    A reply larger than MAX_RESPONSE_BYTES raises.
    """

    body = json.dumps(document).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": f"aiasec/{__version__}",
        **extra_headers,
    }
    outcome: dict[str, Any] = {}
    # Held while the caller gives up and while the worker decides to send, so a
    # request the caller already reported as timed out is never sent afterwards.
    decision = threading.Lock()

    def exchange() -> None:
        try:
            connection.connect()
            with decision:
                if outcome.get("abandoned"):
                    return
                outcome["socket"] = connection.sock
            connection.request("POST", path, body=body, headers=headers)
            response = connection.getresponse()
            outcome["reply"] = (response.status, response.read(MAX_RESPONSE_BYTES + 1))
        except Exception as exc:  # noqa: BLE001 - handed to the calling thread below
            outcome["error"] = exc
        finally:
            connection.close()

    # The socket timeout bounds each operation, not the request: a slow name lookup
    # (no socket timeout covers it), a slow handshake, or a reply sent a byte at a
    # time can each outlast it. The exchange gets timeoutSeconds in total; past it,
    # shutting the socket down ends any read still in progress.
    worker = threading.Thread(target=exchange, daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        with decision:
            outcome["abandoned"] = True
            sock = outcome.get("socket")
        if sock is not None:
            with suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
        raise HttpTargetError(f"Target timed out after {timeout} s")
    error = outcome.get("error")
    if isinstance(error, TimeoutError):
        raise HttpTargetError(f"Target timed out after {timeout} s") from error
    if isinstance(error, (OSError, http.client.HTTPException)):
        raise HttpTargetError(f"HTTP request to the target failed: {error}") from error
    if error is not None:
        raise error

    status, payload = outcome["reply"]
    if len(payload) > MAX_RESPONSE_BYTES:
        raise HttpTargetError(f"Target reply is larger than {MAX_RESPONSE_BYTES} bytes")
    return status, payload


def _expand(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in os.environ:
            raise HttpTargetError(
                f"Header references environment variable {name}, which is not set"
            )
        return os.environ[name]

    return _ENV_REFERENCE.sub(replace, value)


def _parse_reply(payload: bytes, probe_id: str) -> tuple[str, list[ToolCall]]:
    try:
        reply = json.loads(payload)
    except (ValueError, RecursionError) as exc:  # deep nesting exhausts the decoder's stack
        raise HttpTargetError(f"Target reply for probe {probe_id} is not JSON") from exc
    if not isinstance(reply, dict) or not isinstance(reply.get("response"), str):
        raise HttpTargetError(f"Target reply for probe {probe_id} must contain a response string")
    # As with MCP targets, an omitted list would pass every tool_not_called check.
    try:
        return reply["response"], parse_tool_calls(reply.get("toolsCalled"))
    except ValueError as exc:
        raise HttpTargetError(
            f"Target reply for probe {probe_id} must report toolsCalled: {exc}"
        ) from exc

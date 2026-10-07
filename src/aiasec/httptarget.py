"""Drive an agent under test that is exposed as an HTTP endpoint.

The contract (docs/target-contract.md) mirrors the MCP agent tool: for each probe turn
aiasec POSTs JSON `{"probeId", "turn", "turns", "inputs"}` and expects
`{"response": "<reply>", "toolsCalled": ["<tool>", ...]}` with status 200.

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
import time
from contextlib import suppress
from types import TracebackType
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aiasec import __version__
from aiasec.core.conversation import drive_conversation
from aiasec.core.evaluator.rules import TargetObservation
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
        self._path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")

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

    def _post(self, probe_id: str, arguments: dict[str, Any]) -> tuple[str, list[str]]:
        body = json.dumps(arguments).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"aiasec/{__version__}",
            **self._headers,
        }
        timeout = self._config.timeout_seconds
        deadline = time.monotonic() + timeout
        expired = threading.Event()
        watchdog: threading.Timer | None = None
        connection = self._connection()
        try:
            connection.connect()
            # The socket timeout bounds each read, not the reply: a target that sends a
            # byte just inside it would never time out. At the deadline the watchdog shuts
            # the socket down, which ends whatever read is in progress.
            watchdog = threading.Timer(
                max(deadline - time.monotonic(), 0.0), _expire, (connection.sock, expired)
            )
            watchdog.start()
            connection.request("POST", self._path, body=body, headers=headers)
            response = connection.getresponse()
            payload = response.read(MAX_RESPONSE_BYTES + 1)
        except (OSError, http.client.HTTPException) as exc:
            if expired.is_set() or isinstance(exc, TimeoutError):
                raise HttpTargetError(f"Target timed out after {timeout} s") from exc
            raise HttpTargetError(f"HTTP request to the target failed: {exc}") from exc
        finally:
            if watchdog is not None:
                watchdog.cancel()
            connection.close()

        # A reply cut short by the watchdog can read as complete, so check the flag too.
        if expired.is_set():
            raise HttpTargetError(f"Target timed out after {timeout} s")
        if response.status != 200:
            raise HttpTargetError(
                f"Target answered HTTP {response.status} for probe {probe_id}; aiasec expects 200 "
                "and does not follow redirects"
            )
        if len(payload) > MAX_RESPONSE_BYTES:
            raise HttpTargetError(f"Target reply is larger than {MAX_RESPONSE_BYTES} bytes")
        return _parse_reply(payload, probe_id)

    def _connection(self) -> http.client.HTTPConnection:
        timeout = self._config.timeout_seconds
        if self._scheme == "https":
            # The audit rule below warns about Pythons older than 3.4.3, which did not verify
            # certificates. aiasec needs 3.12+ and passes a default context explicitly
            # (CERT_REQUIRED, hostname checking); tests/test_http_target.py asserts both.
            return http.client.HTTPSConnection(  # nosemgrep: httpsconnection-detected
                self._host, self._port, timeout=timeout, context=ssl.create_default_context()
            )
        return http.client.HTTPConnection(self._host, self._port, timeout=timeout)


def _expire(sock: socket.socket | None, expired: threading.Event) -> None:
    expired.set()
    if sock is not None:
        with suppress(OSError):
            sock.shutdown(socket.SHUT_RDWR)


def _expand(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in os.environ:
            raise HttpTargetError(
                f"Header references environment variable {name}, which is not set"
            )
        return os.environ[name]

    return _ENV_REFERENCE.sub(replace, value)


def _parse_reply(payload: bytes, probe_id: str) -> tuple[str, list[str]]:
    try:
        reply = json.loads(payload)
    except ValueError as exc:
        raise HttpTargetError(f"Target reply for probe {probe_id} is not JSON") from exc
    if not isinstance(reply, dict) or not isinstance(reply.get("response"), str):
        raise HttpTargetError(f"Target reply for probe {probe_id} must contain a response string")
    tools = reply.get("toolsCalled")
    # As with MCP targets, an omitted list would pass every tool_not_called check.
    if not isinstance(tools, list) or not all(isinstance(tool, str) for tool in tools):
        raise HttpTargetError(
            f"Target reply for probe {probe_id} must report toolsCalled as a list of tool names"
        )
    return reply["response"], list(tools)

"""Transport and process-runner abstractions for JSON-RPC over stdio."""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path
from typing import Any, Protocol, TextIO, cast

JsonObject = dict[str, Any]


class McpTransportError(RuntimeError):
    """Raised when a JSON-RPC transport cannot read or write messages."""


class JsonRpcTransport(Protocol):
    """Minimal fakeable transport contract for JSON-RPC messages."""

    def send(self, message: JsonObject) -> None:
        """Send one JSON-RPC message."""

    def receive(self) -> JsonObject:
        """Receive one JSON-RPC message."""

    def close(self) -> None:
        """Close the transport."""


class ProcessRunner(Protocol):
    """Fakeable factory for starting MCP server processes."""

    def start(
        self,
        command: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> JsonRpcTransport:
        """Start a process and return a JSON-RPC transport."""


class LineJsonRpcTransport:
    """Newline-delimited JSON-RPC transport over text streams."""

    def __init__(self, *, reader: TextIO, writer: TextIO) -> None:
        self._reader = reader
        self._writer = writer

    def send(self, message: JsonObject) -> None:
        """Serialize and write one JSON-RPC message."""

        try:
            self._writer.write(json.dumps(message, ensure_ascii=False, separators=(",", ":")))
            self._writer.write("\n")
            self._writer.flush()
        except OSError as exc:
            raise McpTransportError("Unable to write JSON-RPC message to transport") from exc

    def receive(self) -> JsonObject:
        """Read and parse one newline-delimited JSON-RPC message."""

        try:
            raw_line = self._reader.readline()
        except OSError as exc:
            raise McpTransportError("Unable to read JSON-RPC message from transport") from exc

        if raw_line == "":
            raise McpTransportError("Transport closed before a JSON-RPC message was received")

        try:
            parsed = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise McpTransportError("Transport returned malformed JSON") from exc

        if not isinstance(parsed, dict):
            raise McpTransportError("JSON-RPC message must be an object")
        return cast("JsonObject", parsed)

    def close(self) -> None:
        """Close the underlying streams."""

        for stream in (self._writer, self._reader):
            with suppress(OSError):
                stream.close()


class StdioProcessRunner:
    """Start MCP stdio servers as local child processes."""

    def __init__(self, *, shutdown_timeout_seconds: float = 2.0) -> None:
        if shutdown_timeout_seconds <= 0:
            raise ValueError("shutdown_timeout_seconds must be positive")
        self._shutdown_timeout_seconds = shutdown_timeout_seconds

    def start(
        self,
        command: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> JsonRpcTransport:
        """Start a local command and expose its stdin/stdout as JSON-RPC."""

        if not command:
            raise ValueError("command must not be empty")

        process_env = None if env is None else {**os.environ, **env}
        process = subprocess.Popen(
            list(command),
            cwd=cwd,
            env=process_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
        )
        return _SubprocessJsonRpcTransport(
            process,
            shutdown_timeout_seconds=self._shutdown_timeout_seconds,
        )


class _SubprocessJsonRpcTransport(LineJsonRpcTransport):
    def __init__(
        self,
        process: subprocess.Popen[str],
        *,
        shutdown_timeout_seconds: float,
    ) -> None:
        if process.stdin is None or process.stdout is None:
            raise McpTransportError("Process was not started with stdio pipes")
        self._process = process
        self._shutdown_timeout_seconds = shutdown_timeout_seconds
        super().__init__(reader=process.stdout, writer=process.stdin)

    def close(self) -> None:
        """Close pipes and stop the child process if it is still running."""

        super().close()
        if self._process.poll() is not None:
            return

        self._process.terminate()
        try:
            self._process.wait(timeout=self._shutdown_timeout_seconds)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait(timeout=self._shutdown_timeout_seconds)

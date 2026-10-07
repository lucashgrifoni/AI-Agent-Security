"""Transport and process-runner abstractions for JSON-RPC over stdio."""

from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path
from typing import Any, Protocol, TextIO, cast

JsonObject = dict[str, Any]


class McpTransportError(RuntimeError):
    """Raised when a JSON-RPC transport cannot read or write messages."""


class McpTransportTimeout(McpTransportError):
    """Raised when no message arrives before the receive deadline."""


class JsonRpcTransport(Protocol):
    """Minimal fakeable transport contract for JSON-RPC messages."""

    def send(self, message: JsonObject, timeout: float | None = None) -> None:
        """Send one JSON-RPC message.

        ``timeout`` bounds the write in seconds; a transport raises McpTransportTimeout
        when it passes. The adapter passes the keyword only when a request has a deadline.
        """

    def receive(self, timeout: float | None = None) -> JsonObject:
        """Receive one JSON-RPC message.

        ``timeout`` bounds this wait in seconds and overrides the transport's default;
        a transport raises McpTransportTimeout when it passes. The adapter passes the
        keyword only when a request has a deadline.
        """

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
    """Newline-delimited JSON-RPC transport over text streams.

    A blocking readline cannot time out, so a daemon thread reads the stream into a
    queue that receive() waits on with a deadline. A silent peer fails instead of
    hanging.
    """

    def __init__(
        self,
        *,
        reader: TextIO,
        writer: TextIO,
        receive_timeout_seconds: float | None = None,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._receive_timeout_seconds = receive_timeout_seconds
        self._lines: queue.Queue[str | McpTransportError] = queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        end: str | McpTransportError = ""  # end of stream
        try:
            for line in self._reader:
                self._lines.put(line)
        except (OSError, ValueError) as exc:
            end = McpTransportError(f"Unable to read JSON-RPC message from transport: {exc}")
        self._lines.put(end)

    def send(self, message: JsonObject, timeout: float | None = None) -> None:
        """Serialize and write one JSON-RPC message.

        A peer that stops reading fills the pipe and blocks the write. With a
        ``timeout``, a watchdog calls ``_abort()`` when it passes; the subprocess
        transport stops the process there, which makes the blocked write fail.
        """

        expired = threading.Event()
        watchdog = None
        if timeout is not None:
            watchdog = threading.Timer(timeout, self._expire, (expired,))
            watchdog.start()
        try:
            self._writer.write(json.dumps(message, ensure_ascii=False, separators=(",", ":")))
            self._writer.write("\n")
            self._writer.flush()
        except OSError as exc:
            if not expired.is_set():
                raise McpTransportError("Unable to write JSON-RPC message to transport") from exc
        finally:
            if watchdog is not None:
                watchdog.cancel()
        if expired.is_set():
            raise McpTransportTimeout(f"Target did not read the request within {timeout} seconds")

    def _expire(self, expired: threading.Event) -> None:
        expired.set()
        self._abort()

    def _abort(self) -> None:
        """Unblock a write stuck on a peer that stopped reading; a plain stream cannot."""

    def receive(self, timeout: float | None = None) -> JsonObject:
        """Return the next message, or fail once the receive deadline passes."""

        deadline = timeout if timeout is not None else self._receive_timeout_seconds
        try:
            item = self._lines.get(timeout=deadline)
        except queue.Empty as exc:
            raise McpTransportTimeout(
                f"Target sent no JSON-RPC message within {deadline} seconds"
            ) from exc
        if isinstance(item, McpTransportError) or item == "":
            # The stream is over: leave the marker queued so a later read fails the same
            # way instead of waiting for a line that will never come.
            self._lines.put(item)
            if isinstance(item, McpTransportError):
                raise item
        return _parse_line(item)

    def close(self) -> None:
        """Close the underlying streams."""

        for stream in (self._writer, self._reader):
            with suppress(OSError):
                stream.close()


def _parse_line(raw_line: str) -> JsonObject:
    if raw_line == "":
        raise McpTransportError("Transport closed before a JSON-RPC message was received")

    try:
        parsed = json.loads(raw_line)
    except json.JSONDecodeError as exc:
        raise McpTransportError("Transport returned malformed JSON") from exc

    if not isinstance(parsed, dict):
        raise McpTransportError("JSON-RPC message must be an object")
    return cast("JsonObject", parsed)


class StdioProcessRunner:
    """Start MCP stdio servers as local child processes."""

    def __init__(
        self,
        *,
        shutdown_timeout_seconds: float = 2.0,
        receive_timeout_seconds: float | None = None,
    ) -> None:
        if shutdown_timeout_seconds <= 0:
            raise ValueError("shutdown_timeout_seconds must be positive")
        if receive_timeout_seconds is not None and receive_timeout_seconds <= 0:
            raise ValueError("receive_timeout_seconds must be positive")
        self._shutdown_timeout_seconds = shutdown_timeout_seconds
        self._receive_timeout_seconds = receive_timeout_seconds

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
            receive_timeout_seconds=self._receive_timeout_seconds,
        )


class _SubprocessJsonRpcTransport(LineJsonRpcTransport):
    def __init__(
        self,
        process: subprocess.Popen[str],
        *,
        shutdown_timeout_seconds: float,
        receive_timeout_seconds: float | None = None,
    ) -> None:
        if process.stdin is None or process.stdout is None:
            raise McpTransportError("Process was not started with stdio pipes")
        self._process = process
        self._shutdown_timeout_seconds = shutdown_timeout_seconds
        super().__init__(
            reader=process.stdout,
            writer=process.stdin,
            receive_timeout_seconds=receive_timeout_seconds,
        )

    def _abort(self) -> None:
        # A stopped process breaks the pipe, so the blocked write fails instead of waiting.
        with suppress(OSError):
            self._process.kill()

    def close(self) -> None:
        """Stop the child process, then close its pipes.

        stdin closes first so a well-behaved server sees EOF and exits. stdout closes
        last: on Windows, closing a pipe that the reader thread is blocked on waits for
        the read to return, so a hung server would block close() until it exited.
        """

        with suppress(OSError):
            self._writer.close()
        if self._process.poll() is None:
            try:
                self._process.wait(timeout=self._shutdown_timeout_seconds)
            except subprocess.TimeoutExpired:
                self._process.terminate()
                try:
                    self._process.wait(timeout=self._shutdown_timeout_seconds)
                except subprocess.TimeoutExpired:
                    self._process.kill()
                    self._process.wait(timeout=self._shutdown_timeout_seconds)
        with suppress(OSError):
            self._reader.close()

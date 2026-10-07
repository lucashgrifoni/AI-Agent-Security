"""Drive an agent under test that is exposed as one MCP tool.

The target contract (docs/target-contract.md): the target is an MCP stdio server that
exposes a tool, `aiasec_agent` by default. aiasec calls that tool once per probe turn
with the conversation so far. The tool runs the agent and returns its reply as text
content, and the names of the tools the agent called in
`structuredContent.toolsCalled`.
"""

from __future__ import annotations

from types import TracebackType
from typing import Any

from aiasec.core.conversation import drive_conversation
from aiasec.core.evaluator.rules import TargetObservation
from aiasec.core.probe import Probe
from aiasec.mcp.config import McpStdioConfig
from aiasec.mcp.stdio import DEFAULT_PROBE_TIMEOUT_SECONDS, McpSession, McpStdioAdapter
from aiasec.mcp.transport import ProcessRunner, StdioProcessRunner


class McpTargetError(RuntimeError):
    """Raised when a target does not honor the aiasec target contract."""


class McpAgentTarget:
    """An agent under test reached through an MCP tool call per probe."""

    def __init__(self, client: McpStdioAdapter, *, agent_tool: str) -> None:
        self._client = client
        self._agent_tool = agent_tool

    @classmethod
    def start(
        cls,
        config: McpStdioConfig,
        *,
        runner: ProcessRunner | None = None,
    ) -> McpAgentTarget:
        """Start the target process, initialize MCP, and check the agent tool exists."""

        process_runner = runner or StdioProcessRunner(
            receive_timeout_seconds=config.timeout_seconds
        )
        transport = process_runner.start(config.command, cwd=config.cwd, env=config.env or None)
        client = McpStdioAdapter(transport)
        target = cls(client, agent_tool=config.agent_tool)
        try:
            client.connect(
                mode=config.protocol,
                probe_timeout=min(DEFAULT_PROBE_TIMEOUT_SECONDS, config.timeout_seconds),
            )
            exposed = {tool.get("name") for tool in client.list_tools()}
            if config.agent_tool not in exposed:
                raise McpTargetError(
                    f"Target does not expose the agent tool {config.agent_tool!r}; "
                    f"it exposes {sorted(name for name in exposed if isinstance(name, str))}"
                )
        except BaseException:
            target.close()
            raise
        return target

    @property
    def session(self) -> McpSession:
        """The protocol era and version agreed with the target."""

        if self._client.session is None:
            raise McpTargetError("Target session is not connected")
        return self._client.session

    @property
    def label(self) -> str:
        """Short description of the target for run output."""

        return f"MCP {self.session.protocol_version} ({self.session.era})"

    def observe(self, probe: Probe) -> TargetObservation:
        """Send a probe to the agent, one tool call per turn, and return what it did."""

        def send(arguments: dict[str, Any]) -> tuple[str, list[str]]:
            result = self._client.call_tool(self._agent_tool, arguments)
            if result.get("isError") is True:
                raise McpTargetError(f"Target returned a tool error for probe {probe.id}")
            return _text_content(result), _tools_called(result, probe.id)

        return drive_conversation(probe, send)

    def close(self) -> None:
        """Stop the target process."""

        self._client.close()

    def __enter__(self) -> McpAgentTarget:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def _text_content(result: dict[str, Any]) -> str:
    content = result.get("content")
    if not isinstance(content, list):
        raise McpTargetError("Tool result must contain a content list")
    return "\n".join(
        str(block.get("text", ""))
        for block in content
        if isinstance(block, dict) and block.get("type") == "text"
    )


def _tools_called(result: dict[str, Any], probe_id: str) -> list[str]:
    structured = result.get("structuredContent")
    tools = structured.get("toolsCalled") if isinstance(structured, dict) else None
    # A target that does not report its tool calls cannot pass a tool_not_called check
    # by omission, so a missing or malformed list is a contract violation, not "none".
    if not isinstance(tools, list) or not all(isinstance(tool, str) for tool in tools):
        raise McpTargetError(
            f"Target did not report structuredContent.toolsCalled as a list of tool names "
            f"for probe {probe_id}"
        )
    return list(tools)

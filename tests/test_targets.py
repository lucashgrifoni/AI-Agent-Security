"""Target selection: one interface for every live target, one entry per kind of config."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aiasec.core.modes import (
    HTTP_TARGET_MODE,
    MCP_HTTP_TARGET_MODE,
    MCP_TARGET_MODE,
    MODEL_API_TARGET_MODE,
)
from aiasec.core.target import AgentTarget
from aiasec.httptarget import HttpAgentTarget, HttpTargetConfig
from aiasec.mcp.config import McpHttpConfig, McpStdioConfig
from aiasec.mcp.target import McpAgentTarget
from aiasec.modeltarget import ModelAgentTarget, ModelTargetConfig
from aiasec.targets import KINDS, kind_of, load_target_config


@pytest.mark.parametrize("target", [HttpAgentTarget, ModelAgentTarget, McpAgentTarget])
def test_every_live_target_has_the_members_of_the_interface(target: type) -> None:
    for member in ("label", "observe", "close", "__enter__", "__exit__"):
        assert hasattr(target, member), member


def test_the_interface_rejects_an_object_that_cannot_observe() -> None:
    assert not isinstance(object(), AgentTarget)


@pytest.mark.parametrize(
    ("raw", "config_type", "mode", "action"),
    [
        (
            {"transport": "http", "url": "http://127.0.0.1:8765/agent"},
            HttpTargetConfig,
            HTTP_TARGET_MODE,
            "send probes to http://127.0.0.1:8765/agent",
        ),
        (
            {"transport": "ollama", "model": "qwen3", "apiKeyEnv": None},
            ModelTargetConfig,
            MODEL_API_TARGET_MODE,
            "send probes to the ollama model qwen3 at http://127.0.0.1:11434/api/chat",
        ),
        (
            {"transport": "stdio", "command": ["python", "server.py"]},
            McpStdioConfig,
            MCP_TARGET_MODE,
            "start ['python', 'server.py']",
        ),
        (
            {"transport": "mcp-http", "url": "http://127.0.0.1:8766/mcp"},
            McpHttpConfig,
            MCP_HTTP_TARGET_MODE,
            "send probes to the MCP server at http://127.0.0.1:8766/mcp",
        ),
    ],
)
def test_each_config_selects_its_kind(
    tmp_path: Path, raw: dict[str, Any], config_type: type, mode: str, action: str
) -> None:
    path = tmp_path / "target.json"
    path.write_text(json.dumps(raw), encoding="utf-8")

    config = load_target_config(path)
    kind = kind_of(config)

    assert type(config) is config_type
    assert kind.mode == mode
    assert kind.action(config) == action


def test_every_config_type_has_exactly_one_kind() -> None:
    assert set(KINDS) == {HttpTargetConfig, ModelTargetConfig, McpStdioConfig, McpHttpConfig}


def test_mcp_targets_take_one_probe_at_a_time() -> None:
    assert not KINDS[McpStdioConfig].concurrent
    assert not KINDS[McpHttpConfig].concurrent

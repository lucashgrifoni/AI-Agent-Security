"""Send probes straight to a model API: Anthropic, OpenAI (or a compatible server), Ollama.

The target config names the model, an optional system prompt and the tools the model
may call. For each probe turn aiasec sends the conversation so far as one request. The
model's text is the reply; the tool calls it asks for are recorded with their arguments
and never executed, so the turn ends there.

Probe input roles reach the model like this:

- `system`: appended to the config's system prompt;
- `user` and `assistant`: messages;
- `rag_corpus`: a user message holding the retrieved documents;
- `tool_output`: a call the model is shown to have made, followed by its result. The
  tool is named after a `tool://<name>/...` document path (otherwise `read_document`)
  and declared to the model if the config does not declare it;
- `tool_catalog`: tool definitions the model sees, named after the last segment of the
  document path, with the document's text (including the injected part) as description.

An API key is read from the environment variable the config names, and is only sent
over https or to a loopback address. Requests use the same deadline, no-redirect and
size rules as HTTP targets (aiasec.httptarget.post_json).
"""

from __future__ import annotations

from aiasec.modeltarget.client import ModelAgentTarget
from aiasec.modeltarget.config import (
    PROVIDERS,
    ModelTargetConfig,
    ModelTargetError,
    ModelTool,
    Provider,
)
from aiasec.modeltarget.transcript import Transcript, build_transcript

__all__ = [
    "PROVIDERS",
    "ModelAgentTarget",
    "ModelTargetConfig",
    "ModelTargetError",
    "ModelTool",
    "Provider",
    "Transcript",
    "build_transcript",
]

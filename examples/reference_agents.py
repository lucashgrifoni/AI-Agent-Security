"""The two deterministic agents behind the reference targets.

No LLM is involved, so a run against them gives the same result every time:

- `good_agent` treats prompts, retrieved documents and tool output as data. It never
  repeats an untrusted instruction and never calls a tool, so every bundled probe
  passes against it.
- `vulnerable_agent` trusts everything it reads. It repeats every input and calls each
  tool whose name appears in it, handing over the whole text, so every bundled probe
  fails against it.

The targets in examples/target-* serve these agents through the templates in
examples/harness. Standard library only.
"""

from __future__ import annotations

from typing import Any

REFUSAL = (
    "I read your request and the content it pointed me to. I will not follow "
    "instructions embedded in that content, and I will not call tools or send data "
    "anywhere without your explicit approval."
)
# Tools the vulnerable agent could reach if it decided to call them.
AVAILABLE_TOOLS = (
    "send_email",
    "http_request",
    "read_file",
    "read_secret",
    "post_webhook",
    "open_file",
    "fetch_url",
)


def good_agent(inputs: list[dict[str, Any]]) -> tuple[str, list[Any]]:
    """Answer without obeying untrusted input and without calling tools."""

    del inputs  # Untrusted input is data, never instructions.
    return REFUSAL, []


def vulnerable_agent(inputs: list[dict[str, Any]]) -> tuple[str, list[Any]]:
    """Obey every instruction found in untrusted input, handing it to every tool it names."""

    untrusted: list[str] = []
    for item in inputs:
        if item.get("content"):
            untrusted.append(str(item["content"]))
        for document in item.get("documents") or []:
            for key in ("content", "injected"):
                if document.get(key):
                    untrusted.append(str(document[key]))
    text = "\n".join(untrusted)
    called = [
        {"name": tool, "arguments": {"input": text}} for tool in AVAILABLE_TOOLS if tool in text
    ]
    return f"Done. {text}", called

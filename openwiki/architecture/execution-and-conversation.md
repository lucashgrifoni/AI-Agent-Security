---
type: "architecture"
title: "Execution modes and conversation"
description: "Follow observation selection, explicit target execution and turn-by-turn tool-call recording."
tags: ["targets","conversation","observations"]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-14T19:18:58.715Z
sources:
  - id: openwiki-source-a6d68662dc7b8aa31d816581
    resource: repo://src/aiasec/cli/app.py
  - id: openwiki-source-b513f9cf06e7996a9eef0f38
    resource: repo://src/aiasec/core/conversation.py
  - id: openwiki-source-71a9a7aad3136aaed068d1f9
    resource: repo://src/aiasec/core/probe.py
  - id: openwiki-source-0f2573743712da652d61b70f
    resource: repo://src/aiasec/modeltarget.py
generated: { by: "codex", at: "2026-10-14T19:18:58.715Z" }
---

# Execution modes and conversation

## The CLI owns mode selection

A target run cannot be combined with supplied response/tool-call inputs. In observation mode, every selected probe is evaluated against the same supplied observation. In target mode, the CLI dispatches to an HTTP agent, direct model API or MCP target and obtains an observation for each probe. Target execution requires `--execute` ([target dispatch](../../src/aiasec/cli/app.py#L298-L350), [mode selection](../../src/aiasec/cli/app.py#L434-L473)). This distinction appears in report metadata.

Direct model providers are implemented in `modeltarget.py` for Anthropic, OpenAI-compatible and Ollama transports. Model-requested tool calls are recorded with arguments and are not executed by that direct-model transport. This is distinct from testing an agent harness that performs its own tools ([model transport](../../src/aiasec/modeltarget.py#L1-L59)).

## Conversation state is explicit

Each user input opens a turn. Retrieved documents and tool outputs attach to the preceding turn, or the first turn when they precede any user input. The driver sends accumulated history, retains prior assistant replies, scores the final reply and accumulates reported calls from all turns ([conversation driver](../../src/aiasec/core/conversation.py)). Tool observations depend on the target contract's reported calls; they are not an independent interception of every operation the tested agent performed.

## The optional judge is advisory

The CLI obtains optional judge opinions after the rules results and passes them to the report renderer. It does not replace those results or the gate decision ([run flow](../../src/aiasec/cli/app.py#L475-L490), [probe schema](../../src/aiasec/core/probe.py#L71-L90)). External model access is a separate configured execution dependency.

Continue with [rules and gate](../concepts/rules-and-gate.md) to interpret the resulting evidence.

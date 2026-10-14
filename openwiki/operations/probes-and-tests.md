---
type: "operations"
title: "Probe maintenance and regression tests"
description: "Extend the versioned rules-only probe contract and locate gate and conversation regression coverage."
tags: ["probes","testing","maintenance"]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-14T19:18:58.715Z
sources:
  - id: openwiki-source-71a9a7aad3136aaed068d1f9
    resource: repo://src/aiasec/core/probe.py
  - id: openwiki-source-0c5bab43a6c28c1bde5bf1bf
    resource: repo://tests/test_gate_partial.py
  - id: openwiki-source-d219a36c446fb20f63c6c3c6
    resource: repo://tests/test_gate.py
generated: { by: "codex", at: "2026-10-14T19:16:48.664Z" }
---

# Probe maintenance and regression tests

## Keep the probe contract explicit

A probe declares its id, title, category, severity, inputs and expectations under `aiasec.probe/v1`. The configured evaluator is restricted to `rules`; the optional judge criterion stays separate. Pydantic models reject extra fields, and identity fields must be nonempty ([probe schema](../../src/aiasec/core/probe.py#L69-L105)). Add a probe that checks a concrete observed property, and preserve source attribution and selection metadata in the report.

## Check boundaries with existing tests

The test suite includes probe loading/selection, evaluator rules, conversation, tool arguments, MCP/HTTP/model targets and outputs. Gate tests cover threshold outcomes and partial-report handling ([threshold tests](../../tests/test_gate.py), [subset tests](../../tests/test_gate_partial.py)). Follow the contribution and workflow commands in the repository before proposing a change; a configured test is separate from a currently passing run.

Use owned deterministic reference targets when exercising examples. Testing an external model or agent is a separate action with its own authorization and runtime configuration. Update the [source-linked wiki](../../docs/openwiki.md) through the native lifecycle when behavior changes.

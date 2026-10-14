---
type: "operations"
title: "Probe maintenance and regression tests"
description: "Extend the versioned rules-only probe contract and locate gate and conversation regression coverage."
tags: ["probes","testing","maintenance"]
sources:
  - id: openwiki-source-f511aae758ec5d25a9f8719a
    resource: repo://.github/workflows/security.yml
  - id: openwiki-source-71a9a7aad3136aaed068d1f9
    resource: repo://src/aiasec/core/probe.py
  - id: openwiki-source-0c5bab43a6c28c1bde5bf1bf
    resource: repo://tests/test_gate_partial.py
  - id: openwiki-source-d219a36c446fb20f63c6c3c6
    resource: repo://tests/test_gate.py
generated: { by: "codex", at: "2026-10-14T23:10:39.454Z" }
verified:
  - by: openwiki/0.7.2
    at: 2026-10-14T23:10:39.454Z
---

# Probe maintenance and regression tests

## Keep the probe contract explicit

A probe declares its id, title, category, severity, inputs and expectations under `aiasec.probe/v1`. The configured evaluator is restricted to `rules`; the optional judge criterion stays separate. Pydantic models reject extra fields, and identity fields must be nonempty ([probe schema](../../src/aiasec/core/probe.py#L69-L105)). Add a probe that checks a concrete observed property, and preserve source attribution and selection metadata in the report.

## Check boundaries with existing tests

The test suite includes probe loading/selection, evaluator rules, conversation, tool arguments, MCP/HTTP/model targets and outputs. Gate tests cover threshold outcomes and partial-report handling ([threshold tests](../../tests/test_gate.py), [subset tests](../../tests/test_gate_partial.py)). Follow the contribution and workflow commands in the repository before proposing a change; a configured test is separate from a currently passing run.

Use owned deterministic reference targets when exercising examples. Testing an external model or agent is a separate action with its own authorization and runtime configuration. Update the [source-linked wiki](../../docs/openwiki.md) through the native lifecycle when behavior changes.

## CI token permissions

The [security workflow](../../.github/workflows/security.yml) grants actions read to the Semgrep, CodeQL and Trivy jobs, alongside their existing content and security-event permissions. The Gitleaks history job also receives pull-request read permission. These reads support the workflow's existing report and PR operations; they do not change scanner commands, rule selection, conditions or gates.

A report produced by a scanner is distinct from its upload to GitHub Code Scanning. CodeQL, Code Scanning upload and Dependency Review also depend on the repository's available GitHub features. Validate their actual execution and upload results before treating a configured check as passing.

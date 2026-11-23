---
type: "quickstart"
title: "AI agent security testbed"
description: "Route observed replies, explicit target runs and rules-based report gates without promoting results into runtime protection."
tags: ["agents","probes","mcp"]
sources:
  - id: openwiki-source-05ccef8d4cf1698187f20464
    resource: repo://pyproject.toml
  - id: openwiki-source-00e7e13ce81ae4881fcd1042
    resource: repo://src/aiasec/core/runner.py
generated: { by: "codex", at: "2026-10-14T19:16:48.664Z" }
verified:
  - by: openwiki/0.7.2
    at: 2026-10-14T23:10:39.454Z
---

# AI agent security testbed

The package installs `aiasec` and requires Python3.12 or newer. Its CLI runs versioned adversarial probes and writes reports for a separate gate ([package metadata](../pyproject.toml), [probe runner](../src/aiasec/core/runner.py)). A passing run means the selected expectations did not detect a failure in the supplied observations; it does not certify the agent or provide a runtime guardrail.

## Choose a task

| Task | Page |
|---|---|
| Distinguish a supplied observation from an explicit target run | [Execution modes and conversation](architecture/execution-and-conversation.md) |
| Understand expectations, report counts and subset gates | [Rules and release gate](concepts/rules-and-gate.md) |
| Add a probe or locate regression checks | [Probe maintenance](operations/probes-and-tests.md) |
| Maintain this source-linked guide | [OpenWiki setup](../docs/openwiki.md) |

Use the [README](../README.md) and target contract for installation and examples. Review target configuration before using `--execute`: that option authorizes the configured process or network operation in the testbed, and testing must remain within an owned or authorized target.

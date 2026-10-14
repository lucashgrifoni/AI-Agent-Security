---
type: "concept"
title: "Rules and report gate"
description: "Interpret deterministic expectations, executed-probe counts and explicit subset acceptance."
tags: ["rules","sarif","gate"]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-14T19:18:58.715Z
sources:
  - id: openwiki-source-0cf9d872ddf9e6d788ab0e48
    resource: repo://src/aiasec/core/evaluator/rules.py
  - id: openwiki-source-ca798e730a770fb6902687fb
    resource: repo://src/aiasec/core/gate.py
generated: { by: "codex", at: "2026-10-14T19:16:48.664Z" }
---

# Rules and report gate

## Expectations describe an observed property

The evaluator supports regex match/nonmatch and tool-called/tool-not-called expectations over final response or tool arguments. It evaluates each expectation and creates a finding when the expectation fails. Tool-call objects contribute their names to the observation's called-tool list, avoiding missed calls when only detailed call records were supplied ([evaluator](../../src/aiasec/core/evaluator/rules.py#L17-L20), [observation and evaluation](../../src/aiasec/core/evaluator/rules.py#L64-L113)). Probe validation limits `ignore_quoted` to regex checks on the final response; it does not treat JSON argument quotes as quoted prose ([expectation schema](../../src/aiasec/core/probe.py#L36-L64)).

## An empty findings list needs a denominator

The SARIF gate requires a valid recorded executed-probe count and rejects zero executed probes. It counts readable severities and compares them with configured maximum budgets; absent limits are unlimited. A filtered selection is rejected unless the caller explicitly permits a partial report ([gate implementation](../../src/aiasec/core/gate.py#L25-L38), [counts and selection](../../src/aiasec/core/gate.py#L98-L199)). An empty findings list alone cannot prove the suite ran.

## Bound the conclusion

The gate's PASS/FAIL is a decision over recorded findings, executed counts, suite selection and thresholds. Preserve observation mode and selection when comparing runs. A supplied response passing the rules is weaker evidence about a live agent than an exercised target, and neither observes behaviors absent from its harness contract.

Return to [execution modes](../architecture/execution-and-conversation.md) for the observation boundary.

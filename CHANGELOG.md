# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

- Grew the bundled suite to 10 probes across 5 categories: prompt-injection,
  indirect-injection, tool-abuse, data-exfil, and jailbreak.
- Added `aiasec gate` to turn a SARIF report into a PASS/FAIL release verdict
  with per-severity thresholds and an opt-in failing exit code.
- Added a `severity` property to SARIF results so a gate can separate critical
  from high, which the SARIF `level` alone cannot express.
- Added `tests/test_probe_suite.py`: every probe must flag a compromised sample,
  pass against a well-behaved target, and never fire on another probe's sample.
- Added `docs/writing-probes.md` covering the probe schema, the four supported
  expectation kinds, the quality bar, and the contribution checklist.
- Added initial `aiasec` skeleton with probe loading, rules-only evaluation,
  Markdown output, SARIF output, example probes, and unit tests.
- Added a minimal fakeable MCP stdio JSON-RPC adapter with unit tests.
- Added a safe `aiasec mcp tools list` CLI path for local fixtures and stdio config dry-runs.
- Added baseline governance files for security reporting and contribution flow.

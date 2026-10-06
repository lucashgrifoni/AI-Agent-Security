# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

- Fixed the wheel build: the bundled probes were added to the wheel twice, so
  `pip install .` failed. CI now builds the wheel, checks every probe ships in it,
  and runs the quickstart from a clean install.
- The release gate now fails closed when a report does not record how many probes
  were executed, or records zero. Reports carry `probesExecuted`, `probesFailed`,
  and `observationMode` under `runs[].properties.aiasec`, plus `invocations`.
  SARIF written by earlier builds lacks these fields and is rejected by the gate.
- `aiasec run` refuses an empty probe set (exit 2) instead of writing a clean report.
- SARIF results carry a location pointing at the probe file and a stable
  `partialFingerprints` entry, so GitHub code scanning displays and deduplicates
  them. Locations never contain absolute machine paths.
- Probes that name an evaluator other than `rules` are rejected at load time.
  Probe load errors exit 2 with a message instead of a traceback.
- Markdown reports state the observation mode and what a passing probe means.
- Added `aiasec --version`.
- Added CI (lint, tests on Python 3.12 and 3.13, wheel build and smoke test,
  SARIF schema validation), Security CI (Semgrep, CodeQL, pip-audit, Trivy
  secrets, Gitleaks, Dependency Review, CycloneDX SBOM, actionlint), and
  OpenSSF Scorecard.
- SECURITY.md now points to GitHub private vulnerability reporting.
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

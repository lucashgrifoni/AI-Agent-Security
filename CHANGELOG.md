# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

- `timeoutSeconds` now bounds each request as a whole. An MCP target that kept sending
  notifications restarted the wait with each one, and an HTTP target that sent its
  reply a byte at a time restarted it with each byte; either could hang a run and CI
  forever. The deadline starts before the request is written: an MCP target that stops
  reading its input is stopped at the deadline instead of blocking a large request,
  and for HTTP it covers name resolution, connecting and the TLS handshake. An HTTP
  request that timed out during the name lookup is never sent afterwards. The
  `server/discover` probe has the same single deadline.
- A target reply with deeply nested JSON fails the run as a contract error (exit 2);
  it used to escape as a `RecursionError` traceback with exit 1.
- An MCP target can no longer exhaust aiasec's memory: at most 16 of its messages wait
  unread, so a flooding target meets the pipe's backpressure, and a message longer
  than 1,048,576 characters fails the run. `close()` no longer waits on a stream
  another thread is still reading or writing.
- Only the errors MCP 2026-07-28 defines (`-32020`, `-32021`, `-32022`) mark a server
  as modern. Any other code in the reserved `-32020` to `-32099` range, such as
  `-32042` from 2025-11-25, now leads to the `initialize` fallback instead of failing
  the run.
- `LineJsonRpcTransport` accepts the `timeout` that `connect()` passes and enforces
  it; `connect()` used to fail with `TypeError` on it. `send` and `receive` of the
  `JsonRpcTransport` protocol now both take `timeout`, so a custom transport must
  accept it on both.
- An MCP tool result with no `text` content block fails the run. It used to read as
  an empty reply and pass every `regex_not_match` check.
- A probe with an empty `inputs` list is rejected at load time. It used to send
  nothing and pass.
- SARIF results carry `partialFingerprints.primaryLocationLineHash`, the key GitHub
  code scanning matches on, so two failed expectations of one probe stay two alerts.
- `aiasec run` exits 2 when it cannot write the report; it used to exit 1, which reads
  as "a probe failed". The GitHub Action deletes any earlier report before the run and
  accepts exit 1 only when this run wrote a new one.
- The Code of Conduct asks for reserved `.test` hosts only when a payload names a
  network or email destination; payloads without one were in breach as written.
- Release automation: publishing a GitHub Release builds the wheel and sdist, attests
  their provenance, attaches them with a CycloneDX SBOM and the provenance bundle, and
  publishes to PyPI through trusted publishing once the maintainer enables it. See
  `docs/releasing.md`.
- CI egress: Harden-Runner blocks outbound traffic outside each job's allowlist; jobs
  that move artifacts stay in audit mode, with the reason in the workflow.
- Optional Snyk Code job, enabled by the `SNYK_ENABLED` variable and `SNYK_TOKEN`
  secret.
- Five new probes: `output-manipulation` (`html-script-output-001`,
  `sql-payload-output-001`, `shell-payload-output-001`, OWASP LLM05) and
  `mcp-specific` (`tool-description-poisoning-001`, `tool-shadowing-001`, OWASP MCP03),
  for 15 probes in 7 categories. `tool_catalog` is a new input role for poisoned tool
  definitions.
- Probes can declare `metadata.owasp_mcp`; SARIF results and rules carry it as
  `owasp_mcp`. Added `docs/owasp-mapping.md`.
- Fixed the probe-authoring guide: LLM02 is Sensitive Information Disclosure in the
  2025 list; improper output handling is LLM05.
- Multi-turn probes: target mode makes one call per user turn, sending the
  conversation so far with the agent's earlier replies as `assistant` inputs, and
  scores the last reply plus every tool called in any turn. Calls carry `turn` and
  `turns`. `crescendo-001` now reaches the target as three calls. Empty `documents`
  lists are no longer sent.
- HTTP targets: a target config with `"transport": "http"` makes aiasec POST each turn
  to `url` and read `{"response", "toolsCalled"}`. Header values can reference
  environment variables as `${NAME}`; redirects are not followed; replies over 1 MiB
  fail. Reports record `observationMode: http-target`. Added
  `examples/target-http-vulnerable`.
- Target mode speaks MCP 2026-07-28. aiasec probes with `server/discover`, sends the
  protocol version, client info and client capabilities in `_meta` on every request to a
  modern server, and falls back to the `initialize` handshake for a legacy server, as the
  2026-07-28 stdio backward-compatibility rules describe.
- The fallback handshake offers `2025-11-25` instead of `2024-11-05`; a legacy server
  answers with the version it speaks.
- New target config field `protocol` (`auto`, `modern`, `legacy`; default `auto`).
- A result whose `resultType` is not `complete` (for example `input_required`) fails the
  run instead of being read as an empty answer.
- The reference targets are dual-era, and `aiasec run` prints the negotiated version.
- Probes can check the arguments of tool calls: `regex_not_match` with
  `on: tool_arguments` (and an optional `tool_name`) fails when any key, string, number
  or boolean in a call's arguments matches. A target reports arguments by sending
  `{"name", "arguments"}` objects in `toolsCalled`; plain names still work. A call whose
  arguments were not reported fails such a check, and argument values never appear in
  reports or error messages.
- A probe whose expectation sets an empty `tool_name` is rejected at load time. Read as
  a literal name it matched no call, so `tool_not_called` and argument checks passed
  without checking anything.
- Two new probes use it, for 17 in total: `tool-argument-traversal-001` (tool output
  steers `open_file` outside the workspace, OWASP LLM06) and `tool-argument-exfil-001`
  (a retrieved document steers `fetch_url` to a collector, OWASP LLM02). Both map to
  OWASP MCP06. The vulnerable reference targets now report arguments.
- `aiasec run` and `aiasec probes list` select probes with `--category`,
  `--min-severity` and `--probe-id`, combined with AND. A category or id that matches
  no loaded probe, or a selection that matches nothing, exits 2. A filtered run records
  the filters in SARIF (`runs[].properties.aiasec.selection`) and in the Markdown
  summary; an unfiltered report is unchanged.
- README no longer says HTTP targets are left for later.

## 0.1.0 - 2026-10-06

First release.

- `aiasec run --response-file` with a missing file exits 2 with a usage error. It
  used to raise a traceback and exit 1, which reads as "a probe failed".
- `aiasec gate` rejects negative `--max-*` thresholds (exit 2), and `GateThresholds`
  rejects them in the Python API.
- Added a composite GitHub Action (`action.yml`): it installs aiasec from the pinned
  commit, sends the probes to a target, writes SARIF, and fails the job when the gate
  fails. Inputs reach the scripts through environment variables, never interpolated
  into shell. `Action self-test` runs it against both reference targets.
- Documented that the MCP client uses the handshake-based protocol and cannot test a
  server that implements only the 2026-07-28 revision.
- Added target mode: `aiasec run --target <config> --execute` starts an agent harness
  as an MCP stdio server and sends each probe's inputs to it through one tool call,
  then scores that probe against the response and tool calls the target reports.
  Reports record `observationMode: mcp-stdio-target`. The contract is in
  `docs/target-contract.md`.
- `--target` never starts a process without `--execute`, and cannot be combined
  with `--response`, `--response-file`, or `--tools-called`.
- A target that stays silent longer than `timeoutSeconds` (default 30), omits
  `structuredContent.toolsCalled`, returns `isError`, or lacks the agent tool fails
  the run with exit 2.
- Added two deterministic reference targets: `examples/target-mcp-good` passes every
  bundled probe and `examples/target-mcp-vulnerable` fails every one. Tests and CI
  drive both.
- The stdio transport stops the child process before closing its output pipe, so
  closing a hung target no longer blocks until the process exits on its own.
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

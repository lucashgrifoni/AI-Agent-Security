# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

- `aiasec compare --baseline A.sarif --report B.sarif` reports each run's attack
  success rate (failed probes over executed probes) and its change, then compares the
  runs check by check: regressions, failing checks new since the baseline, fixed
  checks, and probes or checks the baseline ran that this run did not. A check is
  identified by what it checks, so reordering a probe file changes nothing.
  `--exit-on-regression` exits 1 on a regression, and on lost coverage unless
  `--allow-partial`. SARIF run properties now list `executedProbes` and
  `executedExpectations`, and each result carries its `expectationId`.
- An HTTP target header that takes its value from an environment variable holding a
  line break now fails before any request, naming the variable. It used to fail
  inside `http.client` with an error that quoted the value, usually a credential, into
  the terminal or CI log.
- Optional LLM judge: `aiasec run --judge judge.json` asks a model, through the same
  model API config, about each probe that declares a `judge` criterion (the unsafe
  behavior in words; `crescendo-001` and `persona-swap-001` have one). Opinions are
  reported next to the rules result, with disagreements marked, and never change the
  results, the gate or the exit code. The agent's output reaches the judge between
  random-code tags, the reply cut at 15,000 characters and the tool calls at 5,000;
  the judge's text is escaped in the Markdown report.
- Model API targets: a target config with `transport` `anthropic`, `openai` (or a
  compatible server) or `ollama` sends each probe turn straight to the model with your
  system prompt and tool definitions. Tool calls the model asks for are recorded with
  their arguments and never executed. The API key comes from an environment variable
  and is only sent over https or to a loopback address. Example configs are in
  `examples/model-targets`; no new dependency.
- The composite action installs aiasec's dependencies from a hash-locked file in its
  own checkout (`.github/requirements/action.txt`), so pinning the action to a commit
  also pins every package it installs. It used to install the newest releases that
  the `pyproject.toml` ranges allowed at run time.
- The CI, security and release workflows install their tools from hash-locked files
  in `.github/requirements` and build without downloading a build backend; the Snyk
  CLI comes from Snyk's setup action pinned by commit, at a fixed version whose
  checksum it verifies. Dependabot refreshes the locks and the action pin.
- `aiasec run --tool-calls-file calls.json` reads observed tool calls, with their
  arguments, in the `toolsCalled` shape of the target contract. With `--tools-called`
  (names only) the two argument probes can only report that the arguments were not
  reported. The file cannot be combined with `--tools-called` or `--target`.
- A tool call reported with a blank name, as a bare string or in an object, is a
  contract error, from a target or from the file. A bare `""` used to pass as a
  call to no tool at all.
- An invalid target config, or `mcp tools list --config`, lists each invalid field
  with its reason on its own line. The message no longer carries pydantic's
  documentation links or the rejected value, which could be a header or env secret.
- **Behavior change:** `aiasec gate` refuses a report produced with `--category`,
  `--min-severity` or `--probe-id` (exit 2), because thresholds met by part of the
  suite say nothing about the rest. Pass `--allow-partial` to gate a subset on
  purpose; the gate's JSON then lists the filters under `selections`. A report whose
  recorded selection cannot be read fails closed.
- The composite action takes `categories`, `min-severity` and `probe-ids` inputs. When
  one is set, the action passes `--allow-partial` to the gate.
- Copyable harness templates in `examples/harness` (MCP stdio and HTTP, standard
  library only) put your own agent behind the target contract: replace `run_agent`
  and point a target config at it. An unconnected template makes `aiasec run` exit 2
  rather than pass. The reference targets now run on these templates, with their two
  agents in `examples/reference_agents.py` instead of three copies.
- Five new probes (22 in total): `issue-comment-injection-001` and
  `email-injection-001` (instructions in an issue body or an email the agent reads),
  `malformed-json-injection-001` (a forged record after a truncated JSON tool result),
  `many-shot-001` (32 fake answered questions before the real one) and
  `system-prompt-leak-001` (OWASP LLM07: a code planted in a `system` input must not
  come back). Harnesses receive a new input role, `system`, which belongs in the
  agent's system prompt.
- The vulnerable reference agent also knows `post_comment`, `forward_email` and
  `run_command`, so it fails the new probes' tool checks as well as their sentinels.
- Probes map to the OWASP Top 10 for Agentic Applications 2026: `metadata.owasp_agentic`
  (21 of 22 bundled probes; no Agentic item covers system prompt leakage) travels into
  SARIF rule and result properties as `owasp_agentic`. `docs/owasp-mapping.md` gives
  the basis for each id in the official document and lists the items the suite does
  not cover.

## 0.2.0 - 2026-10-07

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
  no loaded probe, an empty name in either option (an unset variable, a stray comma), or a selection that matches nothing, exits 2. Probe ids and categories may no longer contain a comma or leading or trailing spaces, which the filters could not select. A filtered run records
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

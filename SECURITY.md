# Security Policy

## Supported Versions

This project is pre-1.0. Security fixes target the `master` branch and the latest
published release.

## Reporting a Vulnerability

Report suspected vulnerabilities privately through GitHub:
[Report a vulnerability](https://github.com/lucashgrifoni/AI-Agent-Security/security/advisories/new).

Please do not open a public issue for a suspected vulnerability. Include the affected
version or commit, reproduction steps, expected impact, and any relevant logs with
secrets removed.

Reports are handled on a best-effort basis by a single maintainer.

Do not include real credentials, private customer data, tenant identifiers, or
live exploit payloads in reports or issues.

## Scope

In scope:

- Probe parsing and execution logic.
- The release gate, including any way to make it pass a report it should fail.
- SARIF and Markdown report generation.
- The MCP adapter and its process handling.

Out of scope:

- Testing third-party agents, MCP servers, or LLM providers without
  authorization.
- Claims that an agent is secure because this testbed passes. A passing run means
  the bundled probes did not detect a failure; it is not a security guarantee.

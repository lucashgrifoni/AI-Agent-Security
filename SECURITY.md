# Security Policy

## Supported Versions

This project is in pre-release bootstrap. Security fixes target the current
main development line until the first tagged release exists.

## Reporting a Vulnerability

Report suspected vulnerabilities privately to the project maintainer before
publishing details. Include the affected version or commit, reproduction steps,
expected impact, and any relevant logs with secrets removed.

Do not include real credentials, private customer data, tenant identifiers, or
live exploit payloads in public issues.

## Scope

In scope:

- Probe parsing and execution logic.
- SARIF, Markdown, and JSON report generation.
- Target adapter behavior once real adapters are added.

Out of scope:

- Testing third-party agents, MCP servers, or LLM providers without
  authorization.
- Claims that an agent is secure because this testbed passes.


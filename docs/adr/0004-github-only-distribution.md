# 0004. Releases are distributed only through GitHub

- Status: accepted
- Date: 2026-11-23 (#37)

## Context

A package index adds a second channel to secure and a name that, once registered,
stays registered. Each GitHub Release already carries the wheel, the sdist, a CycloneDX
SBOM and a signed build provenance attestation.

## Decision

aiasec is installed from a release tag (`pip install git+https://...@vX.Y.Z`) or from
the attested wheel attached to the GitHub Release. The publish workflow has no PyPI or
TestPyPI job.

## Consequences

- Users verify what they install with `gh attestation verify` before installing it.
- `pip install ai-agent-security-testbed` fails, and the README says so.

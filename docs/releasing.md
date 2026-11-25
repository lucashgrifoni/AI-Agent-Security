# Releasing

Maintainer guide. Contributors do not need it.

## Distribution

Releases are distributed only through GitHub: the signed tag, the GitHub Release and
its attested assets, and the container image in the GitHub Container Registry
(`ghcr.io/lucashgrifoni/ai-agent-security-testbed`). The package is not published to
PyPI.

## One-time setup

Optional, and it needs the maintainer's own account:

| What | Where | Then |
|---|---|---|
| Snyk Code (optional) | create a Snyk API token | add the secret `SNYK_TOKEN` and set the variable `SNYK_ENABLED` to `true` |
| Container package visibility | after the first release that pushes the image, open the `ai-agent-security-testbed` package under the account's Packages | check that it is linked to this repository, and make it public so that `docker pull` and `gh attestation verify oci://...` work without a login |

## Cutting a release

1. In `CHANGELOG.md`, rename the `Unreleased` heading to the new version and date and
   add a new, empty `## Unreleased` heading above it (`tests/test_changelog.py` checks
   there is always exactly one, first). Bump `version` in `pyproject.toml` and
   `__version__` in `src/aiasec/__init__.py`, and the release tag in the README install
   commands. Merge that through a pull request; the required checks must pass.
2. Wait for CI on the merge commit to pass.
3. Tag the merge commit with a signed tag and push it:
   `git tag -s vX.Y.Z -m "aiasec X.Y.Z"` then `git push origin vX.Y.Z`.
4. Publish the GitHub Release for the tag with the release notes.
5. The `Publish` workflow then builds the wheel and sdist, stops if the tag,
   `pyproject.toml`, `__version__` and the built metadata do not name one version,
   attests their provenance, and attaches the wheel, sdist, CycloneDX SBOM
   (`aiasec.cdx.json`) and provenance bundle (`aiasec.intoto.jsonl`) to the release.
   It never replaces a file that already exists: a retried run fails instead, so a
   verified asset never changes. To retry after a partial failure, delete the release
   assets first, then re-run the failed workflow run.
6. In the same workflow, the `container` job builds the image from the `Dockerfile`,
   stops if the tag and `pyproject.toml` do not name one version, generates a
   CycloneDX SBOM of the image, and pushes `:X.Y.Z` and `:latest` to GHCR. It then
   pushes a build provenance attestation and an SBOM attestation for the image digest
   to the registry. It is the only job with `packages: write`. It refuses to push a
   version tag that already exists, so to retry it, delete that package version
   first, then re-run the failed job.

## Verifying a release

```bash
gh release download vX.Y.Z -R lucashgrifoni/AI-Agent-Security
gh attestation verify ai_agent_security_testbed-X.Y.Z-py3-none-any.whl -R lucashgrifoni/AI-Agent-Security
```

The attestation names the workflow and the commit that built the file.

For the container image:

```bash
gh attestation verify oci://ghcr.io/lucashgrifoni/ai-agent-security-testbed:X.Y.Z -R lucashgrifoni/AI-Agent-Security
gh attestation verify oci://ghcr.io/lucashgrifoni/ai-agent-security-testbed:X.Y.Z -R lucashgrifoni/AI-Agent-Security \
  --predicate-type https://cyclonedx.org/bom
```

The base image is pinned by digest in the `Dockerfile`; Dependabot's `docker` entry
proposes digest updates. Pull requests build the image and run it in the CI
`container` job without pushing.

## CI network policy

Harden-Runner blocks outbound traffic outside each job's allowlist. Jobs that move
artifacts between jobs or attest builds (CI build, SBOM, Scorecard, Publish) stay in
audit mode, because those GitHub endpoints rotate and cannot be listed exactly. When a
job fails with a blocked endpoint, add that host to the job's `allowed-endpoints`
after checking why the job needs it.

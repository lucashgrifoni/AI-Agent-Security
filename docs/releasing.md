# Releasing

Maintainer guide. Contributors do not need it.

## One-time setup

These need the maintainer's own accounts, so they are manual.

| What | Where | Then |
|---|---|---|
| PyPI trusted publisher | pypi.org, Account settings > Publishing > Add a pending publisher: project `ai-agent-security-testbed`, owner `lucashgrifoni`, repository `AI-Agent-Security`, workflow `publish.yml`, environment `pypi` | set the repository variable `PYPI_PUBLISH` to `true` |
| TestPyPI trusted publisher (optional) | test.pypi.org, same form, environment `testpypi` | set `TESTPYPI_PUBLISH` to `true` |
| Snyk Code (optional) | create a Snyk API token | add the secret `SNYK_TOKEN` and set the variable `SNYK_ENABLED` to `true` |

No API token is stored for PyPI: trusted publishing exchanges a short-lived OIDC token.
The `pypi` environment requires the maintainer's approval and only deploys from `v*`
tags; `testpypi` only deploys from `master`.

## Cutting a release

1. In `CHANGELOG.md`, rename the `Unreleased` heading to the new version and date and
   add a new, empty `## Unreleased` heading above it (`tests/test_changelog.py` checks
   there is always exactly one, first). Bump `version` in `pyproject.toml` and
   `__version__` in `src/aiasec/__init__.py`. Merge
   that through a pull request; the required checks must pass.
2. Wait for CI on the merge commit to pass.
3. Tag the merge commit with a signed tag and push it:
   `git tag -s vX.Y.Z -m "aiasec X.Y.Z"` then `git push origin vX.Y.Z`.
4. Publish the GitHub Release for the tag with the release notes.
5. The `Publish` workflow then builds the wheel and sdist, stops if the tag,
   `pyproject.toml`, `__version__` and the built metadata do not name one version,
   attests their provenance,
   attaches the wheel, sdist, CycloneDX SBOM (`aiasec.cdx.json`) and provenance bundle
   (`aiasec.intoto.jsonl`) to the release, and then, once approved in the `pypi`
   environment, publishes the same files to PyPI. Neither step replaces a file that
   already exists: a retried run fails instead, so PyPI and the release never serve
   different bytes. To retry after a partial failure, delete the release assets first.

To publish by hand (`Publish` > Run workflow), run it on the release tag: a PyPI
publish without a tag, or on a tag that does not match the package version, stops
before anything is uploaded.

## Verifying a release

```bash
gh release download vX.Y.Z -R lucashgrifoni/AI-Agent-Security
gh attestation verify ai_agent_security_testbed-X.Y.Z-py3-none-any.whl -R lucashgrifoni/AI-Agent-Security
```

The attestation names the workflow and the commit that built the file.

## CI network policy

Harden-Runner blocks outbound traffic outside each job's allowlist. Jobs that move
artifacts between jobs or attest builds (CI build, SBOM, Scorecard, Publish) stay in
audit mode, because those GitHub endpoints rotate and cannot be listed exactly. When a
job fails with a blocked endpoint, add that host to the job's `allowed-endpoints`
after checking why the job needs it.

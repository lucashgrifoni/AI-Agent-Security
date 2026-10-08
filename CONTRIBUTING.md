# Contributing

## Development Setup

Use Python 3.12 or newer.

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
```

CI installs the same tools from hash-locked files. To reproduce its environment exactly:

```bash
python -m pip install --require-hashes -r .github/requirements/ci.txt
python -m pip install --no-deps --no-build-isolation -e .
```

The `.txt` files in `.github/requirements` are generated from the `.in` files next to
them; the first lines of each `.txt` record the `uv pip compile` command. When you add a
dependency to `pyproject.toml`, add it to `action.in` (runtime) or `ci.in` (dev) and
regenerate; `tests/test_ci_requirements.py` fails until you do. Semgrep has its own
directory, `.github/requirements-semgrep`, because Dependabot moves a package to the same
version in every lock of a directory and semgrep pins some of its dependencies below the
versions the other locks use.

## Contribution Rules

- Keep probes deterministic where possible.
- Do not add probes that require attacking systems you do not own or have
  permission to test.
- Do not commit tokens, transcripts with sensitive data, real customer prompts,
  or private MCP server details.
- Prefer rules-only evaluators before adding LLM-as-judge behavior.
- Add tests for new probe schema behavior, evaluators, and output formats.

## Pull Request Checklist

- Tests pass locally.
- Ruff passes locally.
- README or docs are updated when behavior changes.
- New probes include category, severity, references, and clear expectations.


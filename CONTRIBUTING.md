# Contributing

## Development Setup

Use Python 3.12 or newer.

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
```

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


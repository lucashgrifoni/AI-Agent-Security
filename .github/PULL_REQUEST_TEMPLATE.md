## Summary

- What changed?
- Why was the change needed?

## Validation

- [ ] `python -m pytest`
- [ ] `python -m ruff check .`
- [ ] For a new or changed probe: a compromised sample in `tests/test_probe_suite.py`, and the probe fails against `examples/target-mcp-vulnerable` and passes against `examples/target-mcp-good`
- [ ] For changes to the gate, SARIF, or target driver: a test that fails without the change
- [ ] For packaging or workflow changes: `python -m build` and the CI smoke test

## Release / security impact

- [ ] No public contract changed (CLI flags, exit codes, SARIF properties, probe schema, target contract, action inputs)
- [ ] Breaking change documented in CHANGELOG.md, if applicable
- [ ] Security-sensitive behavior reviewed
- [ ] Docs updated, if applicable
- [ ] The description does not imply that a passing run means an agent is secure

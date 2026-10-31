## Summary

<!-- One or two sentences: what changes and why. -->

## Type of change

- [ ] Bug fix (script or behavior)
- [ ] New tool / technique module
- [ ] Schema or contract change (replay-log, finding-triage, finding-to-control, roe-consent)
- [ ] Evidence run (replay log + triage + report)
- [ ] Documentation
- [ ] Tooling / repo hygiene

## Guardrail / ADR cited

<!-- Cite the guardrail(s) (docs/guardrails.md, G-1…G-9) and/or ADR this change serves or is bound by. -->

## Checklist

- [ ] Full test suite green (`python -m pytest -q`).
- [ ] `git diff --check` clean (no trailing whitespace / conflict markers).
- [ ] G-6: no operator paths, tokens, real UPNs, or tenant IDs committed outside evidence files (samples/replay-log, samples/finding-triage, docs/reports); scripts, tests, and docs use placeholders such as `<lab-tenant-id>`. The Graph CLI client `14d82eec…` is a public Microsoft ID and is allowed.
- [ ] `CHANGELOG.md` updated under `## [Unreleased]`.
- [ ] Docs / docstrings updated if behavior, required scopes, or prerequisites changed.
- [ ] Squash-merge; no GitHub Issues opened for task tracking; no `Closes #N` auto-close keyword.

## Test evidence

<!-- pytest result, or the replay-log / report artifact for an evidence run. Redact identifiers. -->

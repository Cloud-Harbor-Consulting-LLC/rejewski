# Contributing to Rejewski

Thanks for your interest in Rejewski. This project is developed under Project Harbor Sonar (PHS), Cloud Harbor Consulting's flagship security agent build.

## Status

The repo has been **public since Mon Oct 26, 2026** (v1.0), and external contributions are open. Before the flip, contributions came from the Cloud Harbor Consulting build team only. The conventions below apply to every contributor. To discuss an idea before writing code, such as which attack stage Rejewski should emulate next, start a thread in [GitHub Discussions](https://github.com/Cloud-Harbor-Consulting-LLC/rejewski/discussions).

## Code of Conduct

This project adopts the [Contributor Covenant v2.1](./CODE_OF_CONDUCT.md). All participants are expected to uphold it. Report unacceptable behavior to <derek.morgan@cloudharborconsulting.cloud>.

## Branching model

Branch off `main`. Names follow **ADR 0002 §6**:

- `feature/<kebab-case-summary>` — new work
- `fix/<kebab-case-summary>` — corrections
- `docs/<kebab-case-summary>` — documentation-only changes

Never embed an ADR or backlog ID in a branch name — branches are ephemeral, IDs are durable (ADR 0002 §6). Keep each branch scoped to one reviewable change.

## Commit messages

Use a Conventional-Commits-style subject: `type(scope): summary`, e.g. `feat(report): add ROI section`, `fix(alerts): correct $select field`, `docs(readme): add Design principles section`. Common types: `feat`, `fix`, `docs`, `style`, `test`, `refactor`, `chore`. Keep the subject imperative and under ~72 characters; put the rationale in the body.

There is **no DCO `Signed-off-by` requirement**. AI-assisted commits carry a `Co-Authored-By:` trailer identifying the assisting model.

## Pull request conventions

These are Rejewski's **standing PR conventions** — follow them for every change:

- **Squash and merge**, then delete the branch. One PR is one squashed commit on `main`.
- **No GitHub Issues.** Work is tracked in the PHS Master Plan / Planner, not GitHub Issues. Do not open Issues to track tasks. (GitHub *issue templates* still exist for external bug/doc/policy reports — see [Issue templates](#issue-templates).)
- **No `Closes #N` / `Fixes #N`** auto-close keywords in commits or PR descriptions — there are no tracking Issues to close.
- Keep PRs **small and focused** — one coherent change per PR.
- The PR description states **what changed, why, and how it was verified** (which acceptance criteria it meets).
- Before opening a PR: the **full test suite is green**, `git diff --check` is clean, and the branch is rebased/current with `main`.
- Sign-off / attribution: end commit messages with the `Co-Authored-By:` trailer when AI-assisted; end PR descriptions with the standard generation trailer.

## Testing expectations

Rejewski ships with a Python test suite (`pytest`). Every PR must keep it **fully green** — the current baseline is **235 passing**. The `tests` workflow (`.github/workflows/tests.yml`) runs the suite from a clean install on every pull request and every push to `main`, on Ubuntu (Python 3.11 and 3.13) and Windows (Python 3.13). It needs no secrets and makes no Graph calls.

```bash
python -m venv .venv
source .venv/Scripts/activate        # macOS/Linux: source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest -q
```

Add or update tests with any behavioral change. Schema, tool, and report changes must carry matching test coverage; docs-only changes keep the suite green without new tests. Also run `git diff --check` (no trailing-whitespace or conflict markers) before opening the PR.

## Issue templates

Bug reports, documentation fixes, and feature requests use the templates in [`.github/ISSUE_TEMPLATE/`](./.github/ISSUE_TEMPLATE/):

- **Bug report** (`bug_report.yml`) — a tool script, core script, schema, or document behaves incorrectly.
- **Documentation fix** (`documentation_fix.yml`) — a correction, clarification, or improvement to documentation.
- **Feature request** (`feature_request.yml`) — a new attack stage, ATT&CK technique, tool surface, or report capability. It asks for the stage, the use case, and confirmation that testing stays on tenants the requester owns or is authorized to assess.
- The template chooser is configured in `config.yml`.

These templates are for **external reports on the public repo**; they do not change the internal "no GitHub Issues for task tracking" convention above.

## Architecture Decision Records (ADRs)

Durable design decisions are recorded as ADRs under [`docs/adr/`](./docs/adr/). Write one when a decision is reversible only by a superseding decision — a guardrail change, an identity/auth model, a schema contract, a naming or process rule.

- Copy [`docs/adr/_template.md`](./docs/adr/_template.md) and follow the section layout (Context, Decision, Rationale, Consequences, Alternatives, Compliance, Change Log).
- Numbering and reference style follow **ADR 0002 (Naming Convention)**: four-digit zero-padded IDs, sequential, **never reused or renumbered**; filename `NNNN-kebab-case-title.md`; in-text reference `ADR 0007` (with a space). Renaming an artifact is a Supersede event, not a rewrite.
- New ADRs land as `Status: Proposed` and move to `Accepted` when adopted.

## Security disclosure

To report a security vulnerability **in Rejewski's own code** (not findings Rejewski produces against a target tenant), follow [SECURITY.md](./SECURITY.md). Please do **not** open a public issue or PR for a suspected vulnerability — email <derek.morgan@cloudharborconsulting.cloud> instead.

## Questions

Contact <derek.morgan@cloudharborconsulting.cloud>.

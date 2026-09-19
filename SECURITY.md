# Security Policy

This policy covers security vulnerabilities **in Rejewski's own code** — the toolkit, its scripts, schemas, and runtime. It does **not** cover the findings Rejewski produces when it assesses a target tenant; those are the operating team's to triage under the Rules of Engagement ([docs/roe-consent-flow.md](./docs/roe-consent-flow.md)), not a vulnerability in this project.

## Reporting a vulnerability

**Email <derek.morgan@cloudharborconsulting.cloud> with the subject line `Rejewski security`.**

Please do **not** open a public GitHub issue or pull request for a suspected vulnerability, and do not disclose it publicly until it has been resolved and coordinated.

Include what you can:

- affected file(s), script, or component and the version / commit;
- a description of the issue and its impact (what an attacker could do);
- steps to reproduce, or a proof-of-concept, if you have one;
- any suggested remediation.

Do not include live credentials, tokens, or real tenant data in a report. Rejewski's own guardrails apply — see [docs/guardrails.md](./docs/guardrails.md) (G-6 redaction).

## Scope during the private build

Rejewski is a **private build through Sat Oct 24, 2026**, going **public Mon Oct 26, 2026**. Until the public flip:

- The repository and its history are private; reports are expected from the Cloud Harbor Consulting build team and named collaborators via the email above.
- There is no public advisory or CVE process yet. Fixes are handled directly on `main` and noted in [CHANGELOG.md](./CHANGELOG.md).
- Best-effort acknowledgement is within **3 business days**.

This section **expands at public launch** into a full coordinated-disclosure process — a stated response/remediation timeline, a supported-versions table, and GitHub private security advisories — appropriate for a public repository.

## Supported versions

Rejewski is pre-release and under active development. Only the current `main` branch is supported; there are no released versions or backports during the private build.

## Handling

Reports are triaged privately. A confirmed vulnerability is fixed on `main` with matching test coverage where applicable, and the fix is recorded in the changelog. The reporter is credited if they wish once the repository is public.

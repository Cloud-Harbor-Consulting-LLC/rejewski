# Security Policy

This policy covers security vulnerabilities **in Rejewski's own code**: the toolkit, its scripts, schemas, and runtime. It does **not** cover the findings Rejewski produces when it assesses a tenant; those belong to the tenant's owner and the operator who ran the assessment under the Rules of Engagement ([docs/roe-consent-flow.md](./docs/roe-consent-flow.md), [docs/external-auth.md](./docs/external-auth.md)).

## Reporting a vulnerability

Report privately, by either route:

- **GitHub private vulnerability reporting:** the **Report a vulnerability** button on this repository's **Security** tab.
- **Email:** <derek.morgan@cloudharborconsulting.cloud> with the subject line `Rejewski security`.

Do **not** open a public issue, pull request, or discussion for a suspected vulnerability, and do not disclose it publicly until a fix is available or the disclosure date below has passed.

Include what you can:

- the affected file, script, or component, and the release or commit;
- a description of the issue and its impact (what an attacker could do);
- steps to reproduce, or a proof of concept;
- any suggested remediation.

Do not include live credentials, tokens, or real tenant data in a report. Rejewski's own guardrails apply; see [docs/guardrails.md](./docs/guardrails.md) (G-6).

## What is in scope

Issues in Rejewski's code that weaken its safety controls are the most important to report, for example:

- running against a tenant without a consent record that authorizes it, or bypassing any check in `scripts/roe_gate.py` (G-1);
- a tool issuing a write request to Microsoft Graph, or recording one as valid evidence (G-1, G-3);
- tokens, passwords, or other secrets reaching a replay log, report, or console output (G-5, G-6);
- a token cache surviving the end-of-run teardown (G-8);
- a dependency vulnerability that affects how Rejewski runs.

Out of scope:

- findings in a tenant that Rejewski assessed (those are the point of the tool);
- vulnerabilities in Microsoft services or Microsoft Graph itself; report those to the [Microsoft Security Response Center](https://msrc.microsoft.com/);
- issues that require an attacker who already controls the operator's workstation or the `.env` file.

## Response

- **Acknowledgement** within 3 business days.
- **Status updates** at least every 14 days while the report is open.
- **Coordinated disclosure:** a confirmed vulnerability is fixed on `main` with matching test coverage, released, and published as a GitHub security advisory. The reporter is credited if they wish. If no fix is available after 90 days, the reporter may disclose, and the advisory is published with the known mitigations.

## Supported versions

| Version | Supported |
|---|---|
| Latest 1.0.x release | Yes |
| `main` | Yes (fixes land here first) |
| Release candidates (`v1.0-rc.*`) | No |

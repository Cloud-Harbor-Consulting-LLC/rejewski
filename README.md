# Rejewski

Agentic Microsoft 365 tenant pen-testing assistant. A friendly threat actor that emulates recon and discovery TTPs against a tenant the operator owns or has written authorization to assess, and produces findings mapped to specific M365 controls.

> **Status:** Private build through Sat Oct 24, 2026. Public launch Mon Oct 26, 2026. See [Project Harbor Sonar Master Plan](https://cloudharborconsulting.sharepoint.com/:t:/s/CHC-Ops/IQBCENuicazZQK8l9Z4XeVFKAQNQEEy11y6ehgv9eb__az0?e=9rw5oh) for build cadence and milestones.

## What it does

Rejewski runs as an agentic loop on top of the Claude Agent SDK. Each run:

1. Prompts the operator for Rules of Engagement consent and records the consent.
2. Executes read-only Microsoft Graph and Defender / Purview queries against the target tenant.
3. Maps each finding to a specific M365 control (Conditional Access policy, Defender setting, Purview label, Intune compliance check, and so on).
4. Emits a structured replay log so every run reproduces.
5. Renders an HTML report with severity scores and business-impact lines per finding.

## Quickstart

**Prerequisites**

- Python 3.11+ and `git`.
- Access to the `cloudharbordemo` Azure sandbox tenant with a seeded operator account. Guardrail G-1 locks every run to that tenant; Rejewski runs read-only against it only (see [Rules of Engagement](#rules-of-engagement)).

**Install**

```bash
git clone https://github.com/Cloud-Harbor-Consulting-LLC/rejewski.git
cd rejewski
python -m venv .venv
source .venv/Scripts/activate      # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

**Configure**

Create a `.env` file in the repo root (it is gitignored — never commit it) with the sandbox operator's credentials:

```
AZURE_TENANT_ID=76b87c33-6178-4ff9-94a7-164792c8e4c6
COMPROMISED_USER_UPN=<seeded-operator>@cloudharbordemo.onmicrosoft.com
COMPROMISED_USER_PASSWORD=<password>
# FOCI_CLIENT_ID is optional; defaults to Microsoft Graph Command Line Tools (14d82eec).
```

**Run**

Each tool acquires a delegated, read-only Graph token on its first call (against the borrowed FOCI client), caches it, and writes a structured replay-log entry:

```bash
python scripts/tool_list_users.py --run-id demo-001
```

Then consolidate the run's replay-log entries and render the HTML report:

```bash
python scripts/consolidate_run.py --run-id demo-001
python scripts/generate_html_report.py --replay-log <consolidated-log>.json --output report.html
```

The full agentic loop (Claude Agent SDK) is driven by `python scripts/rejewski_runtime.py`, which reads `rejewski.config.json` and enforces the G-1 sandbox-tenant check before any Graph call.

## Rules of Engagement

Every run is gated by a per-run consent prompt. The prompt summarizes the target tenant, the techniques in scope, the expected duration, and the operator identity, and the operator confirms by echoing a generated run ID back verbatim — any other input is treated as a decline, and a declined or aborted run terminates before any network egress. The consent record is written as the first entry of the run's replay log and binds every downstream entry by `run_id`. Sprint 1's exit floor is five consented runs logged end-to-end.

The self-test consent mechanic is specified in [docs/roe-consent-flow.md](docs/roe-consent-flow.md); the authorization flow for a third-party tenant assessment (and the durable long-term consent-record archive) is in [docs/external-auth.md](docs/external-auth.md); the governing decision is [ADR 0001 — Rules of Engagement](docs/adr/0001-rules-of-engagement.md).

## Guardrails

Rejewski runs under nine operational guardrails (**G-1 through G-9**), each enforced in code, the SDK, or PR review and cited by number from the technique modules. In brief: every run is locked to the `cloudharbordemo` sandbox tenant (**G-1**) with no tenant app registration and a single borrowed Microsoft first-party FOCI client (**G-2**, **G-4**); token requests carry read-only delegated Graph scopes only (**G-3**); every invocation captures mandatory evidence (**G-5**) with directory identifiers redacted in the public repo (**G-6**); the sandbox holds only seeded test data, never real users (**G-7**); sessions are time-boxed (**G-8**); and enumeration volume is capped per call (**G-9**).

Full rule text — statement, rationale, enforcement, scope, and exceptions for each — is in [docs/guardrails.md](docs/guardrails.md); the guardrail set is authorized by [ADR 0001](docs/adr/0001-rules-of-engagement.md).

## Naming

Rejewski is named for Marian Rejewski (1905-1980), the Polish mathematician who in December 1932 first reconstructed the internal wiring of the German military Enigma cipher machine using permutation theory, without access to a captured device. Working with fellow Polish Cipher Bureau cryptologists Jerzy Różycki and Henryk Zygalski, he built the foundation later extended by British codebreakers at Bletchley Park. The name honors that legacy of applying rigorous method to previously "unbreakable" security systems. Trademark clearance research is complete internally; a formal opinion from outside counsel is pending as of this writing.

Full rationale and heritage attribution: [ADR 0007 — Naming Rationale and Heritage Attribution](docs/adr/0007-naming-rationale.md).

## Contributing

See CONTRIBUTING.md. Full v1 lands in Sprint 5.

## License

MIT. See LICENSE.

---

Part of [Cloud Harbor Consulting](https://cloudharborconsulting.cloud) M365 security tooling.

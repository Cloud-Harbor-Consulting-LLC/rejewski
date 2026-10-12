# Rejewski

Read-only Microsoft 365 adversary-emulation toolkit. A friendly threat actor that emulates recon and discovery TTPs against a tenant the operator owns or has written authorization to assess, and produces findings mapped to specific M365 controls.

> **Status:** Private build through Sat Oct 24, 2026. Public launch Mon Oct 26, 2026. See [Project Harbor Sonar Master Plan](https://cloudharborconsulting.sharepoint.com/:t:/s/CHC-Ops/IQBCENuicazZQK8l9Z4XeVFKAQNQEEy11y6ehgv9eb__az0?e=9rw5oh) for build cadence and milestones.

## What it does

Rejewski is a set of read-only Microsoft Graph tools. They sign in as a seeded test account in a sandbox tenant and record what that account can read. Each run:

1. Starts with a Rules of Engagement consent record, written as the first entry of the run's replay log.
2. Executes read-only Microsoft Graph and Defender / Purview queries against the target tenant.
3. Maps each finding to a specific M365 control (Conditional Access policy, Defender setting, Purview label, Intune compliance check, and so on).
4. Emits a structured replay log so every run reproduces.
5. Renders an HTML report with severity scores and business-impact lines per finding.

An agent layer built on the Claude Agent SDK ships alongside the tools. `scripts/rejewski_runtime.py` loads the SDK options from `rejewski.config.json`, and `scripts/reasoning_loop.py` routes each recon step to a model and stamps the replay-log entry with the model it chose. In v1.0 that layer runs offline: the operator runs the tools, and connecting them to the agent needs a Graph MCP server, which `rejewski.config.json` does not configure.

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

`scripts/rejewski_runtime.py` loads `rejewski.config.json` into Claude Agent SDK options and refuses a config that names an out-of-scope technique. The G-1 sandbox-tenant lock is enforced by `scripts/replay_log.py`, which refuses any entry whose tenant is not `cloudharbordemo`. Each tool writes its token event before its Graph call, so a tool pointed at another tenant stops after token acquisition and before its first Graph call.

## Usage example — a full comprehensive run

The Quickstart above runs a single tool. A real assessment exercises **all 14 tool surfaces in one consented session**, consolidates them under a single run ID, and renders one report. This is the shape of the canonical **R014** run committed as evidence in this repo.

**1. Consent once for the run.** Follow the ROE prompt ([docs/roe-consent-flow.md](docs/roe-consent-flow.md)) and use a single run ID for the whole session — here `R014`.

**2. Run every tool surface, tagged to that run ID.** Each tool authenticates once (then reuses the cached token) and writes its own entries to `replay-logs/`:

```bash
for tool in tool_list_users tool_list_applications tool_list_service_principals \
            tool_list_role_assignments tool_list_oauth_grants tool_list_groups \
            tool_list_ca_policies tool_dfi_health tool_intune_devices \
            tool_purview_labels tool_signin_logs tool_list_security_alerts \
            tool_list_sharepoint_sites tool_list_inbox_rules; do
  python scripts/$tool.py --run-id R014
done
```

**3. Consolidate the run** into one replay log. `consolidate_run.py` reads every `replay-logs/` entry whose `run_id` matches, writes `samples/replay-log/<run-id>.json`, and unconditionally redacts the operator-local cache path (G-6):

```bash
python scripts/consolidate_run.py --run-id R014
```

**4. Render the HTML report** from the consolidated log plus the committed finding records (`--finding-dir`/`--mapping-dir`/`--roi-model` default to the `samples/` sets):

```bash
python scripts/generate_html_report.py \
  --replay-log samples/replay-log/R014.json \
  --output docs/reports/replay-report-R014.html
```

The committed result is **[docs/reports/replay-report-R014.html](docs/reports/replay-report-R014.html)**: a single self-contained report — graph calls, token events, findings, control mappings, and a per-finding ROI section — from one 14-surface run, with **9 distinct findings, each carrying a severity score and an ROI line**. Fourteen surfaces collapse to nine findings because several map to the same ATT&CK technique (five to T1087.004 account discovery, two to T1654 log enumeration), and `tool_list_inbox_rules` is a documented block (the delegated self-mailbox boundary), not a finding.

## Rules of Engagement

Every run starts with a consent record. [docs/roe-consent-flow.md](docs/roe-consent-flow.md) specifies the consent prompt: it summarizes the target tenant, the techniques in scope, the expected duration, and the operator identity, and the operator confirms by echoing a generated run ID back verbatim. In v1.0 the prompt is specified but not yet wired into the tools. The operator writes the record before running the tools (`scripts/write_consent_record.py` builds a schema-valid one), and no tool refuses to run without one, so the record is a procedural control checked at review. The consent record is the first entry of the run's replay log and binds every downstream entry by `run_id`. Sprint 1's exit floor is five consented runs logged end-to-end.

The self-test consent mechanic is specified in [docs/roe-consent-flow.md](docs/roe-consent-flow.md); the authorization flow for a third-party tenant assessment (and the durable long-term consent-record archive) is in [docs/external-auth.md](docs/external-auth.md); the governing decision is [ADR 0001 — Rules of Engagement](docs/adr/0001-rules-of-engagement.md).

## Guardrails

Rejewski runs under nine operational guardrails (**G-1 through G-9**), each enforced in code, the SDK, or PR review and cited by number from the technique modules. In brief: every run is locked to the `cloudharbordemo` sandbox tenant (**G-1**) with no tenant app registration and a single borrowed Microsoft first-party FOCI client (**G-2**, **G-4**); token requests carry read-only delegated Graph scopes only (**G-3**); every invocation captures mandatory evidence (**G-5**) with directory identifiers redacted in the public repo (**G-6**); the sandbox holds only seeded test data, never real users (**G-7**); sessions are time-boxed (**G-8**); and enumeration volume is capped per call (**G-9**).

Full rule text — statement, rationale, enforcement, scope, and exceptions for each — is in [docs/guardrails.md](docs/guardrails.md); the guardrail set is authorized by [ADR 0001](docs/adr/0001-rules-of-engagement.md).

## Design principles

These are the program-level **operating principles** from the [Project Harbor Sonar Master Plan](https://cloudharborconsulting.sharepoint.com/:t:/s/CHC-Ops/IQBCENuicazZQK8l9Z4XeVFKAQNQEEy11y6ehgv9eb__az0?e=9rw5oh) §2 — the *why* behind how the project is run (scope, cadence, launch strategy).

> **Different numbering scheme from the Guardrails above.** These principles use the Master Plan's own `G1`–`G8` labels; they are **not** the code-enforced `G-1` through `G-9` in the [Guardrails](#guardrails) section above. Guardrails answer "what does the code enforce"; these principles answer "why does the project operate the way it does." Don't conflate `G4` here (Threat Actor Emulation) with `G-4` above (FOCI client allowlist), etc.

- **G1 — Read-Only.** The agent never writes to the target tenant: no policy creation, role assignment, group-membership change, or user-property change; Microsoft Graph calls are limited to GET.
- **G2 — No Credential Harvesting.** No password spray, no theft or replay of another user's or device's tokens, no MFA-bypass attempts, and no session-cookie capture. The tools sign in as a seeded sandbox test account with that account's own password (ROPC), then silently reuse that account's own cached refresh token. The T1550.001 module records that reuse as evidence of what a stolen refresh token allows.
- **G3 — Telemetry-Aware and Replayable.** Every run produces a structured replay log (prompts, tool calls, results, timestamps) so findings reproduce; the agent assumes Defender XDR audit telemetry sees every call.
- **G4 — Threat Actor Emulation.** The agent emulates the recon and discovery TTPs of a real-world threat actor, mapped to MITRE ATT&CK Enterprise — no persistence, no lateral movement off M365, no defense evasion.
- **G5 — Rules of Engagement.** Every run starts with an ROE prompt and a consent record; the operator confirms tenant ownership or written authorization and scope boundaries, and acknowledges G1–G4.
- **G6 — Private Build, Public Launch.** Repo, boards, and build artifacts stay private through Sat Oct 24, 2026; public launch is Mon Oct 26, 2026, with a single high-level teaser post on Sat Aug 1, 2026.
- **G7 — M365-Wide Control Inventory Mapping.** Every finding maps to a specific M365 control (Conditional Access policy, Defender setting, Purview label, Intune compliance check, and so on); the agent does not surface findings without a control mapping.
- **G8 — Measure at Sprint Boundaries.** Build KPIs are collected weekly and sprint-checkpoint KPIs reviewed every four weeks; v1.1 backlog grooming happens at sprint checkpoints, never mid-sprint.

Source: Project Harbor Sonar Master Plan §2 (Operating Guardrails), linked in the status banner above.

## Naming

Rejewski is named for Marian Rejewski (1905-1980), the Polish mathematician who in December 1932 first reconstructed the internal wiring of the German military Enigma cipher machine using permutation theory, without access to a captured device. Working with fellow Polish Cipher Bureau cryptologists Jerzy Różycki and Henryk Zygalski, he built the foundation later extended by British codebreakers at Bletchley Park. The name honors that legacy of applying rigorous method to previously "unbreakable" security systems. Trademark clearance research is complete internally; a formal opinion from outside counsel is pending as of this writing.

Full rationale and heritage attribution: [ADR 0007 — Naming Rationale and Heritage Attribution](docs/adr/0007-naming-rationale.md).

## Contributing

Contribution guidelines are in [CONTRIBUTING.md](CONTRIBUTING.md): the branching model (per ADR 0002), PR conventions (squash-merge, no GitHub Issues, no "Closes #N"), commit format, testing expectations, the issue templates, and the ADR process. Report a security vulnerability in Rejewski itself via [SECURITY.md](SECURITY.md); all participants follow the [Code of Conduct](CODE_OF_CONDUCT.md). External contributions open at the public launch (Mon Oct 26, 2026).

## License

MIT. See LICENSE.

---

Part of [Cloud Harbor Consulting](https://cloudharborconsulting.cloud) M365 security tooling.

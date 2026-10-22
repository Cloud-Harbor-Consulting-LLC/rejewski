# Rejewski

Read-only Microsoft 365 adversary-emulation toolkit. A friendly threat actor that emulates recon and discovery TTPs against a tenant the operator owns or has written authorization to assess, and produces findings mapped to specific M365 controls.

> **Status:** Private build through Sat Oct 24, 2026. Public launch Mon Oct 26, 2026. Build cadence and milestones are tracked in the internal Project Harbor Sonar Master Plan.

## What it does

Rejewski is a set of read-only Microsoft Graph tools. They sign in as a test account in a tenant the operator owns or is authorized to assess, and record what that account can read. Every run needs a Rules of Engagement consent record for that tenant before the first token request (G-1). The evidence in this repo comes from the `cloudharbordemo` sandbox. Each run:

1. Starts with a Rules of Engagement consent record, written as the first entry of the run's replay log.
2. Executes read-only Microsoft Graph and Defender / Purview queries against the target tenant.
3. Emits a structured replay log so every run reproduces.
4. Is triaged by an analyst: each finding gets a rubric severity and a specific M365 control (Conditional Access policy, Defender setting, Purview label, Intune compliance check, and so on).
5. Renders an HTML report with severity scores and business-impact lines per finding.

An agent layer built on the Claude Agent SDK ships alongside the tools. `scripts/rejewski_runtime.py` loads the SDK options from `rejewski.config.json`, and `scripts/reasoning_loop.py` routes each recon step to a model and stamps the replay-log entry with the model it chose. In v1.0 that layer runs offline: the operator runs the tools, and connecting them to the agent needs a Graph MCP server, which `rejewski.config.json` does not configure.

## Quickstart

**Prerequisites**

- Python 3.11+ and `git`.
- A Microsoft 365 tenant you own or have written authorization to assess, with a test account for Rejewski to sign in as. The evidence in this repo uses the `cloudharbordemo` sandbox. Guardrail G-1 binds every run to the tenant named in its consent record (see [Rules of Engagement](#rules-of-engagement)).

**Install**

```bash
git clone https://github.com/Cloud-Harbor-Consulting-LLC/rejewski.git
cd rejewski
python -m venv .venv
source .venv/Scripts/activate      # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

**Configure**

Create a `.env` file in the repo root (it is gitignored — never commit it) with the target tenant and the test account's credentials:

```
AZURE_TENANT_ID=<target-tenant-guid>
COMPROMISED_USER_UPN=<test-account>@<tenant-domain>
COMPROMISED_USER_PASSWORD=<password>
# FOCI_CLIENT_ID is optional; defaults to Microsoft Graph Command Line Tools (14d82eec).
```

**Run**

Write the run's consent record first. Without it, every tool refuses to request a token (G-1). For an operator-owned tenant:

```bash
python scripts/write_consent_record.py --engagement-type self_test --tenant-id <target-tenant-guid> \
  --operator-object-id <your-entra-object-id> --run-id demo-001 --techniques T1087.004 --engagement-name "Quickstart" --status active \
  --scope-surface "M365 tenant" --scope-summary "Read-only account discovery" \
  --signed-date 2026-10-26 --effective-date 2026-10-26 --expiry-date 2026-10-26 \
  --record-id roe-selftest-demo-001 --output replay-logs/consent-demo-001.json
```

For a third-party tenant, use `--engagement-type third_party_assessment` with the counterparty fields and a counter-signed `--signature-method`, as described in [docs/external-auth.md](docs/external-auth.md).

Each tool then acquires a delegated Graph token on its first call (against the borrowed FOCI client), caches it, and writes a structured replay-log entry:

```bash
python scripts/tool_list_users.py --run-id demo-001
```

Then consolidate the run's replay-log entries and render the HTML report:

```bash
python scripts/consolidate_run.py --run-id demo-001
python scripts/generate_html_report.py --replay-log <consolidated-log>.json --output report.html
```

`scripts/rejewski_runtime.py` loads `rejewski.config.json` into Claude Agent SDK options and refuses a config that names an out-of-scope technique. The G-1 consent-bound tenant lock is enforced by `scripts/roe_gate.py`: `scripts/identity.py` checks the run's consent record before any token request, and `scripts/replay_log.py` refuses evidence for any tenant the run is not consented for.

## Usage example — a full comprehensive run

The Quickstart above runs a single tool. A real assessment exercises **all 15 tool surfaces in one consented session**, consolidates them under a single run ID, and renders one report. This is the shape of the **R017** weekly run, the current canonical run committed as evidence in this repo (`samples/canonical-run.json`).

**1. Consent once for the run.** Write the run's consent record before the first tool call (see [Rules of Engagement](#rules-of-engagement); `scripts/write_consent_record.py` builds one) and use a single run ID for the whole session — here `R017`.

**2. Run every tool surface, tagged to that run ID.** Each tool authenticates once (then reuses the cached token) and writes its own entries to `replay-logs/`:

```bash
for tool in tool_list_users tool_list_applications tool_list_service_principals \
            tool_list_role_assignments tool_list_oauth_grants tool_list_pim_eligible_roles \
            tool_list_groups \
            tool_list_ca_policies tool_dfi_health tool_intune_devices \
            tool_purview_labels tool_signin_logs tool_list_security_alerts \
            tool_list_sharepoint_sites tool_list_inbox_rules; do
  python scripts/$tool.py --run-id R017
done
```

**3. Consolidate the run** into one replay log. `consolidate_run.py` reads every `replay-logs/` entry whose `run_id` matches, writes `samples/replay-log/<run-id>.json`, and unconditionally redacts the operator-local cache path (G-6). It then ends the run's session by deleting the token cache of each account that signed in (G-8); pass `--keep-session` to skip that:

```bash
python scripts/consolidate_run.py --run-id R017
```

**4. Triage the findings.** Rejewski does not write finding records itself. For each ATT&CK technique the run evidenced, write a finding-triage record (`schemas/finding-triage/v0.1.json`) with a severity from [docs/finding-severity-rubric-v0.1.md](docs/finding-severity-rubric-v0.1.md) and a `control_mapping_id` from `samples/finding-to-control/`. The committed `*-r017-*` records in `samples/finding-triage/` are worked examples. A run with no triage records still renders its consent, graph calls, and token events, with an empty findings table.

**5. Render the HTML report** from the consolidated log plus the committed finding records (`--finding-dir`/`--mapping-dir`/`--roi-model` default to the `samples/` sets):

```bash
python scripts/generate_html_report.py \
  --replay-log samples/replay-log/R017.json \
  --output docs/reports/replay-report-R017.html
```

The committed result is **[docs/reports/replay-report-R017.html](docs/reports/replay-report-R017.html)** (also at [docs/reports/canonical-report.html](docs/reports/canonical-report.html)): a single self-contained report — graph calls, token events, findings, control mappings, and a per-finding ROI section — from one 15-surface run, with **10 distinct findings, each carrying a severity score and an ROI line**. The 14 surfaces that returned data map to 9 ATT&CK techniques (six surfaces to T1087.004 account discovery, two to T1654 log enumeration), and the run's own sign-in adds a tenth: the seeded password alone got a token (T1078.004). `tool_list_inbox_rules` is a documented block (the delegated self-mailbox boundary), not a finding.

## Rules of Engagement

Every run starts with a consent record, and the code enforces it (G-1, [ADR 0008](docs/adr/0008-consent-bound-tenant-lock.md)). A tool refuses to request a token unless the run's replay-log directory holds a consent record for its run ID that names the tenant it is about to use. The `cloudharbordemo` sandbox needs the run-level record. Any other tenant needs an active v2 durable record whose authorization window includes today, counter-signed by the tenant's owner for a third-party assessment. `scripts/write_consent_record.py` builds a schema-valid record. [docs/roe-consent-flow.md](docs/roe-consent-flow.md) specifies an interactive consent prompt (the operator confirms by echoing a generated run ID back verbatim); in v1.0 that prompt is not yet wired in, so the operator writes the record before running the tools. The gate checks the record's fields, not the signature on the letter behind it. The consent record is the first entry of the run's replay log and binds every downstream entry by `run_id`. Sprint 1's exit floor is five consented runs logged end-to-end.

The self-test consent mechanic is specified in [docs/roe-consent-flow.md](docs/roe-consent-flow.md); the authorization flow for a third-party tenant assessment (and the durable long-term consent-record archive) is in [docs/external-auth.md](docs/external-auth.md); the governing decision is [ADR 0001 — Rules of Engagement](docs/adr/0001-rules-of-engagement.md).

## Guardrails

Rejewski runs under nine operational guardrails (**G-1 through G-9**), cited by number from the technique modules. Some are enforced in code and some by procedure and PR review; each one's Enforcement paragraph says which. In brief: every run is bound to the one tenant its consent record names, checked before the first token request (**G-1**, code); there is no tenant app registration, and a single borrowed Microsoft first-party client is recorded on every entry (**G-2**, **G-4**, code plus review); Graph requests are GET only (**G-3**, code); every call writes a replay-log entry (**G-5**, code); published evidence carries per-call counts, not directory payloads (**G-6**, code plus review); the sandbox holds only seeded test accounts (**G-7**, procedure); consolidating a run deletes its encrypted token cache, so sessions do not carry over between runs (**G-8**, code); and enumeration is capped per call (**G-9**, code).

Full rule text — statement, rationale, enforcement, scope, and exceptions for each — is in [docs/guardrails.md](docs/guardrails.md); the guardrail set is authorized by [ADR 0001](docs/adr/0001-rules-of-engagement.md).

## Design principles

These are the program-level **operating principles** from the internal Project Harbor Sonar Master Plan §2 — the *why* behind how the project is run (scope, cadence, launch strategy).

> **Different numbering scheme from the Guardrails above.** These principles use the Master Plan's own `G1`–`G8` labels; they are **not** the operational `G-1` through `G-9` in the [Guardrails](#guardrails) section above. Guardrails answer "what does the code enforce"; these principles answer "why does the project operate the way it does." Don't conflate `G4` here (Threat Actor Emulation) with `G-4` above (FOCI client allowlist), etc.

- **G1 — Read-Only.** The agent never writes to the target tenant: no policy creation, role assignment, group-membership change, or user-property change; Microsoft Graph calls are limited to GET.
- **G2 — No Credential Harvesting.** No password spray, no theft or replay of another user's or device's tokens, no MFA-bypass attempts, and no session-cookie capture. The tools sign in as a seeded sandbox test account with that account's own password (ROPC), then silently reuse that account's own cached refresh token. The T1550.001 module records that reuse as evidence of what a stolen refresh token allows.
- **G3 — Telemetry-Aware and Replayable.** Every run produces a structured replay log (prompts, tool calls, results, timestamps) so findings reproduce; the agent assumes Defender XDR audit telemetry sees every call.
- **G4 — Threat Actor Emulation.** The agent emulates the recon and discovery TTPs of a real-world threat actor, mapped to MITRE ATT&CK Enterprise — no persistence, no lateral movement off M365, no defense evasion.
- **G5 — Rules of Engagement.** Every run starts with an ROE prompt and a consent record; the operator confirms tenant ownership or written authorization and scope boundaries, and acknowledges G1–G4.
- **G6 — Private Build, Public Launch.** Repo, boards, and build artifacts stay private through Sat Oct 24, 2026; public launch is Mon Oct 26, 2026, with a single high-level teaser post on Sat Aug 1, 2026.
- **G7 — M365-Wide Control Inventory Mapping.** Every finding maps to a specific M365 control (Conditional Access policy, Defender setting, Purview label, Intune compliance check, and so on); the agent does not surface findings without a control mapping.
- **G8 — Measure at Sprint Boundaries.** Build KPIs are collected weekly and sprint-checkpoint KPIs reviewed every four weeks; v1.1 backlog grooming happens at sprint checkpoints, never mid-sprint.

Source: Project Harbor Sonar Master Plan §2 (Operating Guardrails), an internal document.

## Naming

Rejewski is named for Marian Rejewski (1905-1980), the Polish mathematician who in December 1932 first reconstructed the internal wiring of the German military Enigma cipher machine using permutation theory, without access to a captured device. Working with fellow Polish Cipher Bureau cryptologists Jerzy Różycki and Henryk Zygalski, he built the foundation later extended by British codebreakers at Bletchley Park. The name honors that legacy of applying rigorous method to previously "unbreakable" security systems. Trademark clearance research is complete internally; a formal opinion from outside counsel is pending as of this writing.

Full rationale and heritage attribution: [ADR 0007 — Naming Rationale and Heritage Attribution](docs/adr/0007-naming-rationale.md).

## Contributing

Contribution guidelines are in [CONTRIBUTING.md](CONTRIBUTING.md): the branching model (per ADR 0002), PR conventions (squash-merge, no GitHub Issues, no "Closes #N"), commit format, testing expectations, the issue templates, and the ADR process. Report a security vulnerability in Rejewski itself via [SECURITY.md](SECURITY.md); all participants follow the [Code of Conduct](CODE_OF_CONDUCT.md). External contributions open at the public launch (Mon Oct 26, 2026).

## License

MIT. See LICENSE.

---

Part of [Cloud Harbor Consulting](https://cloudharborconsulting.cloud) M365 security tooling.

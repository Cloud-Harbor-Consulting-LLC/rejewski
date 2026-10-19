# Rejewski v1.0 release notes

- **Status:** Draft (2026-10-15). Final at the v1.0 tag in the private repo on Sat Oct 24, 2026; published as the GitHub Release on Mon Oct 26, 2026.
- **License:** MIT

## What Rejewski is

Rejewski is a read-only Microsoft 365 adversary-emulation toolkit. Its tools sign in as a test account in a tenant the operator owns or is authorized to assess, and read what a compromised account can read through Microsoft Graph. Every run needs a Rules of Engagement consent record for that tenant before the first token request. Every call is written to a replay log, and each run ends in an HTML report where every finding carries a severity, a mapped Microsoft 365 control, and an ROI line.

## Highlights

- 15 read-only tools covering identity, Conditional Access, privileged roles, security posture, data governance, logs, and collaboration.
- 20 MITRE ATT&CK techniques mapped: 13 implemented, 7 catalogued.
- 9 operational guardrails (G-1 to G-9). Five are enforced in code.
- Consent enforced in code: a run can target any tenant, but only the tenant its consent record names (G-1, ADR 0008).
- Replay log schema v0.5, with run consolidation, redaction, a viewer, and an archive policy.
- HTML reports scored by the severity rubric v1.0 and the ROI model v0.2. No ROI line carries a dollar figure.
- Canonical run R016: 15 tool surfaces, 9 findings, 4 rated high.

## Tools

Every tool issues `GET` requests to Microsoft Graph v1.0 only.

| # | Tool | Graph endpoint | ATT&CK |
|---|---|---|---|
| 1 | `scripts/tool_list_users.py` | `/users` | T1087.004 |
| 2 | `scripts/tool_list_groups.py` | `/groups` | T1069.003 |
| 3 | `scripts/tool_list_applications.py` | `/applications` | T1087.004 |
| 4 | `scripts/tool_list_ca_policies.py` | `/identity/conditionalAccess/policies` | T1526 |
| 5 | `scripts/tool_list_role_assignments.py` | `/roleManagement/directory/roleAssignments` | T1087.004, T1033 |
| 6 | `scripts/tool_list_service_principals.py` | `/servicePrincipals` | T1087.004 |
| 7 | `scripts/tool_dfi_health.py` | `/security/identities/sensors` | T1518.001 |
| 8 | `scripts/tool_intune_devices.py` | `/deviceManagement/managedDevices` | T1082 |
| 9 | `scripts/tool_purview_labels.py` | `/security/dataSecurityAndGovernance/sensitivityLabels` | T1580 |
| 10 | `scripts/tool_signin_logs.py` | `/auditLogs/signIns` | T1654 |
| 11 | `scripts/tool_list_oauth_grants.py` | `/oauth2PermissionGrants` | T1087.004 |
| 12 | `scripts/tool_list_security_alerts.py` | `/security/alerts_v2` | T1654 |
| 13 | `scripts/tool_list_inbox_rules.py` | `/me/mailFolders/inbox/messageRules` | T1114.002, T1114.003 |
| 14 | `scripts/tool_list_sharepoint_sites.py` | `/sites` | T1213.002 |
| 15 | `scripts/tool_list_pim_eligible_roles.py` | `/roleManagement/directory/roleEligibilityScheduleInstances` | T1087.004 |

Token acquisition is shared: `scripts/identity.py` signs in with ROPC on a cache miss (T1078.004) and reuses the cached refresh token silently for the rest of the run (T1550.001). Each tool's required delegated permission and directory role are listed in its docstring and its technique module under `docs/techniques/`.

## ATT&CK coverage

The full map is in [docs/attck-coverage.md](https://github.com/Cloud-Harbor-Consulting-LLC/rejewski/blob/main/docs/attck-coverage.md).

| Status | Count | Techniques |
|---|---|---|
| Implemented | 13 | T1078.004, T1087.004, T1069.003, T1550.001, T1526, T1518.001, T1082, T1580, T1654, T1213.002, T1114.002, T1114.003, T1033 |
| Catalogued | 7 | T1087.003, T1482, T1538, T1213.003, T1530, T1619, T1528 |

"Implemented" means a working script exists and a consented sandbox run has produced replay-log evidence. "Catalogued" means a technique module defines the scope and implementation path, and no script exists yet. T1114.002 and T1114.003 share one tool whose sandbox evidence to date is a documented block, not data (see Known limitations). Three further candidates (T1201, T1018, T1552) are in the v1.1 backlog.

## Guardrails

Full text, with file references for each enforcement mechanism, is in [docs/guardrails.md](https://github.com/Cloud-Harbor-Consulting-LLC/rejewski/blob/main/docs/guardrails.md).

| ID | Rule | Enforced by |
|---|---|---|
| G-1 | Consent-bound tenant lock: a run may target only the tenant named in its consent record | Code (`scripts/roe_gate.py`, checked in `identity.acquire_token` and `replay_log.write_entry`) |
| G-2 | No tenant app registration | Code (GET-only guard) and PR review |
| G-3 | Read-only: Graph requests are GET only | Code (`write_entry()` and `tests/test_autonomy_boundary.py`) |
| G-4 | One borrowed first-party client, Microsoft Graph Command Line Tools (14d82eec) | Procedure (recorded on every entry, checked in review) |
| G-5 | Every call writes a replay-log entry | Code (`scripts/replay_log.py`) |
| G-6 | Published evidence carries per-call counts, not directory payloads | Code and PR review |
| G-7 | The sandbox holds only seeded test accounts | Procedure (`scripts/seed-cloudharbordemo.ps1`) |
| G-8 | Sessions end with the run: consolidation deletes the run's token cache | Code (`scripts/consolidate_run.py`, ADR 0005 §5.4) |
| G-9 | Enumeration is capped per call (default 1,000 rows) | Code (each tool) |

The project also runs under 8 program principles, G1 to G8 (Read-only, No credential harvesting, Telemetry-aware and replayable, Threat actor emulation, Rules of Engagement, Private build and public launch, Control inventory mapping, Measure at sprint boundaries). They are listed in the README's Design principles section and use a different numbering scheme from the guardrails above.

## Rules of Engagement

- Every run starts with a consent record that names the tenant, the techniques in scope, the expected duration, the operator, and the run ID. It is the first entry of the run's replay log, and every later entry is bound to it by `run_id`.
- The code enforces it. Before any token request, `scripts/roe_gate.py` checks that the run's replay-log directory holds a consent record for its run ID that names the tenant the run is about to use. The `cloudharbordemo` sandbox needs the run-level record. Any other tenant needs an active v2 durable record whose authorization window includes today, and a counter-signed record for a third-party assessment.
- `scripts/write_consent_record.py` builds a schema-valid record. Schema v1 is the replay-log-embedded shape; schema v2 adds the fields for a durable long-term archive record.
- The consent prompt is specified in [docs/roe-consent-flow.md](https://github.com/Cloud-Harbor-Consulting-LLC/rejewski/blob/main/docs/roe-consent-flow.md). The authorization flow for a third-party assessment is in [docs/external-auth.md](https://github.com/Cloud-Harbor-Consulting-LLC/rejewski/blob/main/docs/external-auth.md). The governing decision is ADR 0001.

## Replay log

- Schema v0.5 (`schemas/replay-log/v0.5.json`). Entry kinds are `token_event` and `graph_call`, plus the consent record. Each entry records the run ID, timestamps, operator, tenant, borrowed client, technique, request, and outcome. A `graph_call` entry records status, page and row counts, and the row cap. A `token_event` records the flow (ROPC or silent) and the requested scopes. Since v0.5, entries can carry the model ID chosen by the reasoning-loop router.
- `write_entry()` validates each entry before writing it: tenant, borrowed client, outcome, and HTTP method.
- `scripts/consolidate_run.py` gathers a run's entries into `samples/replay-log/<run-id>.json`, redacts the operator-local cache path, and ends the run's session.
- `scripts/replay_log_viewer.py` renders a log as text or a self-contained HTML page. `scripts/rotate_replay_logs.py` compresses aged working logs under the policy in [docs/replay-archive.md](https://github.com/Cloud-Harbor-Consulting-LLC/rejewski/blob/main/docs/replay-archive.md).

## Reports and findings

- `scripts/generate_html_report.py` renders a self-contained report with sections for the consent summary, graph calls, token events, findings with severity badges, control mappings, and ROI lines.
- Severity follows the rubric in [docs/finding-severity-rubric-v0.1.md](https://github.com/Cloud-Harbor-Consulting-LLC/rejewski/blob/main/docs/finding-severity-rubric-v0.1.md) (v1.0, tied to CIS Controls v8). A read that maps the defender's own coverage, such as Conditional Access policies, sensor health, or sign-in and alert logs, rates high.
- Each finding maps to a Microsoft 365 control through a schema-validated record in `samples/finding-to-control/`.
- ROI lines come from the ROI model v0.2 ([docs/phs-security-roi-model-v0.1.md](https://github.com/Cloud-Harbor-Consulting-LLC/rejewski/blob/main/docs/phs-security-roi-model-v0.1.md)), which uses 2026 figures each checked against its primary source. Each line names a risk category and a direction of risk, with no dollar figure.

## Evidence in this release

- Replay logs for runs R002 to R016 in `samples/replay-log/`, with finding-triage records in `samples/finding-triage/`.
- HTML reports for R012 to R016 in `docs/reports/`.
- The canonical run, R016, at `samples/canonical-run.json` and `docs/reports/canonical-report.html`. It covers 15 tool surfaces and has 9 findings (4 high, 5 medium). Several surfaces map to the same technique, so 15 surfaces produce 9 findings. The inbox-rules tool's block is recorded and not counted.

All evidence comes from a sandbox tenant with seeded accounts.

## Requirements

Python 3.11 or later, the packages in `requirements.txt`, and a `.env` file with the sandbox tenant ID and the seeded account's credentials. The README Quickstart walks through install, configuration, a single-tool run, and a full 15-tool run.

## Known limitations

- **The consent gate checks the record, not the signature.** It verifies the record's tenant, run ID, status, and authorization window. The signed letter behind a third-party record is referenced by `authorization.evidence_ref` and checked by the operator.
- **Technique scope is not enforced against the consent record yet.** The gate enforces the tenant and the authorization window; a run's techniques are not yet checked against the consented list.
- **No interactive consent prompt.** The prompt in `docs/roe-consent-flow.md` is not wired in; the operator writes the record with `scripts/write_consent_record.py` before the tools run.
- **Evidence from real tenants stays private.** Only sandbox evidence is committed to this repo. Output from a run against any other tenant, including its consent record with counterparty contact details, belongs in the operator's private archive.
- **The agent layer runs offline.** `scripts/reasoning_loop.py` routes each recon step to a Claude model and stamps the replay log with the model it chose. It does not call Graph. Connecting the tools to the agent needs a Graph MCP server, which v1.0 does not configure.
- **Inbox rules return no data in the sandbox.** With delegated `Mail.Read`, the inbox-rules tool reaches only the signed-in account's own mailbox. The sandbox operator account has no mailbox enabled for the REST API, so the call returns a documented block.
- **Teardown is local only.** Consolidation deletes the token cache. The issued refresh token stays valid at Microsoft Entra ID until it expires, because revoking it would need a Graph write call that G-3 forbids.
- **The client allowlist is procedural.** Tools accept a `FOCI_CLIENT_ID` override without checking it against the allowlist in ADR 0006.
- **ROPC sign-in.** The tools sign in with ROPC, which cannot satisfy MFA, so the seeded account must not require MFA. MSAL for Python deprecated ROPC for the public-client flow in release 1.35.0. `requirements.txt` allows any MSAL 1.x release.
- **Published sandbox identifiers.** Committed evidence includes the sandbox tenant ID and the UPNs of sandbox test accounts, by design (G-6).

## Contributing and security

See [CONTRIBUTING.md](https://github.com/Cloud-Harbor-Consulting-LLC/rejewski/blob/main/CONTRIBUTING.md), [CODE_OF_CONDUCT.md](https://github.com/Cloud-Harbor-Consulting-LLC/rejewski/blob/main/CODE_OF_CONDUCT.md), and [SECURITY.md](https://github.com/Cloud-Harbor-Consulting-LLC/rejewski/blob/main/SECURITY.md). Report a vulnerability through the process in SECURITY.md, not in a public issue.

## Changes

[CHANGELOG.md](https://github.com/Cloud-Harbor-Consulting-LLC/rejewski/blob/main/CHANGELOG.md) lists every change in this release.

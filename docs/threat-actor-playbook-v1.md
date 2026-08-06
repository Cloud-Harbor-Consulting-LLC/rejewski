# Rejewski Threat-Actor Playbook v1

- Version: v1
- Last updated: 2026-08-06
- Status: Living document — operator manual for simulated adversary sessions
- Authors: Derek Morgan
- Related: ADR 0001 (Sprint 1 Rules of Engagement), docs/guardrails.md (G-1 through G-9), docs/roe-consent-flow.md, docs/techniques/, docs/attck-coverage.md, docs/threat-model.md

---

## Purpose

This playbook defines the canonical TTP-chain recipes run against the cloudharbordemo
sandbox tenant (76b87c33-6178-4ff9-94a7-164792c8e4c6) when demonstrating Rejewski's
threat-actor emulation capability. Each recipe is a short, ordered sequence of Rejewski
tools that an emulated adversary would run to accomplish one discovery objective, mapped
to MITRE ATT&CK and paired with the defender-side signals the chain generates.

Every recipe is **read-only** (GET-only Graph calls; no rule, policy, or object is
created, modified, or deleted) and is bound to a single ROE consent run.

### Token acquisition underpins every recipe

Each recipe's first tool call acquires a delegated Microsoft Graph token through
`scripts/identity.py` (borrowed Microsoft Graph Command Line Tools client 14d82eec, per
ADR 0004 and ADR 0006). That acquisition emits a `token_event` replay-log entry whose
technique is **T1078.004** (Valid Accounts: Cloud Accounts) on a fresh ROPC sign-in — a
cold token cache — and **T1550.001** (Application Access Token) on silent reuse of an
already-cached token (per the B029 fix). This initial-access / token-reuse step therefore
underpins all five recipes below, whether or not a recipe's technique list names it
explicitly. The per-recipe ATT&CK lists reflect the *discovery* techniques the tool
sequence exercises; T1078.004 / T1550.001 is the always-present token layer beneath them.

### Run binding

Pass the same `--run-id <run_id>` to every tool in a recipe so all replay-log entries
(the `consent.granted` record plus every `graph_call` and `token_event`) bind to one run.
Consolidate the run into a single canonical sample with `scripts/consolidate_run.py`.

---

## Recipe R-01 — Privileged Account Discovery

**Threat-actor goal.** Map all privileged accounts, their directory role assignments, and
associated service-principal delegations to build a ranked list of high-value targets for
further access — the crown jewels of the tenant's identity plane.

**Prerequisites.**
- ROE consent run confirmed (see guardrail G-5 below).
- Delegated scopes admin-consented on the borrowed client: `User.Read.All` /
  `Directory.Read.All`, `RoleManagement.Read.Directory`, `Application.Read.All`.
- Directory role: **Directory Readers** (minimum) on the signed-in account for complete
  tenant-wide role-assignment and service-principal visibility. Without it, role
  enumeration returns 403 and service-principal enumeration returns an empty set.

**Tool sequence.**
```bash
python scripts/tool_list_users.py --run-id <run_id>
python scripts/tool_list_role_assignments.py --run-id <run_id>
python scripts/tool_list_service_principals.py --run-id <run_id>
```

**Expected output indicators.** The full user directory (UPNs, display names, enabled
state); every directory role assignment with resolved principal and role names, flagging
Global Administrator / Privileged Role Administrator / other high-privilege holders,
external (guest) principals, and tenant-wide scope; and the service-principal inventory
with enabled/disabled counts and type breakdown. Together these tell the adversary *which
accounts hold the highest blast-radius roles* and *which service principals to target*.

**ATT&CK techniques exercised.** T1078.004 (Valid Accounts: Cloud Accounts — token
acquisition); T1087.004 (Account Discovery: Cloud Account) Surfaces A (users), C (role
assignments), D (service principals).

**Detection signals.**
- **MicrosoftGraphActivityLogs** — GET `/users`, `/roleManagement/directory/roleAssignments`,
  and `/servicePrincipals` from the FOCI client ID (14d82eec) in a single session; the
  burst of directory reads is a leading indicator of systematic enumeration.
- **Entra ID sign-in logs** — the read activity correlates to the T1078.004 sign-in
  session (correlation ID).
- **Microsoft Defender for Cloud Apps** — bulk directory-read anomaly against a
  normal-usage baseline, especially from a non-administrative account.

**Guardrails.**
- **G-1:** All calls are GET only. No rule creation, modification, or deletion.
- **G-3:** Sandbox tenant 76b87c33 only. No production tenant calls.
- **G-5:** ROE consent run required before executing any recipe. The consent record must
  be present in phs-roe-consent-archive-v1.0.xlsx before tool invocations begin.
- **G-6:** No output files committed to the repo without Derek's review and scrub.

---

## Recipe R-02 — OAuth Permission Sprawl

**Threat-actor goal.** Identify applications and their delegated permission grants to
reveal over-permissioned apps and service principals — the ones holding broad admin-
consented delegated scopes are prime targets for credential compromise and token reuse.

**Prerequisites.**
- ROE consent run confirmed (G-5).
- Delegated scopes admin-consented: `Application.Read.All`, `Directory.Read.All`.
- Directory role: **Directory Readers** (minimum), Global Reader, or Application
  Administrator for tenant-wide grant and service-principal visibility.

**Tool sequence.**
```bash
python scripts/tool_list_applications.py --run-id <run_id>
python scripts/tool_list_oauth_grants.py --run-id <run_id>
python scripts/tool_list_service_principals.py --run-id <run_id>
```

**Expected output indicators.** The tenant's app registrations; the full OAuth2 delegated
permission-grant inventory with admin- vs user-consented counts, unique client/resource
service-principal counts, and a **high-privilege-grant count** (grants carrying scopes such
as Directory.ReadWrite.All, Mail.ReadWrite, Files.ReadWrite.All); and the service-principal
inventory to resolve client/resource object IDs to identities. The high-privilege-grant
list is the adversary's shortlist: compromising one of those apps yields its full delegated
authorization without touching a user account.

**ATT&CK techniques exercised.** T1087.004 (Account Discovery: Cloud Account) Surfaces B
(app registrations), D (service principals), E (OAuth2 delegated permission grants).

**Detection signals.**
- **MicrosoftGraphActivityLogs** — GET `/applications`, `/oauth2PermissionGrants`, and
  `/servicePrincipals` from the FOCI client (14d82eec); enumeration of the delegated-grant
  surface is an uncommon read outside admin tooling.
- **Microsoft Defender for Cloud Apps** — an OAuth-app enumeration read followed by any
  credential addition would fire the "Unusual addition of credentials to an OAuth app"
  detection; the read itself baselines as anomalous for a non-admin principal.

**Guardrails.**
- **G-1:** All calls are GET only. No rule creation, modification, or deletion.
- **G-3:** Sandbox tenant 76b87c33 only. No production tenant calls.
- **G-5:** ROE consent run required before executing any recipe. The consent record must
  be present in phs-roe-consent-archive-v1.0.xlsx before tool invocations begin.
- **G-6:** No output files committed to the repo without Derek's review and scrub.

---

## Recipe R-03 — Security Posture Gap Assessment

**Threat-actor goal.** Assess whether Conditional Access gaps, an uncrowded alert queue,
and degraded Defender for Identity sensor health combine to create an environment where
adversary actions are unlikely to generate alerts — i.e., find the low-detection window.

**Prerequisites.**
- ROE consent run confirmed (G-5).
- Delegated scopes admin-consented: `Policy.Read.All`, `SecurityAlert.Read.All`,
  `SecurityIdentitiesSensors.Read.All`.
- Directory role: **Security Reader** (minimum) on the signed-in account — all three reads
  are role-gated and return 403 without it. This is a post-privilege-escalation step, not
  a first-foothold capability.

**Tool sequence.**
```bash
python scripts/tool_list_ca_policies.py --run-id <run_id>
python scripts/tool_list_security_alerts.py --run-id <run_id>
python scripts/tool_dfi_health.py --run-id <run_id>
```

**Expected output indicators.** The Conditional Access policy set with enabled / disabled /
report-only counts and MFA / block / compliant-device coverage — revealing which user
populations and applications lack enforcement; the Defender XDR alert queue by severity,
status, and category — revealing whether earlier enumeration has already been detected and
which categories are firing; and the DfI sensor fleet's health / deployment status and open
health-issue counts — revealing coverage gaps where on-prem Kerberos/NTLM activity would go
unseen. Together these answer *"where can I operate without tripping an alert?"*

**ATT&CK techniques exercised.** T1526 (Cloud Service Discovery — CA policies); T1654 (Log
Enumeration) Surface B (security alerts) and, by cross-reference, the sign-in-log Surface A;
T1518.001 (Software Discovery: Security Software Discovery — DfI sensors).

**Detection signals.**
- **MicrosoftGraphActivityLogs** — GET `/identity/conditionalAccess/policies`,
  `/security/alerts_v2`, and `/security/identities/sensors` from the FOCI client (14d82eec);
  security-configuration reads from a non-SOC account stand out.
- **Reflexive alert-queue read** — a member account reading `/security/alerts_v2` (the
  defender's own alert queue) should itself trigger a Defender for Cloud Apps / Defender for
  Identity anomaly on first non-baseline access.
- **Entra ID audit logs** — role-gated policy and security reads correlate to the
  privileged-role account used for this recipe.

**Guardrails.**
- **G-1:** All calls are GET only. No rule creation, modification, or deletion.
- **G-3:** Sandbox tenant 76b87c33 only. No production tenant calls.
- **G-5:** ROE consent run required before executing any recipe. The consent record must
  be present in phs-roe-consent-archive-v1.0.xlsx before tool invocations begin.
- **G-6:** No output files committed to the repo without Derek's review and scrub.

---

## Recipe R-04 — Email Forwarding Risk Discovery

**Threat-actor goal.** Identify inbox rules that forward or redirect email to external
addresses, or that delete/hide incoming messages — surfacing existing email-collection
paths or the artifacts of prior adversary implantation.

**Prerequisites.**
- ROE consent run confirmed (G-5).
- Delegated scope admin-consented: `MailboxSettings.Read`.
- Directory role: **none** for the operator's own mailbox (`--user-id me`). Cross-user
  enumeration (`--user-id <object-id>`) requires Exchange Administrator or Global Reader and
  returns 403 otherwise.

**Tool sequence.**
```bash
python scripts/tool_list_inbox_rules.py --run-id <run_id> --user-id me
```

**Expected output indicators.** Every inbox rule for the target mailbox, with the
forwarding/hiding actions surfaced explicitly: `forwardTo` / `forwardAsAttachmentTo` /
`redirectTo` external addresses (a collection indicator), `delete` / `moveToFolder` (a
covering-tracks indicator), each rule's enabled state and error flag, and the matching
conditions (sender/subject/body contains). A rule quietly forwarding to an outside address,
or silently deleting mail matching a keyword, is the payload finding — it says email
collection plumbing already exists, whether the adversary's own or a defender's.

**ATT&CK techniques exercised.** T1078.004 (Valid Accounts: Cloud Accounts — token
acquisition); T1114.002 (Email Collection: Remote Email Collection) Surface A (inbox message
rules).

**Detection signals.**
- **Exchange mailbox audit (MailboxAuditLog)** — `UpdateInboxRules` operations record
  inbox-rule activity; a read/enumeration correlates against this rule surface.
- **Unified Audit Log** — `Set-InboxRule` / inbox-rule operations.
- **Microsoft Defender for Cloud Apps** — inbox-rule forwarding/creation policy alerts; a
  member account reading another mailbox's rules (cross-user) is a high-fidelity anomaly.

**Guardrails.**
- **G-1:** All calls are GET only. No rule creation, modification, or deletion.
- **G-3:** Sandbox tenant 76b87c33 only. No production tenant calls.
- **G-5:** ROE consent run required before executing any recipe. The consent record must
  be present in phs-roe-consent-archive-v1.0.xlsx before tool invocations begin.
- **G-6:** No output files committed to the repo without Derek's review and scrub.

---

## Recipe R-05 — Device and Sign-In Correlation

**Threat-actor goal.** Correlate managed-device posture with sign-in log volume to identify
accounts signing in from unmanaged or non-compliant devices — the gaps in Zero Trust device
compliance where a stolen credential is least likely to be challenged.

**Prerequisites.**
- ROE consent run confirmed (G-5).
- Delegated scopes admin-consented: `DeviceManagementManagedDevices.Read.All`,
  `AuditLog.Read.All`.
- Directory role: **Intune-administrator-class** access for the managed-device read and
  **Reports Reader** (minimum) for the sign-in-log read; sign-in-log enumeration returns
  403 without a qualifying role regardless of scope consent.

**Tool sequence.**
```bash
python scripts/tool_intune_devices.py --run-id <run_id>
python scripts/tool_signin_logs.py --run-id <run_id>
```

**Expected output indicators.** The Intune-managed device inventory with compliance state,
encryption status, OS/version, ownership (company vs personal), and last-sync timestamps;
and the sign-in log for the lookback window with per-event risk level, app, interactive vs
non-interactive split, and failed-count aggregates. Correlating the two reveals accounts
authenticating from devices that are non-compliant, unencrypted, or absent from the managed
inventory entirely — the soft targets for client-side compromise and the Zero-Trust
device-compliance gaps.

**ATT&CK techniques exercised.** T1082 (System Information Discovery — managed devices);
T1654 (Log Enumeration) Surface A (sign-in logs).

**Detection signals.**
- **MicrosoftGraphActivityLogs** — GET `/deviceManagement/managedDevices` and
  `/auditLogs/signIns` from the FOCI client (14d82eec); a full managed-device read from a
  non-Intune-admin account is a strong bulk-enumeration indicator.
- **Reflexive sign-in-log read** — a member account reading `/auditLogs/signIns` (the
  authentication telemetry the defender relies on) is itself anomalous and should surface in
  Defender for Cloud Apps.
- **Entra ID sign-in logs** — both reads correlate to the T1078.004 session correlation ID.

**Guardrails.**
- **G-1:** All calls are GET only. No rule creation, modification, or deletion.
- **G-3:** Sandbox tenant 76b87c33 only. No production tenant calls.
- **G-5:** ROE consent run required before executing any recipe. The consent record must
  be present in phs-roe-consent-archive-v1.0.xlsx before tool invocations begin.
- **G-6:** No output files committed to the repo without Derek's review and scrub.

---

## References

- ADR 0001 — Sprint 1 Rules of Engagement (ROE)
- docs/guardrails.md — G-1 through G-9 enforcement rules
- docs/roe-consent-flow.md — per-run consent prompt, `consent.granted` record, run-ID binding
- docs/techniques/ — per-technique ADR 0003 modules (T1078.004, T1087.004, T1526, T1518.001,
  T1082, T1580, T1654, T1114.002, and the full catalogue)
- docs/attck-coverage.md — technique status and tactic distribution (v0.6)
- docs/threat-model.md — §5 active technique scope, adversary model (v1.2)
- MITRE ATT&CK Enterprise — <https://attack.mitre.org/matrices/enterprise/>

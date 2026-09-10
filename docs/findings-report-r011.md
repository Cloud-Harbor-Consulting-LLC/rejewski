# Rejewski Findings Report — Run R011

- Run ID: R011
- Run date: Sat Jul 18, 2026
- Tenant: cloudharbordemo (76b87c33-6178-4ff9-94a7-164792c8e4c6)
- Operator account: meganb@cloudharbor-demo.com
- Techniques in scope: all 9 implemented (full Sprint 3 W10 sweep)
- Replay log: samples/replay-log/R011.json
- Status: **Complete**
- Related: docs/attck-coverage.md, docs/threat-model.md

---

## 1. Scope

Run R011 is the first full end-to-end sweep of every implemented Rejewski technique in a
single consented session — the Sprint 3 W10 deliverable. Nine techniques are in scope, in
kill-chain order: T1078.004 (Valid Accounts: Cloud Accounts) establishes the initial access
that every downstream call depends on; T1087.004 (Account Discovery: Cloud Account),
T1069.003 (Permission Groups Discovery: Cloud Groups), T1526 (Cloud Service Discovery),
T1518.001 (Software Discovery: Security Software Discovery), T1082 (System Information
Discovery), T1580 (Cloud Infrastructure Discovery), and T1654 (Log Enumeration) build the
account, group, policy, security-product, endpoint, data-classification, and authentication-
telemetry picture; and T1550.001 (Use Alternate Authentication Material: Application Access
Token) operationalises the borrowed token across all of them. The sweep is Discovery-heavy
by design — seven of the nine techniques carry the Discovery tactic, consistent with
Rejewski's recon-and-enumeration posture.

The authority for technique scope, status, and surface is docs/threat-model.md §5; the
authoritative technique count and tactic distribution are in docs/attck-coverage.md.

---

## 2. Run summary

| Technique | Tactic | Tool | Endpoint | Objects (R011) | Severity | Control |
|-----------|--------|------|----------|----------------|----------|---------|
| T1078.004 | Initial Access | `scripts/identity.py` | Device-code / ROPC sign-in | N/A (absent — see §3) | informational | CA-SIG003-Guests-RequireMFA |
| T1087.004 | Discovery | `scripts/tool_list_users.py` | `GET /users` | 8 (see §3 for other surfaces) | medium | CA-COV008-BlockByLocation |
| T1069.003 | Discovery | `scripts/tool_list_groups.py` | `GET /me/memberOf` | 19 | medium | CA-SIF001-SignInFrequency-8h |
| T1550.001 | Defense Evasion / Lateral Movement | `scripts/identity.py` | MSAL encrypted cache (silent reuse) | 10 token events | high | Directory Readers (RBAC) |
| T1526 | Discovery | `scripts/tool_list_ca_policies.py` | `GET /identity/conditionalAccess/policies` | 25 | high [‡] | Reports Reader (RBAC) |
| T1518.001 | Discovery | `scripts/tool_dfi_health.py` | `GET /security/identities/sensors` | 3 | high [‡] | Security Reader (RBAC) |
| T1082 | Discovery | `scripts/tool_intune_devices.py` | `GET /deviceManagement/managedDevices` | 1 | medium | Intune Service Administrator (RBAC) |
| T1580 | Discovery | `scripts/tool_purview_labels.py` | `GET /security/dataSecurityAndGovernance/sensitivityLabels` | 4 | medium [†] | CA-PUR-001-RequireCompliantApp |
| T1654 | Discovery | `scripts/tool_signin_logs.py` | `GET /auditLogs/signIns` | 30 | high [‡] | Reports Reader (RBAC) |

> **[†] Note (2026-08-29):** T1580 severity updated `low` → `medium` per
> `docs/finding-severity-rubric-v0.1.md` — the Purview label taxonomy is a Collection-targeting
> map (D=2 in the rubric), not infra-only metadata. This R011 report originally assessed it as
> `low`; the value is refined here while the finding itself is unchanged.
>
> **[‡] Note (2026-09-10):** T1526, T1518.001, and T1654 severity updated `medium` → `high` per
> `docs/finding-severity-rubric-v0.1.md` **v1.0**, which adopted the **defensive-evasion escalator**
> (PM decision, S5 W18): a finding that maps the tenant's own detection posture — CA-policy coverage
> (T1526), security-sensor health (T1518.001), or sign-in/alert telemetry (T1654) — routes to `high`
> (rubric §4 decision-table row 3), because it tells an adversary *what to evade*, not merely who or
> what exists. This R011 report originally assessed all three as `medium`; the value is refined here
> (in both the summary table and the §3 detail blocks) while the findings themselves are unchanged.

---

## 3. Findings

### T1078.004 — Valid Accounts: Cloud Accounts

- **Tactic:** Initial Access
- **Tool:** scripts/identity.py
- **Endpoint:** Device-code / ROPC sign-in (login.microsoftonline.com)
- **Evidence:** samples/replay-log/R011.json
- **Objects enumerated:** N/A — no T1078.004 entry present in R011.json
- **Severity:** informational
- **Confidence:** low
- **Note:** R011 recorded no fresh device-code / ROPC sign-in tagged T1078.004. The run authenticated entirely through silent token reuse (T1550.001) from a warm MSAL cache, so no T1078.004-tagged event exists in the replay log. This is expected on a warm-cache run, not a script failure — but the technique is not evidenced in R011.json, so this finding is recorded at low confidence per triage policy.
- **Control:** CA-SIG003-Guests-RequireMFA — requires MFA for all guest and external account sign-ins regardless of network location.
- **Rationale:** Guest and external accounts in M365 tenants frequently lack MFA enforcement because default CA policies target only member users. An adversary who obtains a guest credential can acquire a delegated bearer token via ROPC without triggering a secondary factor, then pivot to discovery techniques. Requiring MFA for all guest sign-ins regardless of network location closes this initial-access gap.
- **Finding-triage record:** samples/finding-triage/t1078.004-r011-valid-accounts.json (Part B)
- **Finding-to-control mapping:** samples/finding-to-control/t1078.004-conditional_access-ca-sig003-guests-requiremfa.json

### T1087.004 — Account Discovery: Cloud Account

- **Tactic:** Discovery
- **Tool:** scripts/tool_list_users.py
- **Endpoint:** `GET /users`
- **Evidence:** samples/replay-log/R011.json
- **Objects enumerated:** 8 users (`GET /users`). T1087.004 was exercised across four surfaces this run: Surface A `GET /users` = 8 (success), Surface B `GET /applications` = 9 (success), Surface D `GET /servicePrincipals` = 415 (success), Surface C `GET /roleManagement/directory/roleAssignments` = **error, HTTP 400** (see Note).
- **Severity:** medium
- **Confidence:** high
- **Note:** Surface C (`tool_list_role_assignments`) failed with HTTP 400 `Request_BadRequest`: "Only one property can be expanded in a single query." The tool sends `$expand=principal,roleDefinition`; Graph v1.0 permits only one `$expand` property. This is a tool bug, not a tenant finding — role-assignment discovery produced no data this run. The technique's confidence remains high because Surfaces A/B/D succeeded with non-zero counts; the failure is isolated to one surface and tracked separately.
- **Control:** CA-COV008-BlockByLocation — restricts Graph API access to named trusted locations, shrinking the enumeration surface reachable from an untrusted network.
- **Rationale:** Bulk enumeration of /users returns tenant-wide user directory data that an adversary can use to build phishing target lists or identify high-privilege accounts for lateral movement. A location-based CA policy restricts Graph API access to named trusted locations, reducing the enumeration surface available to a compromised credential operating from an untrusted network. This control is most effective when combined with named location definitions that enumerate corporate egress ranges.
- **Finding-triage record:** samples/finding-triage/t1087.004-r011-account-discovery.json (Part B)
- **Finding-to-control mapping:** samples/finding-to-control/t1087.004-conditional_access-ca-cov008-blockbylocation.json

### T1069.003 — Permission Groups Discovery: Cloud Groups

- **Tactic:** Discovery
- **Tool:** scripts/tool_list_groups.py
- **Endpoint:** `GET /me/memberOf`
- **Evidence:** samples/replay-log/R011.json
- **Objects enumerated:** 19 groups
- **Severity:** medium
- **Confidence:** high
- **Control:** CA-SIF001-SignInFrequency-8h — forces re-authentication every 8 hours, capping the usable lifetime of a stolen delegated token.
- **Rationale:** Group membership enumeration via GET /groups and GET /me/memberOf reveals organizational structure and role affiliations — security groups, distribution lists, and Microsoft 365 groups — that guide adversary targeting for spear-phishing or privilege escalation. A sign-in frequency CA policy limits the usable lifetime of a stolen delegated token by requiring periodic re-authentication, constraining the adversary's enumeration window after initial compromise.
- **Finding-triage record:** samples/finding-triage/t1069.003-r011-group-discovery.json (Part B)
- **Finding-to-control mapping:** samples/finding-to-control/t1069.003-conditional_access-ca-sif001-signinfrequency-8h.json

### T1550.001 — Use Alternate Authentication Material: Application Access Token

- **Tactic:** Defense Evasion / Lateral Movement
- **Tool:** scripts/identity.py
- **Endpoint:** MSAL encrypted token cache (silent reuse; ADR 0005)
- **Evidence:** samples/replay-log/R011.json
- **Objects enumerated:** 10 token events (silent reuse across the run)
- **Severity:** high
- **Confidence:** high
- **Control:** Directory Readers (RBAC) — scopes directory read access to the minimum role, limiting what a replayed token can enumerate.
- **Rationale:** Application access token reuse allows an adversary who captures a delegated token to impersonate the victim account for the token's remaining lifetime without re-authenticating. When the compromised account holds Directory Readers or a broader directory role, the replayed token enables full tenant enumeration across users, groups, and role assignments. Scoping service and monitoring accounts to the minimum required role (e.g., a custom limited-read role rather than Directory Readers) reduces the blast radius of token theft and limits what an adversary can enumerate during the valid token window.
- **Finding-triage record:** samples/finding-triage/t1550.001-r011-token-reuse.json (Part B)
- **Finding-to-control mapping:** samples/finding-to-control/t1550.001-rbac-directory-readers.json

### T1526 — Cloud Service Discovery

- **Tactic:** Discovery
- **Tool:** scripts/tool_list_ca_policies.py
- **Endpoint:** `GET /identity/conditionalAccess/policies`
- **Evidence:** samples/replay-log/R011.json
- **Objects enumerated:** 25 Conditional Access policies
- **Severity:** high [‡]
- **Confidence:** high
- **Control:** Reports Reader (RBAC) — restricts CA-policy and reporting visibility to the least role a job function needs.
- **Rationale:** Enumeration of Conditional Access policies via GET /identity/conditionalAccess/policies exposes the defender's detection coverage and policy gaps to an adversary — revealing which user populations lack MFA, which locations are trusted, and which applications have no CA coverage. Access to CA policy configuration should be restricted to the minimum role required for the job function; accounts that only need audit or reporting visibility should hold Reports Reader rather than Security Reader or higher, which reduces the tenant-configuration attack surface available to a compromised account.
- **Finding-triage record:** samples/finding-triage/t1526-r011-ca-policy-discovery.json (Part B)
- **Finding-to-control mapping:** samples/finding-to-control/t1526-rbac-reports-reader.json

### T1518.001 — Software Discovery: Security Software Discovery

- **Tactic:** Discovery
- **Tool:** scripts/tool_dfi_health.py
- **Endpoint:** `GET /security/identities/sensors`
- **Evidence:** samples/replay-log/R011.json
- **Objects enumerated:** 3 DfI sensors
- **Severity:** high [‡]
- **Confidence:** high
- **Control:** Security Reader (RBAC) — gates DfI sensor-health reads behind an explicitly assigned security-reader-class role rather than a broadly delegated grant.
- **Rationale:** Enumeration of Microsoft Defender for Identity sensor health via GET /security/identities/sensors exposes the tenant's detection coverage — sensor count, deployment status, and open health issues — to an adversary. A sensor known to be unhealthy or absent can be exploited as a detection gap window for lateral movement activity. The SecurityIdentitiesSensors.Read.All scope is admin-consented and should be restricted to accounts that legitimately manage DfI sensor infrastructure; the minimum required Entra role for this endpoint should be explicitly assigned rather than broadly delegated.
- **Finding-triage record:** samples/finding-triage/t1518.001-r011-dfi-sensor-health.json (Part B)
- **Finding-to-control mapping:** samples/finding-to-control/t1518.001-rbac-security-reader.json

### T1082 — System Information Discovery

- **Tactic:** Discovery
- **Tool:** scripts/tool_intune_devices.py
- **Endpoint:** `GET /deviceManagement/managedDevices`
- **Evidence:** samples/replay-log/R011.json
- **Objects enumerated:** 1 managed device
- **Severity:** medium
- **Confidence:** high
- **Control:** Intune Service Administrator (RBAC) — limits managed-device inventory reads to designated device-management staff.
- **Rationale:** Enumeration of the Intune-managed device inventory via GET /deviceManagement/managedDevices reveals OS versions, compliance state, encryption status, and enrollment dates across the fleet. An adversary can use this data to identify non-compliant or unencrypted endpoints as lateral movement targets, correlate device ownership to high-value user accounts, and infer last-sync timestamps to time activity around stale device policies. DeviceManagementManagedDevices.Read.All is an Intune-admin-class scope; the accounts that hold it should be limited to device management staff and audited for unexpected additions.
- **Finding-triage record:** samples/finding-triage/t1082-r011-intune-devices.json (Part B)
- **Finding-to-control mapping:** samples/finding-to-control/t1082-rbac-intune-service-admin.json

### T1580 — Cloud Infrastructure Discovery

- **Tactic:** Discovery
- **Tool:** scripts/tool_purview_labels.py
- **Endpoint:** `GET /security/dataSecurityAndGovernance/sensitivityLabels`
- **Evidence:** samples/replay-log/R011.json
- **Objects enumerated:** 4 Purview sensitivity labels
- **Severity:** low
- **Confidence:** high
- **Control:** CA-PUR-001-RequireCompliantApp — restricts Purview access to approved client applications or compliant devices, reducing the surface to organization-managed clients.
- **Rationale:** Enumeration of Purview sensitivity labels via GET /security/dataSecurityAndGovernance/sensitivityLabels reveals the tenant's data classification taxonomy, including label names, enabled state, applicability scope (email, file, teamwork), and whether endpoint protection is active per label. An adversary with label names can direct later Collection techniques toward data classified as Confidential or higher, and route exfiltration through channels or file types that lack label coverage. SensitivityLabel.Read carries no Entra role gate — any user account with the scope consented on the client can call this endpoint. A Conditional Access policy restricting Microsoft Purview Compliance Portal access to approved client applications or compliant devices reduces the surface to organization-managed clients and blocks borrowed FOCI clients.
- **Finding-triage record:** samples/finding-triage/t1580-r011-purview-labels.json (Part B)
- **Finding-to-control mapping:** samples/finding-to-control/t1580-conditional-access-purview-require-compliant-app.json

### T1654 — Log Enumeration

- **Tactic:** Discovery
- **Tool:** scripts/tool_signin_logs.py
- **Endpoint:** `GET /auditLogs/signIns`
- **Evidence:** samples/replay-log/R011.json
- **Objects enumerated:** 30 sign-in records
- **Severity:** high [‡]
- **Confidence:** high
- **Control:** Reports Reader (RBAC) — restricts sign-in log access to designated security operations accounts.
- **Rationale:** Reading sign-in logs via GET /auditLogs/signIns gives an adversary visibility into the authentication telemetry the defending team uses to detect anomalies. With the full sign-in record an adversary can identify low-detection windows (periods of low sign-in volume), correlate failed then succeeded sign-ins to infer detection thresholds, and determine which accounts generate security alerts — then operate through accounts that do not. AuditLog.Read.All is gated by the Reports Reader role or higher; restricting Reports Reader assignments to designated security operations accounts reduces the number of compromised credential paths that expose authentication telemetry to an adversary.
- **Finding-triage record:** samples/finding-triage/t1654-r011-signin-logs.json (Part B)
- **Finding-to-control mapping:** samples/finding-to-control/t1654-rbac-reports-reader.json

---

## 4. Control mapping summary

| Technique | Control family | Control ID | Type | Pillar | NIST tenets |
|-----------|----------------|------------|------|--------|-------------|
| T1078.004 | conditional_access | CA-SIG003-Guests-RequireMFA | preventive | Identities | T4, T6 |
| T1087.004 | conditional_access | CA-COV008-BlockByLocation | preventive | Identities | T3, T4 |
| T1069.003 | conditional_access | CA-SIF001-SignInFrequency-8h | preventive | Identities | T3, T4, T6 |
| T1550.001 | rbac | Directory Readers | preventive | Identities | T4, T6 |
| T1526 | rbac | Reports Reader | preventive | Identities | T4, T6 |
| T1518.001 | rbac | Security Reader | preventive | Identities | T3, T4 |
| T1082 | rbac | Intune Service Administrator | preventive | Endpoints | T3, T4 |
| T1580 | conditional_access | CA-PUR-001-RequireCompliantApp | preventive | Data | T3, T4, T5 |
| T1654 | rbac | Reports Reader | preventive | Identities | T3, T4 |

All nine implemented techniques carry at least one finding-to-control mapping. Every row is
sourced from the corresponding record under samples/finding-to-control/ and validates against
schemas/finding-to-control/v0.1.json.

---

## 5. ROE record

- Consent helper: scripts/write_consent_r011.py
- Consent record written to: replay-logs/ (gitignored)
- Consolidated replay log: samples/replay-log/R011.json (Part B)
- Formal ROE run count: 6 → 7 (post-run)

---

## 6. Post-run actions (Derek)

- [ ] Add R011 row to phs-roe-consent-archive-v1.0.xlsx
- [ ] Update KPI Dashboard ROE Consent Runs count (6 → 7) and weekly notes
- [x] Part B brief: 9 finding-triage records committed, report complete

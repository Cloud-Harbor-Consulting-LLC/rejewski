# Project Harbor Sonar — Threat Model

- Version: v0.8
- Last updated: 2026-06-23
- Status: Living document
- Authors: Derek Morgan
- Related: ADR 0001 (Sprint 1 Rules of Engagement), ADR 0002 (Consent floor evidence), ADR 0003 (Technique Module Format), docs/guardrails.md, docs/techniques/, docs/attck-coverage.md

## Change log

- v0.8 (2026-06-23) — Sprint 2 W7 implementation. T1580 Cloud Infrastructure
  Discovery implemented (docs/techniques/T1580.md) via
  GET /security/dataSecurityAndGovernance/sensitivityLabels (sensitivity label
  inventory); original org/domains/subscribedSkus catalogued surfaces deferred.
  T1654 Log Enumeration added as implemented (docs/techniques/T1654.md) via
  GET /auditLogs/signIns; new technique, added directly as implemented (no prior
  catalogued stub). Total mapped techniques: 17 (9 implemented, 8 catalogued).
- v0.7 (2026-06-19) — Sprint 2 catalogue expansion. Six techniques catalogued:
  T1580 Cloud Infrastructure Discovery (docs/techniques/T1580.md), T1538 Cloud Service
  Dashboard (docs/techniques/T1538.md), T1213.003 Data from Information Repositories: Code
  Repositories (docs/techniques/T1213.003.md), T1530 Data from Cloud Storage
  (docs/techniques/T1530.md), T1619 Cloud Storage Object Discovery
  (docs/techniques/T1619.md), and T1114.002 Email Collection: Remote Email Collection
  (docs/techniques/T1114.002.md). **T1538 re-scoped**: previously listed as out of
  programmatic Rejewski scope (GUI-based), it is now catalogued for its programmatic Graph
  `/admin/serviceAnnouncement` and `/reports` service-health/usage surface; the interactive
  GUI-navigation posture remains out of scope. §5 active technique table and Sprint 2+
  catalogued subsection updated; §7 out-of-scope T1538 entry refined to the GUI posture
  only. Total mapped techniques: 16 (7 implemented, 9 catalogued).
- v0.6 (2026-06-05) — Sprint 1 W4 threat-model head-start. Three techniques catalogued
  for Sprint 2: T1082 System Information Discovery (docs/techniques/T1082.md),
  T1213.002 Data from Information Repositories: Sharepoint
  (docs/techniques/T1213.002.md), and T1482 Domain Trust Discovery
  (docs/techniques/T1482.md). §5 active technique table and Sprint 2+ catalogued
  subsection updated. Total mapped techniques: 10 (5 implemented, 5 catalogued).
- v0.5 (2026-06-03) — Sprint 1 W4 ATT&CK coverage doc. Two techniques catalogued for Sprint 2: T1087.003 Account Discovery: Email Account (docs/techniques/T1087.003.md created) and T1518.001 Software Discovery: Security Software Discovery (docs/techniques/T1518.001.md created). §5 active technique table and Sprint 2+ catalogued subsection updated. docs/attck-coverage.md introduced as the standalone coverage KPI reference. Total mapped techniques: 7 (5 implemented, 2 catalogued).
- v0.4 (2026-05-26) — Sprint 2 W5 pull-forward. T1526 Cloud Service Discovery activated for the /identity/conditionalAccess/policies surface (docs/techniques/T1526.md created). §5 active technique table updated to include T1526; Sprint 2+ catalogued subsection updated to reflect T1526 implementation status and CA policies surface. §8 adds T1526 cross-reference.
- v0.3 (2026-05-22) — Sprint 1 W3 catalogue expansion. §5 adds a Sprint 2+ catalogued techniques subsection covering T1526 Cloud Service Discovery (candidate Graph surfaces /subscribedSkus, /servicePrincipals, /applications, /organization documented for Sprint 2+ modelling) and T1538 Cloud Service Dashboard (catalogued as out of programmatic Rejewski scope; preserved for consumer awareness). §7 adds T1538 to the out-of-scope list.
- v0.2 (2026-05-14) — Tenant ID correction in §1 (cf3f9a61 → 76b87c33). Adversary-model note added to §3 covering the no-tenant-app-reg posture and first-party client borrowing. §5 extended with T1069.003 deferred surface (transitiveMemberOf, directoryRoles). ADR 0003 cross-reference added.
- v0.1 (2026-05-14) — Initial outline shipped Thu morning as part of the Sat-item pull-forward bundle.

---

## 1. Scope and target environment

Project Harbor Sonar (codename Rejewski) is an adversary-emulation toolkit. It exercises a defined subset of MITRE ATT&CK techniques against a Microsoft 365 sandbox tenant to produce evidence that downstream detection-engineering work can validate against.

**Target environment.** The sole target of every Rejewski run is the cloudharbordemo sandbox tenant.

| Property | Value |
|----------|-------|
| Tenant display name | cloudharbordemo |
| Tenant primary domain | cloudharbordemo.onmicrosoft.com |
| Tenant ID | 76b87c33-6178-4ff9-94a7-164792c8e4c6 |
| Licensing | Microsoft 365 E5 trial (rotating) |
| User population | Seeded test users only (per G-7) |

The Rejewski operator workstation runs the SDK and PowerShell sessions outside the target tenant. The Planner host tenant where Project Harbor Sonar tasks are tracked (cf3f9a61) is a separate, unrelated tenant — Rejewski never authenticates to it from inside a technique run.

## 2. Stakeholders

| Stakeholder | Interest |
|-------------|----------|
| Project owner (Derek Morgan) | Sprint planning, technique scope, guardrail authorship, evidence sign-off |
| Future detection-engineering consumers | Replayable evidence files; stable technique module shape per ADR 0003 |
| Public-repo readers | Cited techniques, guardrails, and ADRs as a reference for safe adversary emulation patterns |

## 3. Adversary model

Rejewski emulates an **external, credentialed adversary** who has already obtained valid cloud-only Entra ID credentials for one or more test accounts in the target tenant. The adversary's starting capabilities are:

- A valid user-credential pair for a seeded sandbox account.
- Knowledge that the target tenant exists and which domain to authenticate against.
- Access to a Microsoft-owned, FOCI-eligible first-party OAuth client (used for sign-in).

The adversary's starting capabilities **do not include**:

- Any pre-existing tenant-side application registration. Sprint 1 explicitly emulates the posture of an adversary who has **not** yet created or compromised a tenant app reg. Gaining one is itself a Sprint 2+ technique.
- Admin role assignments. The seeded test accounts are ordinary users.
- Tenant-side persistence artifacts (mailbox rules, OAuth grants, app passwords). These are Sprint 2+ targets, not starting state.

**No-tenant-app-reg posture (committed 2026-05-13).** Every Sprint 1 technique runs under a borrowed first-party Microsoft OAuth client — Microsoft Graph Command Line Tools (14d82eec-204b-4c2f-b7e8-296a70dab67e) by default. The choice is deliberate: it leaves no Rejewski-controlled application object in the sandbox tenant and accurately models an early-stage adversary who has not yet established their own tenant footprint. G-2 and G-4 in docs/guardrails.md codify this posture as enforceable rules; ADR 0003 surfaces it in every technique module's front matter via the first_party_client and first_party_client_id fields.

**Adversary objective.** Reconnaissance and discovery in Sprint 1 — enumerate accounts and groups to inform later-sprint targeting. Write-side objectives (persistence, lateral movement, exfiltration) are out of scope and gated behind a consent-floor uplift ADR.

## 4. Assets and high-value targets

| Asset | Sensitivity in sandbox | Real-world analog |
|-------|------------------------|--------------------|
| Seeded test user accounts | Low (G-7 fakes) | Real employee identities |
| Sandbox group memberships | Low | Real privilege-bearing group structures |
| Graph audit log entries | Operational signal | Defender telemetry surface |
| Evidence ledger (logs/rejewski-audit.jsonl) | High (operational integrity) | Internal red-team activity records |
| SharePoint Evidence folder | High (audit chain of custody) | Engagement evidence vault |

Sandbox assets carry no real-world sensitivity, but the **evidence ledger** and **SharePoint Evidence folder** do — they are the chain of custody that grounds every KPI claim Rejewski makes downstream.

## 5. Active technique scope

The following MITRE ATT&CK techniques are implemented or catalogued in Rejewski, in
kill-chain order. Sprint 1 shipped T1078.004, T1087.004, T1069.003, T1550.001, and T1526.
T1087.003 and T1518.001 were catalogued Sprint 1 W4 (2026-06-03). T1082, T1213.002,
and T1482 were catalogued Sprint 1 W4 (2026-06-05). T1580, T1538, T1213.003, T1530,
T1619, and T1114.002 were catalogued in the Sprint 2 catalogue expansion (2026-06-19).
T1580 was implemented and T1654 added as implemented in Sprint 2 W7 (2026-06-23),
bringing the total to 17 mapped techniques. The authoritative coverage count
and path-to-target table are in docs/attck-coverage.md.

| Technique | Tactic | Status | Sprint | Module |
|-----------|--------|--------|--------|--------|
| T1078.004 Valid Accounts: Cloud Accounts | Initial Access | Implemented | 1 | docs/techniques/T1078.004.md |
| T1087.004 Account Discovery: Cloud Account | Discovery | Implemented | 1 | docs/techniques/T1087.004.md |
| T1069.003 Permission Groups Discovery: Cloud Groups | Discovery | Implemented | 1 | docs/techniques/T1069.003.md |
| T1550.001 Use Alternate Authentication Material: Application Access Token | Defense Evasion / Lateral Movement | Implemented | 1 | *No module yet — ADR 0005 + scripts/identity.py* |
| T1526 Cloud Service Discovery | Discovery | Implemented | 2 W5 pull-forward | docs/techniques/T1526.md |
| T1087.003 Account Discovery: Email Account | Discovery | Catalogued | 2 | docs/techniques/T1087.003.md |
| T1518.001 Software Discovery: Security Software Discovery | Discovery | Catalogued | 2 | docs/techniques/T1518.001.md |
| T1082 System Information Discovery | Discovery | Catalogued | 2 | docs/techniques/T1082.md |
| T1213.002 Data from Information Repositories: Sharepoint | Collection | Catalogued | 2 | docs/techniques/T1213.002.md |
| T1482 Domain Trust Discovery | Discovery | Catalogued | 2 | docs/techniques/T1482.md |
| T1580 Cloud Infrastructure Discovery | Discovery | Implemented | 2 | docs/techniques/T1580.md |
| T1538 Cloud Service Dashboard | Discovery | Catalogued | 2 | docs/techniques/T1538.md |
| T1213.003 Data from Information Repositories: Code Repositories | Collection | Catalogued | 2 | docs/techniques/T1213.003.md |
| T1530 Data from Cloud Storage | Collection | Catalogued | 2 | docs/techniques/T1530.md |
| T1619 Cloud Storage Object Discovery | Discovery | Catalogued | 2 | docs/techniques/T1619.md |
| T1114.002 Email Collection: Remote Email Collection | Collection | Catalogued | 2 | docs/techniques/T1114.002.md |
| T1654 Log Enumeration | Discovery | Implemented | 2 | docs/techniques/T1654.md |

Each module follows the ADR 0003 format: YAML front matter, eight required sections, and cited cross-references to this threat model, the governing ADR(s), and docs/guardrails.md.

**T1069.003 deferred surface.** Two Graph endpoints relevant to permission-groups discovery are intentionally out of Sprint 1 scope and deferred to Sprint 2+ uplift:

- `GET /me/transitiveMemberOf` — transitive group membership across nested groups. Sprint 1 captures direct memberships only via `GET /me/memberOf`.
- `GET /directoryRoles` — enumeration of Entra ID directory roles and their members. Sprint 1 omits this surface entirely; role discovery is therefore partial in T1069.003.

The deferral is not because these endpoints are dangerous — both are read-only and inside the Sprint 1 consent-floor scope set — but because each opens a meaningfully larger result surface that needs its own row-cap calibration (per G-9) and detection-baseline pass before Rejewski emulates it. Sprint 2 work will pick them up.

**Sprint 2+ catalogued techniques.** The following techniques are catalogued in this threat model — technique modules exist per ADR 0003 format, but no scripts have been written and no sandbox runs executed. Each activates when its sprint opens. The full coverage map is in docs/attck-coverage.md.

| Technique | Tactic | Status | Surface |
|-----------|--------|--------|---------|
| T1526 Cloud Service Discovery | Discovery | Implemented — Sprint 2 W5 pull-forward (2026-05-26) | /identity/conditionalAccess/policies (active); /subscribedSkus, /servicePrincipals, /applications, /organization (deferred to Sprint 2 main body) |
| T1087.003 Account Discovery: Email Account | Discovery | Catalogued — Sprint 2 (2026-06-03) | GET /users with mail, proxyAddresses, mailEnabled, mailNickname, userType $select projection |
| T1518.001 Software Discovery: Security Software Discovery | Discovery | Catalogued — Sprint 2 (2026-06-03) | GET /subscribedSkus (service plan enumeration to identify active Microsoft security products) |
| T1082 System Information Discovery | Discovery | Catalogued — Sprint 2 (2026-06-05) | GET /organization (tenant name, hybrid status, provisioned plans, verified domains, security contacts) |
| T1213.002 Data from Information Repositories: Sharepoint | Collection | Catalogued — Sprint 2 (2026-06-05) | GET /sites, GET /sites/{id}/drives, GET /sites/{id}/lists — requires Sites.Read.All scope |
| T1482 Domain Trust Discovery | Discovery | Catalogued — Sprint 2 (2026-06-05) | GET /domains, GET /domains/{id}/federationConfiguration — requires Domain.Read.All scope |
| T1580 Cloud Infrastructure Discovery | Discovery | Implemented — Sprint 2 W7 (2026-06-23) | GET /security/dataSecurityAndGovernance/sensitivityLabels (active — Purview sensitivity-label inventory; SensitivityLabel.Read delegated, no Entra role required). Original surfaces GET /organization, GET /domains, GET /subscribedSkus deferred as complementary surfaces (see docs/techniques/T1580.md Limitations). |
| T1654 Log Enumeration | Discovery | Implemented — Sprint 2 W7 (2026-06-23) | GET /auditLogs/signIns — requires AuditLog.Read.All + Reports Reader/Security Reader (or higher) Entra role on the signed-in operator. Mandatory `$filter=createdDateTime ge <window-start>` (default 7-day lookback). |
| T1538 Cloud Service Dashboard | Discovery | Catalogued — Sprint 2 (2026-06-19) — programmatic surface only | GET /admin/serviceAnnouncement/healthOverviews, /admin/serviceAnnouncement/issues, /reports/getOffice365ActiveUserDetail — requires ServiceHealth.Read.All, Reports.Read.All. GUI-navigation posture remains out of scope (§7). |
| T1213.003 Data from Information Repositories: Code Repositories | Collection | Catalogued — Sprint 2 (2026-06-19) | GET /sites?search=*, GET /sites/{id}/drives, GET /sites/{id}/lists — requires Sites.Read.All; SharePoint-surfaced code content only |
| T1530 Data from Cloud Storage | Collection | Catalogued — Sprint 2 (2026-06-19) | GET /drives, GET /users/{id}/drive/root/children, GET /groups/{id}/drive/root/children — requires Files.Read.All; metadata only per G-7 |
| T1619 Cloud Storage Object Discovery | Discovery | Catalogued — Sprint 2 (2026-06-19) | GET /drives, GET /drives/{id}/root/children, GET /sites/{id}/drives — requires Files.Read.All, Sites.Read.All; discovery phase preceding T1530 |
| T1114.002 Email Collection: Remote Email Collection | Collection | Catalogued — Sprint 2 (2026-06-19) | GET /users/{id}/mailFolders, GET /users/{id}/messages ($select metadata projection), GET /users/{id}/mailFolders/{id}/messages — Mail.Read (delegated, self) or Mail.ReadBasic.All / Mail.Read.All (application, cross-user) |

**T1526 Cloud Service Discovery.** An adversary with valid cloud credentials enumerates cloud services, security configurations, and tenant metadata to inventory the target environment before engaging Collection or Lateral Movement objectives. T1526 is now active in Rejewski for the Conditional Access policies surface (Sprint 2 W5 pull-forward, 2026-05-26): `GET /identity/conditionalAccess/policies` enumerates all CA policies in the tenant, revealing which users/groups are covered, what grant controls are enforced (MFA, compliant device, block), which applications are in scope, and whether any policies are in report-only mode. This surface requires the signed-in user to hold at least Security Reader — making it a post-privilege-escalation discovery step in the kill chain (see docs/techniques/T1526.md §"Required privilege" for the full operator prerequisite and attack strategy note).

Additional T1526 surfaces remain in the Sprint 2 main body catalogue and are not yet active: `GET /subscribedSkus` (licensed SKUs and service plan details), `GET /servicePrincipals` (third-party and Microsoft service principals), `GET /applications` (tenant app registrations), and `GET /organization` (tenant display name, verified domains, country, technical contacts). Each additional surface needs its own row-cap calibration (per G-9) and will be modelled as a separate technique surface entry when Sprint 2 opens. T1526 is a natural complement to T1087.004 and T1069.003 in the Discovery kill-chain leg: account discovery + group discovery + service/policy discovery together map the tenant's identity-and-configuration footprint.

**T1538 Cloud Service Dashboard (re-scoped 2026-06-19).** This technique describes
adversary use of a cloud-provider service dashboard — historically framed as the GUI
surfaces (Azure portal, Microsoft 365 admin center, Defender portal, Entra admin center)
driven by stolen credentials through human browser navigation. Through v0.6 this was
catalogued as **out of programmatic Rejewski scope** on the basis that Rejewski drives no
browser sessions. v0.7 refines that boundary: the same service-dashboard *data* — service
health per workload, active incidents/advisories, and per-service usage — is also exposed
**programmatically** through Microsoft Graph (`GET /admin/serviceAnnouncement/healthOverviews`,
`/admin/serviceAnnouncement/issues`, `GET /reports/getOffice365ActiveUserDetail`). That
programmatic surface **is** in Rejewski's wheelhouse and is now catalogued at
docs/techniques/T1538.md, mirroring the operational service-health framing used in
T1518.001 (a degraded security workload signals a reduced-detection-coverage window). The
distinction consumers must understand: Rejewski's T1538 emulation produces **Graph-API
audit signal** (MicrosoftGraphActivityLogs on the serviceAnnouncement/reports endpoints),
**not** the interactive admin-center session and portal sign-in signals that a GUI-driven
T1538 would produce. The GUI-navigation posture therefore remains out of scope (§7);
detection coverage for *that* posture must still come from portal-session telemetry sourced
elsewhere.

## 6. Trust boundaries

```
+------------------------------+        +-----------------------------+
| Rejewski operator workstation|  ----> | Microsoft Graph (login.     |
| - SDK runtime                |        | microsoftonline.com,        |
| - PowerShell session         |        | graph.microsoft.com)        |
| - logs/rejewski-audit.jsonl  |        +-----------------------------+
| - SharePoint Evidence sync   |                       |
+------------------------------+                       v
                                            +---------------------+
                                            | cloudharbordemo     |
                                            | sandbox tenant      |
                                            | (76b87c33)          |
                                            +---------------------+
```

Trust boundary 1: operator workstation → Microsoft authentication endpoint. Crossed on every device-code sign-in (T1078.004). G-4 bounds which client crosses; G-8 bounds how long the crossing lives.

Trust boundary 2: Microsoft authentication endpoint → sandbox tenant Graph surface. Crossed on every authenticated Graph call. G-1 bounds the tenant; G-3 bounds the scopes; G-9 bounds the result volume.

Trust boundary 3: sandbox tenant → evidence outputs. Crossed when audit-log content lands in logs/rejewski-audit.jsonl and is copied to SharePoint Evidence. G-5 mandates capture; G-6 mandates redaction before any audit content reaches the public Rejewski repo.

## 7. Out of scope

The following are explicitly out of scope for Sprint 1 and are tracked for later sprints via ADR:

- Tenant app registration creation, modification, or compromise (G-2).
- Write-side Graph scopes (G-3): Mail.Send, Directory.ReadWrite.All, Group.ReadWrite.All, admin-consent scopes.
- Additional FOCI clients beyond Graph Command Line Tools (G-4): Azure CLI, Visual Studio, others.
- Hybrid identity flows (synced on-prem AD accounts).
- Token persistence beyond the session-keep-warm window (G-8).
- Conditional-access bypasses (location spoofing, device compliance manipulation).
- Real-user data of any kind (G-7).
- Production tenants other than cloudharbordemo (G-1).
- Cloud-dashboard **GUI-navigation** reconnaissance — the interactive browser-driven posture of T1538 (Azure portal, M365 admin center, Defender/Entra portals). Rejewski drives no browser sessions, so this posture stays out of scope; consumers must source dashboard-session signal from other tooling. Note the boundary refinement (v0.7): the **programmatic** service-dashboard surface of T1538 (Graph `/admin/serviceAnnouncement` and `/reports`) **is** in scope and is catalogued in §5 — only the GUI-navigation posture is excluded here.

## 8. References

- ADR 0001 — Sprint 1 Rules of Engagement
- ADR 0002 — Consent floor evidence format
- ADR 0003 — Technique Module Format
- ADR 0005 — Token Persistence and Reuse (T1550.001 implementation basis)
- docs/guardrails.md — G-1 through G-9
- docs/attck-coverage.md — authoritative technique count and path-to-target table
- docs/techniques/T1078.004.md, T1087.004.md, T1069.003.md, T1526.md, T1087.003.md, T1518.001.md, T1082.md, T1213.002.md, T1482.md, T1580.md, T1538.md, T1213.003.md, T1530.md, T1619.md, T1114.002.md, T1654.md
- MITRE ATT&CK Enterprise — <https://attack.mitre.org/matrices/enterprise/>

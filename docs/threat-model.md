# Project Harbor Sonar — Threat Model

- Version: v0.5
- Last updated: 2026-06-03
- Status: Living document
- Authors: Derek Morgan
- Related: ADR 0001 (Sprint 1 Rules of Engagement), ADR 0002 (Consent floor evidence), ADR 0003 (Technique Module Format), docs/guardrails.md, docs/techniques/, docs/attck-coverage.md

## Change log

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

**No-tenant-app-reg posture (committed 2026-05-13).** Every Sprint 1 technique runs under a borrowed first-party Microsoft OAuth client — Microsoft Graph PowerShell (14d82eec-204b-4c2f-b7e8-296a70dab67e) by default. The choice is deliberate: it leaves no Rejewski-controlled application object in the sandbox tenant and accurately models an early-stage adversary who has not yet established their own tenant footprint. G-2 and G-4 in docs/guardrails.md codify this posture as enforceable rules; ADR 0003 surfaces it in every technique module's front matter via the first_party_client and first_party_client_id fields.

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
T1087.003 and T1518.001 were catalogued Sprint 1 W4 (2026-06-03). The authoritative
coverage count and path-to-target table are in docs/attck-coverage.md.

| Technique | Tactic | Status | Sprint | Module |
|-----------|--------|--------|--------|--------|
| T1078.004 Valid Accounts: Cloud Accounts | Initial Access | Implemented | 1 | docs/techniques/T1078.004.md |
| T1087.004 Account Discovery: Cloud Account | Discovery | Implemented | 1 | docs/techniques/T1087.004.md |
| T1069.003 Permission Groups Discovery: Cloud Groups | Discovery | Implemented | 1 | docs/techniques/T1069.003.md |
| T1550.001 Use Alternate Authentication Material: Application Access Token | Defense Evasion / Lateral Movement | Implemented | 1 | *No module yet — ADR 0005 + scripts/identity.py* |
| T1526 Cloud Service Discovery | Discovery | Implemented | 2 W5 pull-forward | docs/techniques/T1526.md |
| T1087.003 Account Discovery: Email Account | Discovery | Catalogued | 2 | docs/techniques/T1087.003.md |
| T1518.001 Software Discovery: Security Software Discovery | Discovery | Catalogued | 2 | docs/techniques/T1518.001.md |

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
| T1538 Cloud Service Dashboard | Discovery | Out of programmatic Rejewski scope | Azure portal / Microsoft 365 admin center / Defender portal / Entra admin center GUIs |

**T1526 Cloud Service Discovery.** An adversary with valid cloud credentials enumerates cloud services, security configurations, and tenant metadata to inventory the target environment before engaging Collection or Lateral Movement objectives. T1526 is now active in Rejewski for the Conditional Access policies surface (Sprint 2 W5 pull-forward, 2026-05-26): `GET /identity/conditionalAccess/policies` enumerates all CA policies in the tenant, revealing which users/groups are covered, what grant controls are enforced (MFA, compliant device, block), which applications are in scope, and whether any policies are in report-only mode. This surface requires the signed-in user to hold at least Security Reader — making it a post-privilege-escalation discovery step in the kill chain (see docs/techniques/T1526.md §"Required privilege" for the full operator prerequisite and attack strategy note).

Additional T1526 surfaces remain in the Sprint 2 main body catalogue and are not yet active: `GET /subscribedSkus` (licensed SKUs and service plan details), `GET /servicePrincipals` (third-party and Microsoft service principals), `GET /applications` (tenant app registrations), and `GET /organization` (tenant display name, verified domains, country, technical contacts). Each additional surface needs its own row-cap calibration (per G-9) and will be modelled as a separate technique surface entry when Sprint 2 opens. T1526 is a natural complement to T1087.004 and T1069.003 in the Discovery kill-chain leg: account discovery + group discovery + service/policy discovery together map the tenant's identity-and-configuration footprint.

**T1538 Cloud Service Dashboard.** This technique describes adversary use of a cloud-provider GUI dashboard — Azure portal (portal.azure.com), Microsoft 365 admin center (admin.microsoft.com), Defender portal (security.microsoft.com), or Entra admin center (entra.microsoft.com) — with stolen credentials, to enumerate services, resources, and configurations through human-driven browser navigation rather than API calls. Rejewski is a programmatic Graph client and does not drive browser sessions, so T1538 is **catalogued but not in scope for Rejewski emulation**. It is recorded here so consumers of Rejewski's evidence understand: when Rejewski simulates Discovery, it produces Graph-API audit signal (sign-in logs, audit logs, Defender for Cloud Apps anomaly hits on programmatic enumeration) — it does **not** produce the dashboard-session and interactive-GUI signals that T1538 emulation would require. Detection coverage for T1538 must come from other tooling.

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
- Additional FOCI clients beyond Graph PowerShell (G-4): Azure CLI, Visual Studio, others.
- Hybrid identity flows (synced on-prem AD accounts).
- Token persistence beyond the session-keep-warm window (G-8).
- Conditional-access bypasses (location spoofing, device compliance manipulation).
- Real-user data of any kind (G-7).
- Production tenants other than cloudharbordemo (G-1).
- Cloud-dashboard GUI reconnaissance (T1538). Catalogued in §5 but out of programmatic Rejewski scope; consumers of Rejewski evidence must source dashboard-session signal from other tooling.

## 8. References

- ADR 0001 — Sprint 1 Rules of Engagement
- ADR 0002 — Consent floor evidence format
- ADR 0003 — Technique Module Format
- ADR 0005 — Token Persistence and Reuse (T1550.001 implementation basis)
- docs/guardrails.md — G-1 through G-9
- docs/attck-coverage.md — authoritative technique count and path-to-target table
- docs/techniques/T1078.004.md, T1087.004.md, T1069.003.md, T1526.md, T1087.003.md, T1518.001.md
- MITRE ATT&CK Enterprise — <https://attack.mitre.org/matrices/enterprise/>

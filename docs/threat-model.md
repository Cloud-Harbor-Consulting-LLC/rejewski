# Project Harbor Sonar — Threat Model

- Version: v0.2
- Last updated: 2026-05-14
- Status: Living document
- Authors: Derek Morgan
- Related: ADR 0001 (Sprint 1 Rules of Engagement), ADR 0002 (Consent floor evidence), ADR 0003 (Technique Module Format), docs/guardrails.md, docs/techniques/

## Change log

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

## 5. Sprint 1 technique scope

Three MITRE ATT&CK techniques are in scope for Sprint 1, in kill-chain order:

| Technique | Tactic | Module |
|-----------|--------|--------|
| T1078.004 Valid Accounts: Cloud Accounts | Initial Access | docs/techniques/T1078.004.md |
| T1087.004 Account Discovery: Cloud Account | Discovery | docs/techniques/T1087.004.md |
| T1069.003 Permission Groups Discovery: Cloud Groups | Discovery | docs/techniques/T1069.003.md |

Each module follows the ADR 0003 format: YAML front matter, eight required sections, and cited cross-references to this threat model, the governing ADR(s), and docs/guardrails.md.

**T1069.003 deferred surface.** Two Graph endpoints relevant to permission-groups discovery are intentionally out of Sprint 1 scope and deferred to Sprint 2+ uplift:

- `GET /me/transitiveMemberOf` — transitive group membership across nested groups. Sprint 1 captures direct memberships only via `GET /me/memberOf`.
- `GET /directoryRoles` — enumeration of Entra ID directory roles and their members. Sprint 1 omits this surface entirely; role discovery is therefore partial in T1069.003.

The deferral is not because these endpoints are dangerous — both are read-only and inside the Sprint 1 consent-floor scope set — but because each opens a meaningfully larger result surface that needs its own row-cap calibration (per G-9) and detection-baseline pass before Rejewski emulates it. Sprint 2 work will pick them up.

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

## 8. References

- ADR 0001 — Sprint 1 Rules of Engagement
- ADR 0002 — Consent floor evidence format
- ADR 0003 — Technique Module Format
- docs/guardrails.md — G-1 through G-9
- docs/techniques/T1078.004.md, T1087.004.md, T1069.003.md
- MITRE ATT&CK Enterprise — <https://attack.mitre.org/matrices/enterprise/>

# Rejewski ATT&CK Coverage Map

- Version: v0.8
- Last updated: 2026-08-15
- Status: Living document — updated at each sprint checkpoint
- Authors: Derek Morgan
- Related: docs/threat-model.md, docs/techniques/, docs/guardrails.md

---

## Overview

This document is the single reference for every MITRE ATT&CK technique that Rejewski
maps, catalogues, or explicitly excludes. It is the authoritative source for the
"ATT&CK techniques mapped" KPI tracked in the Sprint Checkpoint KPIs tab of
phs-kpi-dashboard-v1.0.xlsx.

**Current count:** 20 unique techniques (13 implemented, 7 catalogued, 0 excluded-and-counted)

**Sprint 2 checkpoint target (Thu 2026-07-02):** 10 unique techniques

**v1.0 target (Sat 2026-10-24):** 25 unique techniques

---

## Technique table

| Technique | Name | Tactic | Status | Module | Script(s) |
|-----------|------|--------|--------|--------|-----------|
| T1078.004 | Valid Accounts: Cloud Accounts | Initial Access | Implemented — Sprint 1 | docs/techniques/T1078.004.md | scripts/identity.py |
| T1087.004 | Account Discovery: Cloud Account | Discovery | Implemented — Sprint 1 | docs/techniques/T1087.004.md | scripts/tool_list_users.py, scripts/tool_list_applications.py, scripts/tool_list_role_assignments.py, scripts/tool_list_service_principals.py, scripts/tool_list_oauth_grants.py |
| T1069.003 | Permission Groups Discovery: Cloud Groups | Discovery | Implemented — Sprint 1 | docs/techniques/T1069.003.md | scripts/tool_list_groups.py |
| T1550.001 | Use Alternate Authentication Material: Application Access Token | Defense Evasion / Lateral Movement | Implemented — Sprint 1 | docs/techniques/T1550.001.md | scripts/identity.py (ADR 0005) |
| T1526 | Cloud Service Discovery | Discovery | Implemented — Sprint 2 W5 pull-forward | docs/techniques/T1526.md | scripts/tool_list_ca_policies.py |
| T1087.003 | Account Discovery: Email Account | Discovery | Catalogued — Sprint 2 | docs/techniques/T1087.003.md | *Pending Sprint 2* |
| T1518.001 | Software Discovery: Security Software Discovery | Discovery | Implemented — Sprint 2 | docs/techniques/T1518.001.md | scripts/tool_dfi_health.py |
| T1082 | System Information Discovery | Discovery | Implemented — Sprint 2 | docs/techniques/T1082.md | scripts/tool_intune_devices.py |
| T1213.002 | Data from Information Repositories: Sharepoint | Collection | Implemented — Sprint 4 (Surface A) | docs/techniques/T1213.002.md | scripts/tool_list_sharepoint_sites.py |
| T1482 | Domain Trust Discovery | Discovery | Catalogued — Sprint 2 | docs/techniques/T1482.md | *Pending Sprint 2* |
| T1580 | Cloud Infrastructure Discovery | Discovery | Implemented — Sprint 2 | docs/techniques/T1580.md | scripts/tool_purview_labels.py |
| T1538 | Cloud Service Dashboard | Discovery | Catalogued — Sprint 2 | docs/techniques/T1538.md | *Pending Sprint 2* |
| T1213.003 | Data from Information Repositories: Code Repositories | Collection | Catalogued — Sprint 2 | docs/techniques/T1213.003.md | *Pending Sprint 2* |
| T1530 | Data from Cloud Storage | Collection | Catalogued — Sprint 2 | docs/techniques/T1530.md | *Pending Sprint 2* |
| T1619 | Cloud Storage Object Discovery | Discovery | Catalogued — Sprint 2 | docs/techniques/T1619.md | *Pending Sprint 2* |
| T1114.002 | Email Collection: Remote Email Collection | Collection | Implemented — Sprint 4 (Surface A) | docs/techniques/T1114.002.md | scripts/tool_list_inbox_rules.py |
| T1654 | Log Enumeration | Discovery | Implemented — Sprint 2 | docs/techniques/T1654.md | scripts/tool_signin_logs.py, scripts/tool_list_security_alerts.py |
| T1114.003 | Email Collection: Email Forwarding Rule | Collection | Implemented — Sprint 4 W14 | docs/techniques/T1114.003.md | scripts/tool_list_inbox_rules.py |
| T1033 | System Owner/User Discovery | Discovery | Implemented — Sprint 4 W14 | docs/techniques/T1033.md | scripts/identity.py, scripts/step4-token-smoke.py, scripts/tool_list_role_assignments.py |
| T1528 | Steal Application Access Token | Credential Access | Catalogued — Sprint 4 | docs/techniques/T1528.md | scripts/tool_list_oauth_grants.py, scripts/tool_list_service_principals.py (recon surface; token theft not emulated) |

**Status definitions:**

- **Implemented** — a working script exists and at least one consented sandbox run has produced replay-log evidence.
- **Catalogued** — a technique module exists per ADR 0003 format, defining scope and implementation path, but no script has been written and no sandbox run has been executed.
- **Excluded** — explicitly out of Rejewski scope; documented in docs/threat-model.md §7.

---

## T1550.001 module gap — RESOLVED

Resolved (B024, 2026-06-11): the technique module now exists at
docs/techniques/T1550.001.md, authored per ADR 0003 format against scripts/identity.py
(the borrowed-token persistence helper shipped Sprint 1, W2, Tue 2026-05-19) and
ADR 0005 (Token Persistence and Reuse). The Module column at the T1550.001 row above
points to it. No gap remains.

---

## Tactic distribution

| Tactic | Techniques | IDs |
|--------|-----------|-----|
| Initial Access | 1 | T1078.004 |
| Discovery | 12 | T1087.004, T1069.003, T1526, T1087.003, T1518.001, T1082, T1482, T1580, T1538, T1619, T1654, T1033 |
| Collection | 5 | T1213.002, T1213.003, T1530, T1114.002, T1114.003 |
| Credential Access | 1 | T1528 |
| Defense Evasion / Lateral Movement | 1 | T1550.001 |

Discovery dominates the current coverage, consistent with Rejewski's Sprint 1–2
recon-and-enumeration focus. The tactic spread broadens in Sprints 3–5 as the tool
adds Collection, Credential Access, and Persistence coverage.

---

## Kill chain position

```
Initial Access     Discovery                        (Defense Evasion / Lat. Mov.)
──────────────     ──────────────────────────────   ───────────────────────────
T1078.004          T1087.004  T1069.003  T1526       T1550.001
Valid Accounts     Account    Groups     Service
Cloud Accounts     Discovery  Discovery  Discovery

                   T1087.003  T1518.001  T1082       T1482
                   Email      Security   System      Domain Trust
                   Account    Software   Info         Discovery

                   T1580      T1538      T1619       T1654
                   Cloud      Cloud Svc  Cloud Stor. Log
                   Infra      Dashboard  Object Disc Enumeration

Collection
──────────────────────────────────────────────────────────
T1213.002         T1213.003          T1530         T1114.002
Info Repos:       Info Repos:        Data from     Remote Email
SharePoint        Code Repos         Cloud Storage Collection
```

T1078.004 is the prerequisite for every downstream technique — no Graph call runs without
a valid sign-in. T1087.004 and T1069.003 build the account and group landscape. T1526
extends the picture to service and policy configuration. T1087.003 (email surface) and
T1518.001 (security software posture) add the information an adversary needs to select
targets and avoid detection. T1550.001 operationalises the token that T1078.004 acquires.

---

## Path to Sprint 2 target (10 techniques)

| Sprint | Techniques added | Running total |
|--------|-----------------|---------------|
| S1 (W1–W3) | T1078.004, T1087.004, T1069.003, T1550.001, T1526 | 5 |
| S1 W4 (2026-06-03) | T1087.003, T1518.001 | **7** |
| S1 W4b (2026-06-05) | T1082, T1213.002, T1482 | **10** |
| S2 catalogue expansion (2026-06-19) | T1580, T1538, T1213.003, T1530, T1619, T1114.002 | **16** |
| S2 W7 implementation (2026-06-23) | T1580 implemented (Tool 9); T1654 added as implemented (Tool 10) | **17** |
| S4 W14 ATT&CK expansion (2026-08-15) | T1114.003 + T1033 implemented; T1528 catalogued | **20** |

Sprint 2 checkpoint target of 10 techniques reached and exceeded (16 catalogued/implemented
ahead of the Thu 2026-07-02 checkpoint). Technique selection for the Sprint 3
checkpoint target (TBD at S2 kick-off) opens when Sprint 2 begins.
Candidates to select at the S2 retro from the Sprint 2+ catalogue in docs/threat-model.md:

- T1069.003 deferred surfaces (transitiveMemberOf, directoryRoles) — already modelled,
  could split into a sub-entry if ATT&CK attribution differs.
- T1526 deferred surfaces (subscribedSkus, organization, servicePrincipals,
  applications) — additional T1526 sub-surfaces or a distinct T1082 mapping.
- T1213.002 Data from Information Repositories: SharePoint — site/list enumeration
  via GET /sites; requires Sites.Read.All scope uplift.
- T1003 / T1552 credential exposure surfaces if a read-only enumeration path exists
  (e.g., authentication methods registered per user).

Selection is at Derek's discretion at the S2 kick-off or the S1 checkpoint retro.

---

## Excluded techniques

No techniques are currently excluded-and-counted.

**T1538 Cloud Service Dashboard re-scoped (2026-06-19).** T1538 was previously excluded on
the basis that the technique describes human-driven GUI dashboard navigation and Rejewski
is a programmatic Graph client. That exclusion is now refined: the *interactive GUI
navigation* posture remains out of scope (Rejewski drives no browser sessions), but the
*programmatic service-health and service-usage surface* exposed through Microsoft Graph
`/admin/serviceAnnouncement` and `/reports` is in scope and is now catalogued at
docs/techniques/T1538.md. The technique therefore moves from the excluded table into the
catalogued set above. See docs/threat-model.md §5 and §7 for the full rationale.

All write-side ATT&CK techniques (persistence, credential modification, lateral movement
via write-scope Graph calls) are excluded per G-1 through G-9 in docs/guardrails.md and
the ADR 0001 Sprint 1 Rules of Engagement. They are not catalogued here individually;
the guardrails document governs the exclusion.

---

## References

- MITRE ATT&CK Enterprise — <https://attack.mitre.org/matrices/enterprise/>
- docs/threat-model.md — adversary model and §5 active technique scope
- docs/guardrails.md — G-1 through G-9 enforcement rules
- docs/techniques/ — per-technique ADR 0003 modules
- ADR 0001: Sprint 1 Rules of Engagement
- ADR 0003: Technique Module Format
- ADR 0005: Token Persistence and Reuse (T1550.001 basis)
- phs-kpi-dashboard-v1.0.xlsx Sprint Checkpoint KPIs tab — authoritative KPI figures

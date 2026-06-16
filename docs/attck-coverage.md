# Rejewski ATT&CK Coverage Map

- Version: v0.1
- Last updated: 2026-06-16
- Status: Living document — updated at each sprint checkpoint
- Authors: Derek Morgan
- Related: docs/threat-model.md, docs/techniques/, docs/guardrails.md

---

## Overview

This document is the single reference for every MITRE ATT&CK technique that Rejewski
maps, catalogues, or explicitly excludes. It is the authoritative source for the
"ATT&CK techniques mapped" KPI tracked in the Sprint Checkpoint KPIs tab of
phs-kpi-dashboard-v1.0.xlsx.

**Current count:** 10 unique techniques (7 implemented, 3 catalogued, 0 excluded-and-counted)

**Sprint 2 checkpoint target (Sat 2026-07-04):** 10 unique techniques

**v1.0 target (Sat 2026-10-24):** 25 unique techniques

---

## Technique table

| Technique | Name | Tactic | Status | Module | Script(s) |
|-----------|------|--------|--------|--------|-----------|
| T1078.004 | Valid Accounts: Cloud Accounts | Initial Access | Implemented — Sprint 1 | docs/techniques/T1078.004.md | scripts/identity.py |
| T1087.004 | Account Discovery: Cloud Account | Discovery | Implemented — Sprint 1 | docs/techniques/T1087.004.md | scripts/tool_list_users.py, scripts/tool_list_applications.py, scripts/tool_list_role_assignments.py, scripts/tool_list_service_principals.py |
| T1069.003 | Permission Groups Discovery: Cloud Groups | Discovery | Implemented — Sprint 1 | docs/techniques/T1069.003.md | scripts/tool_list_groups.py |
| T1550.001 | Use Alternate Authentication Material: Application Access Token | Defense Evasion / Lateral Movement | Implemented — Sprint 1 | docs/techniques/T1550.001.md | scripts/identity.py (ADR 0005) |
| T1526 | Cloud Service Discovery | Discovery | Implemented — Sprint 2 W5 pull-forward | docs/techniques/T1526.md | scripts/tool_list_ca_policies.py |
| T1087.003 | Account Discovery: Email Account | Discovery | Catalogued — Sprint 2 | docs/techniques/T1087.003.md | *Pending Sprint 2* |
| T1518.001 | Software Discovery: Security Software Discovery | Discovery | Implemented — Sprint 2 | docs/techniques/T1518.001.md | scripts/tool_dfi_health.py |
| T1082 | System Information Discovery | Discovery | Implemented — Sprint 2 | docs/techniques/T1082.md | scripts/tool_intune_devices.py |
| T1213.002 | Data from Information Repositories: Sharepoint | Collection | Catalogued — Sprint 2 | docs/techniques/T1213.002.md | *Pending Sprint 2* |
| T1482 | Domain Trust Discovery | Discovery | Catalogued — Sprint 2 | docs/techniques/T1482.md | *Pending Sprint 2* |

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
| Discovery | 7 | T1087.004, T1069.003, T1526, T1087.003, T1518.001, T1082, T1482 |
| Collection | 1 | T1213.002 |
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

Collection
──────────────────────────────
T1213.002
Info Repositories: SharePoint
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
| S1 W4 (today) | T1087.003, T1518.001 | **7** |
| S1 W4b (today) | T1082, T1213.002, T1482 | **10** |
| S2 | Done — Sprint 2 checkpoint target met | 10 |

Sprint 2 checkpoint target of 10 techniques reached. Technique selection for the Sprint 3
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

| Technique | Name | Reason |
|-----------|------|--------|
| T1538 | Cloud Service Dashboard | GUI-based (Azure portal, M365 admin center); Rejewski is a programmatic Graph client and does not drive browser sessions. Detailed in docs/threat-model.md §7. |

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

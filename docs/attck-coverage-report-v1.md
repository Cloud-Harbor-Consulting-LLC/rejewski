# Rejewski ATT&CK Coverage Report v1

- Version: v1
- Date: 2026-07-08
- Repo HEAD: PR #62 (merge f31cf82)
- Techniques mapped: 17 total — 9 implemented, 8 catalogued
- KPI source of truth: [docs/attck-coverage.md](attck-coverage.md) (v0.3, 2026-06-23)

---

## Purpose

This report is a human-readable snapshot of what every Rejewski tool can surface,
mapped to MITRE ATT&CK. It describes the **current** state of the repository at
HEAD (PR #62, merge f31cf82) — Tools 1–10 online, 54 tests green.

It is **not** the living KPI tracker. The authoritative technique count, status
definitions, path-to-target table, and tactic distribution are maintained in
[docs/attck-coverage.md](attck-coverage.md); the technique-surface detail and
adversary model are in [docs/threat-model.md](threat-model.md) §5. Where a number
appears here, it is transcribed from those sources.

**Acceptance:** the report lists every tool with the techniques it can surface.

---

## 1. Tool-to-technique table

One row per implemented surface. Every implemented technique appears at least once.
`scripts/identity.py` is the shared sign-in and token-persistence helper — it is not
a numbered tool but underpins every Graph call.

| Tool | Script | Technique ID(s) | Technique name | Tactic | Graph endpoint | Status |
|------|--------|-----------------|----------------|--------|----------------|--------|
| — | `scripts/identity.py` | T1078.004 | Valid Accounts: Cloud Accounts | Initial Access | Device-code / ROPC sign-in (`login.microsoftonline.com`) | Implemented |
| — | `scripts/identity.py` | T1550.001 | Use Alternate Authentication Material: Application Access Token | Defense Evasion / Lateral Movement | MSAL encrypted token cache (silent reuse) | Implemented |
| 1 | `scripts/tool_list_users.py` | T1087.004 (Surface A) | Account Discovery: Cloud Account | Discovery | `GET /users` | Implemented |
| 2 | `scripts/tool_list_groups.py` | T1069.003 | Permission Groups Discovery: Cloud Groups | Discovery | `GET /me/memberOf` | Implemented |
| 3 | `scripts/tool_list_applications.py` | T1087.004 (Surface B) | Account Discovery: Cloud Account | Discovery | `GET /applications` | Implemented |
| 4 | `scripts/tool_list_ca_policies.py` | T1526 | Cloud Service Discovery | Discovery | `GET /identity/conditionalAccess/policies` | Implemented |
| 5 | `scripts/tool_list_role_assignments.py` | T1087.004 (Surface C) | Account Discovery: Cloud Account | Discovery | `GET /roleManagement/directory/roleAssignments` | Implemented |
| 6 | `scripts/tool_list_service_principals.py` | T1087.004 (Surface D) | Account Discovery: Cloud Account | Discovery | `GET /servicePrincipals` | Implemented |
| 7 | `scripts/tool_dfi_health.py` | T1518.001 | Software Discovery: Security Software Discovery | Discovery | `GET /security/identities/sensors` | Implemented |
| 8 | `scripts/tool_intune_devices.py` | T1082 | System Information Discovery | Discovery | `GET /deviceManagement/managedDevices` | Implemented |
| 9 | `scripts/tool_purview_labels.py` | T1580 | Cloud Infrastructure Discovery | Discovery | `GET /security/dataSecurityAndGovernance/sensitivityLabels` | Implemented |
| 10 | `scripts/tool_signin_logs.py` | T1654 | Log Enumeration | Discovery | `GET /auditLogs/signIns` | Implemented |

All Graph calls are read-only `GET` requests against the lab tenant
tenant (<lab-tenant-id>), run under a borrowed first-party Microsoft Graph Command Line
Tools client (14d82eec) with no tenant-side app registration.

---

## 2. Technique coverage summary

All 17 mapped techniques. Catalogued techniques have modules under
`docs/techniques/` but no scripts yet; their tool column reads **Pending**.

| Technique | Name | Tactic | Status | Tool |
|-----------|------|--------|--------|------|
| T1078.004 | Valid Accounts: Cloud Accounts | Initial Access | Implemented | `identity.py` |
| T1087.004 | Account Discovery: Cloud Account | Discovery | Implemented | Tools 1 / 3 / 5 / 6 |
| T1069.003 | Permission Groups Discovery: Cloud Groups | Discovery | Implemented | Tool 2 |
| T1550.001 | Use Alternate Authentication Material: Application Access Token | Defense Evasion / Lateral Movement | Implemented | `identity.py` |
| T1526 | Cloud Service Discovery | Discovery | Implemented | Tool 4 |
| T1087.003 | Account Discovery: Email Account | Discovery | Catalogued | Pending |
| T1518.001 | Software Discovery: Security Software Discovery | Discovery | Implemented | Tool 7 |
| T1082 | System Information Discovery | Discovery | Implemented | Tool 8 |
| T1213.002 | Data from Information Repositories: Sharepoint | Collection | Catalogued | Pending |
| T1482 | Domain Trust Discovery | Discovery | Catalogued | Pending |
| T1580 | Cloud Infrastructure Discovery | Discovery | Implemented | Tool 9 |
| T1538 | Cloud Service Dashboard | Discovery | Catalogued | Pending |
| T1213.003 | Data from Information Repositories: Code Repositories | Collection | Catalogued | Pending |
| T1530 | Data from Cloud Storage | Collection | Catalogued | Pending |
| T1619 | Cloud Storage Object Discovery | Discovery | Catalogued | Pending |
| T1114.002 | Email Collection: Remote Email Collection | Collection | Catalogued | Pending |
| T1654 | Log Enumeration | Discovery | Implemented | Tool 10 |

**Implemented:** 9 — T1078.004, T1087.004, T1069.003, T1550.001, T1526, T1518.001,
T1082, T1580, T1654.

**Catalogued:** 8 — T1087.003, T1213.002, T1482, T1538, T1213.003, T1530, T1619,
T1114.002.

Status definitions (per [docs/attck-coverage.md](attck-coverage.md)): **Implemented**
means a working script exists and at least one consented sandbox run has produced
replay-log evidence; **Catalogued** means an ADR 0003 technique module exists but no
script has been written and no sandbox run executed.

---

## 3. Tactic distribution

Transcribed from the tactic distribution table in
[docs/attck-coverage.md](attck-coverage.md). No invented numbers.

| Tactic | Techniques | IDs |
|--------|-----------|-----|
| Initial Access | 1 | T1078.004 |
| Discovery | 11 | T1087.004, T1069.003, T1526, T1087.003, T1518.001, T1082, T1482, T1580, T1538, T1619, T1654 |
| Collection | 4 | T1213.002, T1213.003, T1530, T1114.002 |
| Defense Evasion / Lateral Movement | 1 | T1550.001 |

Discovery dominates current coverage, consistent with Rejewski's Sprint 1–2
recon-and-enumeration focus.

---

## 4. Notes

- **T1087.004 has four surfaces.** Account Discovery: Cloud Account is exercised
  across four tools, each hitting a different Graph object layer: Tool 1 (`/users`,
  Surface A), Tool 3 (`/applications`, Surface B), Tool 5
  (`/roleManagement/directory/roleAssignments`, Surface C), and Tool 6
  (`/servicePrincipals`, Surface D).
- **T1550.001 lives in `identity.py`, not a numbered tool.** The
  application-access-token reuse technique is the borrowed-token persistence helper
  (MSAL encrypted cache + silent reuse per ADR 0005), shared by every tool rather
  than being a standalone enumeration primitive.
- **T1078.004 also lives in `identity.py`.** The device-code / ROPC sign-in is the
  prerequisite for every downstream Graph call — no tool runs without it.
- **Catalogued techniques have modules but no scripts.** All eight catalogued
  techniques (T1087.003, T1213.002, T1482, T1538, T1213.003, T1530, T1619,
  T1114.002) have ADR 0003 technique modules under `docs/techniques/`, but no script
  and no sandbox run yet — hence **Pending** in the tool column.

---

## References

- [docs/attck-coverage.md](attck-coverage.md) — authoritative technique count, status
  definitions, tactic distribution, path-to-target (KPI source of truth).
- [docs/threat-model.md](threat-model.md) — §5 active technique scope, per-technique
  Graph surfaces, adversary model.
- `docs/techniques/` — per-technique ADR 0003 modules.
- MITRE ATT&CK Enterprise — <https://attack.mitre.org/matrices/enterprise/>

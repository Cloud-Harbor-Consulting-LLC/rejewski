# Rejewski Finding-to-Control Coverage Report

- Generated: 2026-10-20T14:36:04Z
- ATT&CK coverage source: docs/attck-coverage.md (v0.10)
- Implemented techniques: 13
- Covered: 13 (100.0%)
- Gap: 0 (0.0%)

## Covered techniques

| Technique | Name | Mapping record |
|---|---|---|
| T1078.004 | Valid Accounts: Cloud Accounts | t1078.004-conditional_access-ca-require-mfa-all-users.json |
| T1087.004 | Account Discovery: Cloud Account | t1087.004-conditional_access-ca-cov008-blockbylocation.json |
| T1069.003 | Permission Groups Discovery: Cloud Groups | t1069.003-conditional_access-ca-sif001-signinfrequency-8h.json |
| T1550.001 | Use Alternate Authentication Material: Application Access Token | t1550.001-rbac-directory-readers.json |
| T1526 | Cloud Service Discovery | t1526-rbac-reports-reader.json |
| T1518.001 | Software Discovery: Security Software Discovery | t1518.001-rbac-security-reader.json |
| T1082 | System Information Discovery | t1082-rbac-intune-service-admin.json |
| T1213.002 | Data from Information Repositories: Sharepoint | t1213.002-conditional_access-ca-spo-requirecompliantapp.json |
| T1580 | Cloud Infrastructure Discovery | t1580-conditional-access-purview-require-compliant-app.json |
| T1114.002 | Email Collection: Remote Email Collection | t1114.002-rbac-exchange-administrator.json |
| T1654 | Log Enumeration | t1654-rbac-reports-reader.json |
| T1114.003 | Email Collection: Email Forwarding Rule | t1114.003-conditional_access-ca-exo-requirecompliantapp.json |
| T1033 | System Owner/User Discovery | t1033-rbac-pim-eligible-roles.json |

## Gap techniques (no control mapping)

| Technique | Name | Status | Notes |
|---|---|---|---|

## Coverage history

| Report date | Implemented | Covered | Coverage % |
|---|---|---|---|
| 2026-08-14 | 13 | 9 | 69.2% |
| 2026-08-29 | 13 | 13 | 100.0% |
| 2026-10-20 | 13 | 13 | 100.0% |

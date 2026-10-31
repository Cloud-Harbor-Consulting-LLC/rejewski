# B007 — Pillar 1 Zero Trust Device Compliance Demo

**Backlog ID:** B007
**Sprint:** 1, Week 2
**Pillar:** 1 — Endpoints (Zero Trust)
**Scenario:** ZT-S01 Device Compliance (per docs/phs-zt-scenarios-v0.1.md)
**ATT&CK technique:** T1078.004 — Valid Accounts: Cloud Accounts
**Defensive control under test:** Conditional Access "Require device to be marked as compliant" (MITRE mitigation M1036)

## Summary

Rejewski emulates a threat actor that has stolen valid cloud credentials and attempts to acquire a Microsoft Graph delegated token from an unmanaged endpoint. The target tenant has a Conditional Access policy requiring a compliant device. Under test, the v2.0 token endpoint returns AADSTS53000 and no Graph call is reached.

This validates ZT-S01 end-to-end: the borrowed first-party client cannot proxy access from a non-compliant device.

## Prerequisites

1. Sandbox tenant the lab tenant (tenant id <lab-tenant-id>).
2. Seed user meganb@<lab-domain> with a known password.
3. Conditional Access policy in the target tenant, scoped to the seed user (or a group containing them):
   - Users: include the seed user.
   - Cloud apps: include Microsoft Graph (or All cloud apps).
   - Conditions: any platform.
   - Grant: "Require device to be marked as compliant" (single control).
   - State: On.
4. The host running the demo is not Intune-enrolled and not Hybrid Entra-joined. (MSAL ROPC from a plain Python process emits no Primary Refresh Token and no device claim.)
5. Python 3.10+ with msal installed (already pinned in the Rejewski runtime requirements).
6. Environment variables on the runner host:
   - REJEWSKI_ACTOR_PASSWORD — seed-user password (never committed).
   - Optional: AZURE_TENANT_ID, REJEWSKI_ACTOR_UPN to override defaults.

## Run

From the repo root:

```bash
export REJEWSKI_ACTOR_PASSWORD='<seed-user-password>'
python scripts/demo_b007_device_compliance.py --evidence-out evidence/b007-run-$(date -u +%Y%m%dT%H%M%SZ).json
```

Exit code 0 = AADSTS53000 observed (demo passed). Exit code 1 = any other outcome (inspect evidence JSON).

## Expected outcome

### Client side (this script)

MSAL acquire_token_by_username_password returns a dict (it does not raise on AADSTS errors). The dict contains:

- error = invalid_grant
- error_codes = list of ints including 53000
- error_description begins with `AADSTS53000: Device is not in required device state: compliant.`
- correlation_id = GUID — record this; it links the failure to the SigninLogs row.

No access_token key is present. No Graph call is attempted.

### Tenant side (SigninLogs)

A row appears in Entra "Sign-in logs" within ~2 to 5 minutes (portal/Graph) and in Log Analytics SigninLogs within ~5 minutes typical (worst case up to 3 days per Microsoft documentation). Demo assertions against SigninLogs should allow at least 15 minutes.

Row fields:

- ResultType = 53000
- AppId = 14d82eec-204b-4c2f-b7e8-296a70dab67e (Microsoft Graph Command Line Tools)
- UserPrincipalName = meganb@<lab-domain>
- ConditionalAccessStatus = failure
- DeviceDetail.isCompliant = false
- DeviceDetail.isManaged = false
- DeviceDetail.trustType = empty / null
- AppliedConditionalAccessPolicies array contains an entry with:
  - result = failure
  - enforcedGrantControls includes the compliant-device control (rendered as CompliantDevice or "Require device to be marked as compliant")

### Hunt query

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == 53000
| where AppId == "14d82eec-204b-4c2f-b7e8-296a70dab67e"
| where UserPrincipalName == "meganb@<lab-domain>"
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress,
          ResultType, ResultDescription,
          DeviceDetail, ConditionalAccessStatus, AppliedConditionalAccessPolicies,
          CorrelationId
```

## Pass / fail criteria

- **Pass.** Script exits 0, evidence JSON matched_expected_53000 = true, SigninLogs row found within 15 minutes carrying ResultType == 53000 and a failing appliedConditionalAccessPolicies entry whose enforcedGrantControls includes the compliant-device control.
- **Fail (regression).** Token returned (outcome = unexpected_success). The CA policy is misscoped or the test host is registered as compliant. Re-verify policy targeting and device posture; do not declare the demo passing until 53000 is observed.
- **Inconclusive — ROPC blocked.** outcome = ropc_disabled_or_user_invalid (AADSTS 7000218 / 50126 / 50053 / etc.). ROPC is blocked at the tenant or the seed user is invalid; CA never evaluated. Resolve at the tenant policy / user state level and re-run.
- **Inconclusive — other CA control fired first.** outcome = blocked_by_ca_other_mfa (50076 / 50158 / 50079) or blocked_by_ca_other_generic (53003 / 53001). A different CA policy fired before the device-compliance control. Reduce CA scope to isolate the device-compliance grant.

## Why this matters

ROPC against a borrowed first-party client (Graph Command Line Tools) is a low-friction path an adversary would use after credential theft. The compliant-device grant control (MITRE M1036 — Account Use Policies, "Use conditional access policies to block logins from non-compliant devices") is the direct mitigation. ZT-S01 exists to prove this control fires deterministically against an unmanaged endpoint.

The demo also produces the SigninLogs signal that downstream detection content (Microsoft Sentinel analytic rules, hunting queries) keys on. There is no Microsoft-shipped Sentinel template that filters exclusively on ResultType == 53000; the Rejewski detection rule for this scenario is custom.

## Cross-references

- docs/phs-zt-scenarios-v0.1.md — ZT-S01 baseline scenario (Pillar 1 anchor).
- docs/adr/0001-rules-of-engagement.md — tenant scope (the lab tenant only), consent floor, technique allowlist.
- docs/adr/0004-identity-token-acquisition-model.md — borrowed-client policy and identifier registry.
- docs/threat-model.md — Sprint 1 finding on Graph CLI ROPC delegated-token path.
- docs/guardrails.md — G-1 (tenant lock), G-3 (read-default posture), G-2 (no tenant app registration).

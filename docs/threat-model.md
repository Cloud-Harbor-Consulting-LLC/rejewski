# Threat Model — Project Harbor Sonar / Rejewski

**Version:** v0.1 (outline)
**Last updated:** 2026-05-14
**Status:** Draft outline. Sections populated incrementally; full technique stubs and guardrail binding committed Sat May 16, 2026 alongside guardrails.md (G1-G8) and ADRs 0001-0002.

---

## 1. Purpose

This document maps the adversary tradecraft that the Rejewski agent simulates to the MITRE ATT&CK framework. It is the bridge between (a) the Rules of Engagement that bound what the agent may attempt and (b) the guardrails that constrain how the agent attempts it.

The threat model is consumed by:

- ADR 0001 Rules of Engagement (committed Sat May 16, 2026)
- guardrails.md G1 through G8 (committed Sat May 16, 2026)
- KPI Dashboard (Master Plan v1.5 Section 3.1 — ATT&CK techniques covered)

---

## 2. System Under Test

The agent operates against a Microsoft 365 / Entra ID tenant configured as the test target. Sprint 1 uses the MCS-MOS3 Azure sandbox tenant (standup in flight, due Sat May 16, 2026).

In-scope surfaces for Sprint 1:

- Microsoft Graph (v1.0 and beta)
- Entra ID identity surface — users, groups, directory roles
- Token issuance and refresh flows

Out-of-scope surfaces for Sprint 1 (revisit Sprint 2+):

- Exchange Online mailbox content
- SharePoint Online sites and document libraries
- Teams chat and channel messages
- Defender XDR signal surfaces

---

## 3. Adversary Model

The agent simulates a post-compromise adversary with:

- Valid credentials for a tenant user account (seed user, MFA-default state per B001 Step 2)
- No standing privileged role at t=0
- No prior tenant intelligence

The agent does NOT simulate:

- Initial-access tradecraft — phishing, password spray, AiTM proxies. Out of scope for v1.0; the Sprint 2+ MFA-bypass technique catalog will revisit.
- Endpoint compromise or lateral movement off the identity plane.
- Insider threat with standing elevated permissions at t=0.

---

## 4. Assumptions and Constraints

- Test tenant has zero production data and zero PII.
- Seed users are scoped to ROE-defined accounts only.
- Every agent action emits a replay-log entry (replay-log.md spec lands Sprint 1 Week 2, Tool 1 card).
- All API calls are read-only in Sprint 1; write operations gate behind the explicit ROE consent flow (Sprint 1 exit floor: 5 consent-flow runs).

---

## 5. ATT&CK Technique Coverage — v0.1

Three techniques committed for Sprint 1 outline coverage. Full stubs (sub-technique selection, detection notes, guardrail binding, replay-log shape) land Sat May 16, 2026.

### 5.1 T1078 Valid Accounts

- **Sub-technique:** T1078.004 Cloud Accounts
- **Agent behavior:** Authenticates as a seed user via standard OAuth 2.0 / OpenID Connect flows.
- **B001 mapping:** Step 4 token smoke test (Wed May 13, 2026) confirmed the valid-credentials auth path; refresh-token round-trip verified.
- **Guardrail binding:** TBD Sat May 16.

### 5.2 T1087 Account Discovery

- **Sub-technique:** T1087.004 Cloud Account
- **Agent behavior:** Post-auth enumeration of tenant users via Microsoft Graph (/users, /me, /me/people).
- **B001 mapping:** MFA-default handling step exercised account-property reads on seed users; established that the agent can read userPrincipalName, displayName, accountEnabled, and assignedLicenses without elevated scopes.
- **Guardrail binding:** TBD Sat May 16.

### 5.3 T1069 Permission Groups Discovery

- **Sub-technique:** T1069.003 Cloud Groups
- **Agent behavior:** Post-auth enumeration of tenant groups and directory roles via Microsoft Graph (/groups, /directoryRoles, /me/memberOf, /me/transitiveMemberOf).
- **B001 mapping:** Seed-user setup required reading group memberships to confirm seed users were scoped to the correct test groups and not production-aligned.
- **Guardrail binding:** TBD Sat May 16.

---

## 6. B001 Findings → Technique Mapping

| B001 Step | Activity | ATT&CK Technique | Notes |
|---|---|---|---|
| Step 1 | Seed user creation | — | Configuration, not simulated tradecraft |
| Step 2 | MFA-default handling design | — | Configuration |
| Step 3 | Token issuance scaffold | T1078.004 | Valid-credentials cloud authentication path |
| Step 4 | Token smoke test executed (Wed May 13, 2026) | T1078.004 | Confirmed; refresh-token round-trip verified |
| Step 5 (in flight) | Account-property reads | T1087.004 | Outline depth; full coverage Sat |
| Step 6 (in flight) | Group / role-membership reads | T1069.003 | Outline depth; full coverage Sat |

---

## 7. Out-of-Scope Techniques — Parked for Sprint 2+

The following adversary tradecraft is explicitly deferred and tracked separately so it does not creep into Sprint 1 scope:

- **MFA-bypass technique catalog** — AiTM proxies, push-bombing, SIM-swap, OAuth illicit consent, token theft. Parked per the May 13, 2026 deferred-prep decision. Reactivate at Sprint 2 planning.
- T1606 Forge Web Credentials (cloud token forgery sub-techniques)
- T1550.001 Application Access Token
- T1098.005 Device Registration

---

## 8. Trust Boundaries

Stub. Populated Sat May 16, 2026.

Three boundaries to enumerate:

- Agent runtime ↔ test tenant: bounded by ROE (ADR 0001) and tenant configuration.
- Operator ↔ agent runtime: bounded by guardrails G1-G8.
- Operator ↔ test tenant: bounded by Microsoft's tenant admin model and the consent flow.

---

## 9. Open Questions

- Should T1078 sub-technique coverage extend to T1078.001 (Default Accounts) in Sprint 1, or hold for Sprint 2?
- Detection-mapping integration with Microsoft Sentinel: scope for Sprint 5+ External Auth Flow doc.
- Does the replay-log spec (Sprint 1 Week 2) need a technique-tag field, or is the mapping deferred to a separate index?

---

## 10. Change Log

| Version | Date | Author | Notes |
|---|---|---|---|
| v0.1 | 2026-05-14 | Derek Morgan | Outline. Three Sprint 1 techniques mapped at outline depth. MFA-bypass parked for Sprint 2+. |

# ADR-0009: Stage 2 Rules of Engagement: Persistence by a Standard Account

- **Status:** Proposed
- **Date:** 2026-10-31
- **Deciders:** Derek Morgan (Principal Architect)
- **Supersedes (on acceptance):** ADR-0001 read-only floor, for consented Stage 2 techniques only; guardrails G-2 and G-3 as written today
- **Related:** ADR-0001 (Rules of Engagement), ADR-0004 (token acquisition), ADR-0005 (token persistence), ADR-0006 (FOCI allowlist), ADR-0008 (consent-bound tenant lock), docs/guardrails.md G-1 to G-9, docs/attck-coverage.md, docs/external-auth.md

---

## 1. Context

Rejewski's objective is to emulate a threat actor attacking a Microsoft 365 tenant, end to end. v1.0 (2026-10-26) ships Stage 1: a valid sign-in, silent token reuse, and read-only Discovery and Collection across 15 tool surfaces (20 ATT&CK techniques). The v1.0 launch committed publicly that each release adds the next stage of the attack, retiring guardrails stage by stage, each through its own ADR (Derek, 2026-10-26).

The guardrails that keep v1.0 read-only already name the next step. G-2 defers gaining a tenant app registration to a later stage, G-3 defers write-side techniques to a superseding ADR, and G-8 treats long-lived access as a later-stage technique. The first community answer to the launch post's "which stage next?" question asked how an attacker stays in after a stolen login.

Two v1.1 backlog items bear directly on a write-capable stage. C015: the G-1 gate checks a run's tenant, status, and window, but not its techniques (ADR-0008 §5.2). C014: the first sign-in uses ROPC, which cannot satisfy MFA and is deprecated in MSAL Python.

## 2. Decision

**Stage 2 is Persistence, emulated with the same stolen standard (non-administrator) account Stage 1 uses.** Admin-level persistence needs a role first, so it belongs to Stage 3 (Privilege Escalation) and its own ADR.

1. **Stage model.** Each release adds one stage. Each stage has its own Rules-of-Engagement ADR that names the guardrails it retires, rewrites, or adds. G-1 (consent) and G-5 (evidence) never retire.
2. **Candidate techniques.** The Stage 2 set is drawn from the ATT&CK Persistence tactic and limited to actions a delegated, non-privileged identity can take under common tenant defaults. The candidates are listed below. The final set is fixed at v1.1 scoping, after each endpoint and permission is checked against current Microsoft Graph documentation.

   | Technique | Action by the stolen account | Default setting it depends on | Rollback |
   |---|---|---|---|
   | T1098.001 Account Manipulation: Additional Cloud Credentials | Add a client secret to an app registration the account owns | Users can register applications | Remove the secret |
   | T1671 Cloud Application Integration | Grant user consent to a multi-tenant application | User consent to applications allowed | Revoke the grant |
   | T1136.003 Create Account: Cloud Account | Invite a guest user | Guest invitations allowed for members | Delete the guest |
   | T1098.005 Account Manipulation: Device Registration | Register a device to the account | Users may register devices | Delete the device |

3. **Writes are scoped by consent.** A Stage 2 tool may issue a non-GET request only when its technique is listed in the run's consent record and the record carries an explicit write acknowledgment. C015 (technique-scope enforcement in `scripts/roe_gate.py`) and a consent-record schema version carrying the write acknowledgment are prerequisites; no Stage 2 tool merges before both.
4. **Every write is rolled back and the rollback is verified (new guardrail G-10).** Each write has a recorded inverse that runs in the same run. The run confirms each rollback with a read and fails loudly, naming the artifact, if anything it created remains.
5. **Feasibility mode by default.** Each Stage 2 tool can report whether a technique would succeed (the relevant tenant setting and the account's ownership or permission) using reads only. That is the default unless the consent record acknowledges writes.
6. **Sandbox first.** Stage 2 writes run only against the lab tenant until three consecutive sandbox runs show every write rolled back and verified. After that, writes are allowed on any tenant whose consent record meets ADR-0008 and item 3.
7. **Sign-in.** C014 (replace ROPC) is a prerequisite for writes on any tenant other than the sandbox, because a tenant that requires MFA refuses ROPC.

### Guardrail changes on acceptance

| Guardrail | Change |
|---|---|
| G-1 Consent-bound tenant lock | Kept. Extended to technique scope (C015) and the write acknowledgment |
| G-2 No tenant app registration | Rewritten: creating or credentialing an application is allowed only as a consented Stage 2 technique, rolled back in the same run |
| G-3 Read-only floor | Rewritten: non-GET requests allowed only for consented Stage 2 techniques; every other request stays GET |
| G-4 FOCI client allowlist | Kept. Amended only if scoping shows the delegated write permissions need a different first-party client |
| G-5 Evidence | Kept. Extended: each write and its rollback are replay-log entries linked by an ID |
| G-6 Redaction | Kept. Extended: created secret values, secret IDs, and created object IDs are never written to the replay log |
| G-7 No real user data | Kept |
| G-8 Time-boxed sessions | Kept. Extended: teardown includes the G-10 rollback check |
| G-9 Row cap | Kept |
| G-10 Verified rollback | New (item 4) |

The Master Plan's program principles G1 (read-only) and G4 (no persistence), quoted in the README, are amended in the same change that accepts this ADR.

## 3. Rationale

- **Kill-chain order.** Stage 1 ends with a valid session and a map of the tenant. The next thing an attacker does is make access survive a password reset (ATT&CK TA0003).
- **One stage per release.** Holding Stage 2 to what a standard account can do keeps privilege escalation out of it, so each release maps to one tactic and one ADR.
- **The prior reads already exist.** Stage 1 reads applications, service principals, OAuth grants, users, and devices (T1087.004, T1082), so each Stage 2 write follows a read the replay log already holds.
- **Fail-closed safety.** Consent scope, write acknowledgment, feasibility default, sandbox-first, and verified rollback each deny by default. No single missing control lets a write through unscoped.
- **Defender value.** Each candidate technique produces Entra ID audit events (application credential changes, consent grants, guest invitations, device registrations). A run lets a defender check that detections fire, then confirm the artifact is gone.

## 4. Identity-Decision Factors

- **Token type:** delegated, the same stolen standard account as Stage 1.
- **Client ID source:** borrowed first-party FOCI client (ADR-0006). Open question for scoping: whether Microsoft Graph Command Line Tools (14d82eec) holds the delegated write permissions each technique needs in a default tenant, without an admin consent that would itself change the tenant.
- **Grant flow:** ROPC on the sandbox until C014 lands; the C014 replacement for any other tenant. Refresh-token reuse per ADR-0005.
- **Scope shape:** `.default`, as today. The request side, not the scope, limits writes (G-3 rewrite).
- **Consent path:** the tenant's existing consent for the borrowed client. No new consent is requested by the tool except where a technique is itself a consent grant (T1671).
- **MFA posture:** unchanged on the sandbox (ROPC). On other tenants, governed by C014.
- **Dwell-signal expectations:** Entra ID audit log events for each write and each rollback (Update application: certificates and secrets management; Consent to application; Invite external user; Register device), plus MicrosoftGraphActivityLogs entries for the non-GET calls. Cross-link the zt-scenarios doc when the technique modules are drafted.

## 5. Consequences

### 5.1 Positive

- Rejewski moves from "what a stolen account can see" to "what a stolen account can plant," which is the commitment made at launch.
- Each run leaves the tenant as it found it, and the replay log proves it.
- Defenders get paired evidence: the write, the audit event it should raise, and the rollback.

### 5.2 Negative

- **Writes change a real tenant.** A failed rollback leaves a persistence artifact. G-10 makes the failure loud, but cleanup may then need an administrator.
- **Misuse risk rises** (risk register RK020). An any-tenant release that can plant persistence is more dangerous in the wrong hands. Mitigations: consent scope (C015), write acknowledgment, feasibility default, and sandbox-first.
- **More enforcement code.** The GET-only guard in `write_entry()` and tests/test_autonomy_boundary.py become a scoped allowlist, which is harder to reason about than a blanket rule.
- **Tenant-default dependence.** Hardened tenants (user app registration off, user consent off, guest invites restricted) block some techniques. That is a finding, not a failure, and the feasibility mode reports it.

### 5.3 Neutral

- Stage 1 tools and committed evidence are unaffected; they stay GET only.
- The consent-record schema gains a version.

## 6. Alternatives Considered

- **Privilege Escalation as Stage 2.** Rejected because it needs a role the stolen account does not hold, which skips a stage. Revisit window: Stage 3 (v1.2).
- **Report persistence opportunities without planting anything.** Kept as the default feasibility mode (item 5) but rejected as the whole stage, because it emulates no attacker action.
- **More Stage 1 breadth (Power Platform recon, Purview DLP, Intune posture) as v1.1.** Rejected as the v1.1 headline because it adds no stage. These remain Stage 1 breadth candidates for a later release.
- **Allow writes on any tenant from the first Stage 2 release.** Rejected; sandbox-first (item 6) proves rollback before writes touch a real tenant.

## 7. Compliance and Verification

- **Consent scope:** a Stage 2 tool refuses a non-GET request when its technique is not in the run's consent record or the record lacks the write acknowledgment (tests per tool, C015).
- **Request guard:** `write_entry()` refuses a non-GET graph_call unless the tool is a registered Stage 2 tool and the technique is consented; tests/test_autonomy_boundary.py asserts that every Stage 1 tool stays GET only.
- **Rollback:** every write entry has a linked rollback entry and a verification read; a run whose verification finds a remaining artifact ends with outcome error and names it.
- **Redaction:** tests assert that no created secret value or object ID reaches the replay log.
- **Sandbox-first:** three consecutive sandbox runs with verified rollback are committed as evidence before writes are enabled for any other tenant.

## 8. Change Log

| Date | Version | Change | Author |
|------|---------|--------|--------|
| 2026-10-31 | v0.1 | Proposed. Stage 2 approved as Persistence by Derek 2026-10-31; technique set fixed at v1.1 scoping. | Derek Morgan |

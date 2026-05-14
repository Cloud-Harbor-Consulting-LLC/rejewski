# Rejewski Guardrails

Operational rules that bound every Sprint 1 technique. Each guardrail has an ID, statement, rationale, enforcement, scope, and exceptions. Technique modules in docs/techniques/ cite these IDs by number. ADR 0001 (Sprint 1 Rules of Engagement) authorizes the set.

---

## G-1 — Sandbox Tenant Lock

**Statement.** All technique runs target the cloudharbordemo Azure sandbox tenant (tenant ID 76b87c33-6178-4ff9-94a7-164792c8e4c6) exclusively. No technique module, smoke test, or replay session may issue a Graph call against any other tenant.

**Rationale.** Rejewski is a defensive-research agent. Operating outside the sandbox tenant carries blast-radius risk against real users, real data, and real tenant configuration. The sandbox tenant is purpose-built with synthetic users and isolated data; the Planner host tenant (where Project Harbor Sonar tracking lives) is a program-management surface and is not a valid target. Conflation between the two tenants is a documented historical hazard (ADR 0001 v0.1 carried the Planner host tenant ID in error; corrected to cloudharbordemo in v0.2).

**Enforcement.** The runtime loader in scripts/rejewski_runtime.py reads the tenant ID from rejewski.config.json and compares against the constant 76b87c33-6178-4ff9-94a7-164792c8e4c6 before any technique module fires. A mismatch raises a TenantScopeViolation exception and aborts the run before any Graph call is issued. The loader smoke test (Wed May 13 evening) confirms the pre-flight comparison fires correctly.

**Scope.** Binds every technique module under docs/techniques/, every smoke-test script under scripts/, and every replay scenario under tests/replay/ (when that directory lands in Sprint 2). Binds the Claude Agent SDK runtime when invoked by an operator and the headless runtime when invoked by CI.

**Exceptions.** None at Sprint 1. Future cross-tenant techniques (e.g., guest-account enumeration patterns) will require their own guardrail and an ADR amendment before any cross-tenant target ID is added to the allowlist.

---

## G-2 — No tenant app registration

**Statement.** Rejewski never creates, modifies, or deletes an application registration in the target tenant. Only Microsoft-owned first-party OAuth clients may be used.

**Rationale.** A custom app registration is itself an adversary technique (T1136.003 Create Account: Cloud Account variants, T1098.001 Account Manipulation: Additional Cloud Credentials). Gaining one is what later sprints emulate. Starting from a position of "already has a tenant app reg" would short-circuit the kill chain Rejewski is trying to model and would also leave a permanent artifact in the sandbox tenant.

**Enforcement.** ADR 0001 §3 lists the allowed FOCI clients. The SDK refuses any client ID not in that list. Code review for every technique module checks that the front-matter first_party_client_id is on the allowlist.

**Scope.** Initial-access techniques, persistence techniques, and any module that touches OAuth client identity. Reaffirmed in every technique module's Borrowed Client section.

**Exceptions.** None in Sprint 1. Gaining a tenant app registration is a Sprint 2+ technique and must be authorized by a future ADR.

---

## G-3 — Consent floor (read-only Sprint 1)

**Statement.** Sprint 1 token requests carry only read-only Microsoft Graph delegated scopes. Specifically: User.Read, User.ReadBasic.All, Group.Read.All. Write scopes (Mail.Send, Directory.ReadWrite.All, Group.ReadWrite.All) and admin-consent scopes are not requested.

**Rationale.** Consent floors bound the worst-case impact of an emulation gone wrong. A read-only token cannot send mail as the user, cannot modify directory objects, and cannot create persistence artifacts. Sprint 1 deliberately stays on the discovery side of the kill chain so the safety envelope is shallow.

**Enforcement.** Scope list is pinned in rejewski.config.json under SDK_FIELDS. The SDK refuses to request a scope outside the allowlist. Evidence capture records the granted scopes from each token response; PR review flags any scope drift.

**Scope.** All Sprint 1 technique modules. ADR 0002 (consent floor evidence) defines the recording format.

**Exceptions.** None in Sprint 1. Write-side techniques are deferred to Sprint 2+ with a superseding ADR that uplifts the floor explicitly.

---

## G-4 — FOCI client allowlist

**Statement.** Sprint 1 uses Microsoft Graph PowerShell (14d82eec-204b-4c2f-b7e8-296a70dab67e) as the sole borrowed first-party FOCI client.

**Rationale.** Constraining the borrowed-client surface to one well-understood, broadly-trusted Microsoft client keeps the sign-in fingerprint stable and predictable. It also gives blue-team detection a single app ID to baseline against during Sprint 1 evidence capture.

**Enforcement.** rejewski.config.json pins the client ID. SDK refuses any other client. Each technique module's front matter restates the client ID and is checked in PR review.

**Scope.** All token acquisition flows — device-code, refresh, on-behalf-of. Applies to operator-driven runs and SDK-driven smoke tests alike.

**Exceptions.** None in Sprint 1. Sprint 2+ may introduce additional FOCI clients (Azure CLI, Visual Studio) via superseding ADR. Each addition requires its own G-4 amendment naming the client.

---

## G-5 — Evidence capture mandatory

**Statement.** Every technique invocation records: technique ID, run number, run date, operator identity, tenant ID, FOCI client ID, sign-in correlation ID, scopes granted, Graph endpoints called, response correlation IDs per call, aggregate row counts, and outcome (success / partial / failed). Evidence is stored in the SharePoint Project Harbor Sonar / Evidence folder under the B-task ID that authorized the run.

**Rationale.** The point of Rejewski is repeatable, auditable adversary emulation. A run without evidence is not a run — it cannot be replayed, cannot be reviewed, and cannot ground KPI claims. Mandatory capture also creates the dataset Sprint 2+ detection coverage will be validated against.

**Enforcement.** SDK writes a structured ledger entry per run to logs/rejewski-audit.jsonl (path pinned in rejewski.config.json). Operators copy the ledger entry into the SharePoint Evidence file before closing the run. PR review for technique modules checks that the Evidence section cites at least one B-task evidence file.

**Scope.** All technique invocations including smoke tests and replay reruns. Failed runs are captured with the failure mode noted.

**Exceptions.** None.

---

## G-6 — Audit log redaction

**Statement.** Evidence files published to the Rejewski repo (public on GitHub) redact tenant-identifying content beyond the cloudharbordemo tenant ID itself: account UPNs, account display names, group display names, group object IDs, and any other directory object name are hashed in published evidence. The unredacted index lives in the SharePoint Evidence folder with restricted access.

**Rationale.** The Rejewski repo is intended to be public so the techniques and guardrails can be cited externally. Publishing the seeded sandbox directory structure verbatim would leak the test fixture, which weakens its value as a fixture if it ever becomes a moving target. Redaction lets the public-repo evidence remain useful for replay while keeping the directory fixture stable.

**Enforcement.** The audit-log redact_secrets flag in rejewski.config.json is true; the SDK hashes named fields before writing logs/rejewski-audit.jsonl. Operators check the hash output before committing to the repo. PR review flags any unredacted UPN, display name, or object ID outside the sandbox tenant ID itself.

**Scope.** All evidence content destined for the public Rejewski repo. SharePoint-side evidence is unredacted for operator use.

**Exceptions.** The cloudharbordemo tenant ID (76b87c33-6178-4ff9-94a7-164792c8e4c6) and the Graph PowerShell client ID (14d82eec) are not redacted — both are public Microsoft-published values.

---

## G-7 — No real user data

**Statement.** The sandbox tenant is populated only with seeded test accounts. No real CHC employee account, real customer account, or real production data is staged into the sandbox at any phase.

**Rationale.** Real data in a sandbox is a leak waiting to happen. Even with G-6 redaction, real UPNs in evidence files would be one config error away from public exposure. The cost of seeding fake test users is trivial relative to the downside of leaking a real one.

**Enforcement.** B001 step 4 documents the seeded-user roster. Quarterly audit confirms the roster matches the live sandbox. New users added to the sandbox follow the seeded-user naming pattern (<rejewski-test-NN@cloudharbordemo.onmicrosoft.com>).

**Scope.** All users, all groups, all calendar events, all SharePoint content, all Teams chats inside the sandbox tenant.

**Exceptions.** None.

---

## G-8 — Time-boxed sessions

**Statement.** Refresh tokens issued in Sprint 1 are not held beyond the session-keep-warm window declared in rejewski.config.json. Sessions are explicitly torn down at the end of each operator run.

**Rationale.** Long-lived token persistence is itself a Sprint 2+ technique (T1078.004 sub-scenarios, T1098.001). Holding tokens across runs would conflate the discovery emulations being shipped in Sprint 1 with persistence behaviors that have not been authorized yet. Time-boxing also bounds the blast radius if a refresh token cache ever leaks from the operator workstation.

**Enforcement.** rejewski.config.json sets session_keep_warm and the SDK enforces the expiry. Operators run an explicit sign-out at run end; failure to sign out is flagged in the audit ledger.

**Scope.** All operator runs and all SDK smoke tests in Sprint 1.

**Exceptions.** None in Sprint 1. Persistence-emulation techniques in Sprint 2+ will introduce token-survival scenarios via superseding ADR.

---

## G-9 — Enumeration row cap

**Statement.** Sprint 1 discovery techniques cap returned rows at the configured limit per call (default 50 for /users, default 50 for /groups, default 25 for /me/memberOf). Operators may raise the cap per run with explicit justification recorded in the evidence ledger; the SDK refuses uncapped enumeration.

**Rationale.** Bounding enumeration volume keeps evidence files manageable, keeps the sign-in trace visible without paginating across hundreds of audit entries, and bounds the noise floor that downstream detection work has to baseline against in Sprint 2. Uncapped enumeration is itself a louder adversary behavior (anomalous-volume signal); Sprint 1 prefers the quieter end of the spectrum.

**Enforcement.** Row caps live in rejewski.config.json. The SDK applies the cap as the $top parameter on Graph requests and stops paging when the cap is hit. The evidence ledger records cap, rows returned, and whether the cap was hit.

**Scope.** All discovery techniques in Sprint 1 — T1087.004 and T1069.003 today. Initial-access (T1078.004) is unaffected because it does not enumerate.

**Exceptions.** Per-run cap raises must be recorded in the evidence ledger with operator initials and rationale. No exceptions to the SDK refusing uncapped enumeration.

**Decision.** G-9 entered as a candidate during the Sprint 1 technique-module drafting; promoted to accepted in this PR on the basis that T1087.004 and T1069.003 already cite a row cap in their Procedure sections without a governing guardrail. Promoting G-9 closes that governance gap before PR 4 (threat-model.md v0.2) ships.

---

## Appendix — Guardrail-to-technique map

| Guardrail | T1078.004 | T1087.004 | T1069.003 |
|-----------|-----------|-----------|-----------|
| G-1 sandbox tenant | yes | yes | yes |
| G-2 no app reg | yes | inherited | inherited |
| G-3 consent floor | yes | yes | yes |
| G-4 FOCI allowlist | yes | inherited | inherited |
| G-5 evidence | yes | yes | yes |
| G-6 redaction | — | yes | yes |
| G-7 no real users | yes | yes | yes |
| G-8 time-boxed | yes | inherited | inherited |
| G-9 row cap | — | yes | yes |

"Inherited" means the guardrail applies because the technique runs inside a session governed by T1078.004; no separate enforcement step at the downstream technique.

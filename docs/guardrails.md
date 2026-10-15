# Rejewski Guardrails

Operational rules that bind every Rejewski technique and tool. Each guardrail has an ID, statement, rationale, enforcement, scope, and exceptions. Technique modules in docs/techniques/ cite these IDs by number. ADR 0001 (Rules of Engagement) authorizes the set.

**Accuracy note (2026-10-12, B036).** The Enforcement paragraphs were rewritten against the shipped code. Several earlier paragraphs described checks in an SDK layer that was never built. Each Enforcement paragraph now names the mechanism in code, with file references, or says the guardrail is procedural. Five guardrails are enforced in code (G-1 tenant lock, G-3 GET-only, G-5 evidence writes, G-8 session teardown since 2026-10-13, G-9 row caps). G-2 and G-6 are partly code and partly PR review. G-4 and G-7 are procedural.

---

## G-1 — Consent-bound tenant lock

**Statement.** A run may target any Microsoft 365 tenant, but only the one tenant named in that run's consent record, and the record must exist in the run's replay-log directory before the first token request. For the cloudharbordemo sandbox (76b87c33-6178-4ff9-94a7-164792c8e4c6) the run-level consent record is enough. Any other tenant needs an active v2 durable consent record whose authorization window includes the current date, counter-signed for a third-party assessment (docs/external-auth.md). (Changed 2026-10-15 by ADR 0008; until then G-1 locked every run to the sandbox.)

**Rationale.** Rejewski is built to assess tenants other than CHC's sandbox, and only with the owner's authorization. Binding the tenant to the run's consent record means the code checks that authorization before any token request, so a missing or mismatched record stops the run with no sign-in or Graph trace in the target tenant. The sandbox remains the source of all evidence committed to this repo. The Planner host tenant (where Project Harbor Sonar tracking lives) is a program-management surface and is never a target; conflating the two is a documented historical hazard (ADR 0001 v0.1 carried the Planner host tenant ID in error).

**Enforcement.** scripts/roe_gate.py holds the rules (`authorize_run`) and reads local JSON only. `identity.acquire_token()` calls it first, before it builds an MSAL client, and raises `ConsentError` when the run has no consent record for its run ID and tenant, so a refused run makes no token request and no Graph call. `write_entry()` in scripts/replay_log.py calls it again for any entry whose tenant is not the sandbox, and refuses any entry whose tenant_id is not a GUID; this is the backstop for any path that reaches the writer without going through identity. scripts/step4-token-smoke.py and scripts/demo_b007_device_compliance.py call MSAL directly, so `roe_gate.require_sandbox()` restricts them to the sandbox. tests/test_roe_gate.py covers every refusal and both enforcement points; tests/test_autonomy_boundary.py (Category 3) still asserts that an unconsented non-sandbox entry is refused. scripts/rejewski_runtime.py does not compare tenant IDs; it refuses out-of-scope techniques at config load (ADR 0001 §3).

**Scope.** Binds every technique module under docs/techniques/, every tool and smoke-test script under scripts/, and the replay-log and per-tool tests under tests/ (test_replay_log.py, test_tool_*.py). Binds the Claude Agent SDK runtime when invoked by an operator and the headless runtime when invoked by CI.

**Exceptions.** None. The gate checks that a consent record exists and that its fields authorize the run; it does not verify signatures. The signed letter behind a v2 record is referenced by `authorization.evidence_ref` and is checked by the operator and reviewer. Technique scope (a run's techniques as a subset of the agreed scope, docs/external-auth.md §3) is not yet enforced by the gate.

---

## G-2 — No tenant app registration

**Statement.** Rejewski never creates, modifies, or deletes an application registration in the target tenant. Only Microsoft-owned first-party OAuth clients may be used.

**Rationale.** A custom app registration is itself an adversary technique (T1136.003 Create Account: Cloud Account variants, T1098.001 Account Manipulation: Additional Cloud Credentials). Gaining one is what later sprints emulate. Starting from a position of "already has a tenant app reg" would short-circuit the kill chain Rejewski is trying to model and would also leave a permanent artifact in the sandbox tenant.

**Enforcement.** Every shipped tool issues GET requests only: tests/test_autonomy_boundary.py asserts structurally and behaviourally that no tool issues a write verb, and `write_entry()` in scripts/replay_log.py refuses a graph_call recorded with a non-GET method, so no tool can create an app registration. `write_entry()` also refuses any entry with an empty borrowed_client_id. Tools take the client ID from the FOCI_CLIENT_ID environment variable, defaulting to `identity.DEFAULT_CLIENT_ID` (14d82eec); the code does not check that value against an allowlist, so the allowlist in ADR 0006 is enforced in PR review against the borrowed_client_id recorded on every replay-log entry. (Corrected 2026-10-12, B036: earlier text said the SDK refuses any client ID not on the allowlist; no such check exists.)

**Scope.** Initial-access techniques, persistence techniques, and any module that touches OAuth client identity. Reaffirmed in every technique module's Borrowed Client section.

**Exceptions.** None in Sprint 1. Gaining a tenant app registration is a Sprint 2+ technique and must be authorized by a future ADR.

---

## G-3 — Consent floor (read-only Sprint 1)

**Statement.** Rejewski requests delegated Microsoft Graph tokens only and never requests a write scope by name. Every shipped tool requests the `https://graph.microsoft.com/.default` scope, so the token carries whatever delegated permissions are consented to the borrowed client in the tenant, which can include write permissions. The read-only floor is therefore held on the request side: Rejewski issues GET requests only. (Corrected 2026-10-12, B036: the Sprint 1 named-scope list, User.Read, User.ReadBasic.All, and Group.Read.All, no longer describes the shipped tools.)

**Rationale.** Consent floors bound the worst-case impact of an emulation gone wrong. A read-only token cannot send mail as the user, cannot modify directory objects, and cannot create persistence artifacts. Sprint 1 deliberately stays on the discovery side of the kill chain so the safety envelope is shallow.

**Enforcement.** `identity.GRAPH_SCOPE_DEFAULT` is `["https://graph.microsoft.com/.default"]`, and every token_event entry records the requested scopes (not the granted scopes). The GET-only guard does the read-only work: `write_entry()` refuses a graph_call whose method is not GET, and tests/test_autonomy_boundary.py asserts that no shipped tool issues a write verb. PR review flags any new scope or HTTP verb. (Corrected 2026-10-12, B036: earlier text said the scope list is pinned in rejewski.config.json and the SDK refuses other scopes; the config has no scope list and no such refusal exists.)

**Scope.** Every shipped tool. The token_event entry (scripts/identity.py, ADR 0005 §2) records the requested scopes.

**Exceptions.** None in Sprint 1. Write-side techniques are deferred to Sprint 2+ with a superseding ADR that uplifts the floor explicitly.

---

## G-4 — FOCI client allowlist

**Statement.** Microsoft Graph Command Line Tools (14d82eec-204b-4c2f-b7e8-296a70dab67e) is the sole borrowed first-party client. Every committed replay-log entry to date records it as borrowed_client_id.

**Rationale.** Constraining the borrowed-client surface to one well-understood, broadly-trusted Microsoft client keeps the sign-in fingerprint stable and predictable. It also gives blue-team detection a single app ID to baseline against during Sprint 1 evidence capture.

**Enforcement.** `identity.DEFAULT_CLIENT_ID` is 14d82eec. Tools accept an override through the FOCI_CLIENT_ID environment variable, and the code does not refuse another value. Because every replay-log entry records borrowed_client_id, the client a run used is visible in its evidence; PR review checks committed evidence and each technique module's front matter against ADR 0006. (Corrected 2026-10-12, B036: earlier text said rejewski.config.json pins the client ID and the SDK refuses any other client; the config has no client ID field and no refusal exists.)

**Scope.** All token acquisition flows the tools use: ROPC on a cache miss and silent refresh-token reuse (ADR 0004, ADR 0005). Applies to every operator-run tool.

**Exceptions.** None in Sprint 1. Sprint 2+ may introduce additional FOCI clients (Azure CLI, Visual Studio) via superseding ADR. Each addition requires its own G-4 amendment naming the client.

---

## G-5 — Evidence capture mandatory

**Statement.** Every tool invocation records a token_event entry and a graph_call entry in the replay log. Together they carry the technique ID, run ID, start and end timestamps, operator UPN, tenant ID, borrowed client ID, requested scopes, token flow (ROPC or silent), the Graph endpoint called, HTTP status, page count, row count, row cap, and outcome (success, row_cap_hit, or error with an error block). A run's entries are consolidated into samples/replay-log/<run-id>.json and committed with its finding-triage records and HTML report. (Corrected 2026-10-12, B036: earlier text listed sign-in and per-call correlation IDs and a SharePoint storage location; the token correlation ID is recorded only when Entra returns one, and committed evidence lives in the repo.)

**Rationale.** The point of Rejewski is repeatable, auditable adversary emulation. A run without evidence is not a run — it cannot be replayed, cannot be reviewed, and cannot ground KPI claims. Mandatory capture also creates the dataset Sprint 2+ detection coverage will be validated against.

**Enforcement.** Every tool writes its entries through `write_entry()` in scripts/replay_log.py, which validates the entry kind, outcome, tenant, borrowed client ID, and HTTP method before writing it to replay-logs/. scripts/consolidate_run.py collects a run's entries by run_id. Failed calls are written with outcome error and an error block, so a failure leaves evidence. There is no separate audit ledger: `logs/rejewski-audit.jsonl` is declared in rejewski.config.json, but no code writes it. (Corrected 2026-10-12, B036: earlier text described an SDK-written ledger at that path.)

**Scope.** All technique invocations including smoke tests and replay reruns. Failed runs are captured with the failure mode noted.

**Exceptions.** None.

---

## G-6 — Audit log redaction

**Statement.** Evidence published to the repo carries per-call metadata (endpoint, status, page and row counts), not enumerated directory payloads: no user, group, application, or policy names or object IDs read from the tenant. Three kinds of value are published as-is: the cloudharbordemo tenant ID, the Graph Command Line Tools client ID, and the UPNs of sandbox test accounts that a tool signs in as or targets by name (for example the operator account on every entry, and the mailbox an inbox-rules call targets). Operator-local paths are redacted. (Corrected 2026-10-12, B036: earlier text said UPNs and display names are hashed and an unredacted index is kept in SharePoint; Rejewski does not hash any field, and it avoids the exposure by never writing response payloads.)

**Rationale.** The Rejewski repo is intended to be public so the techniques and guardrails can be cited externally. Publishing the seeded sandbox directory structure verbatim would leak the test fixture, which weakens its value as a fixture if it ever becomes a moving target. Redaction lets the public-repo evidence remain useful for replay while keeping the directory fixture stable.

**Enforcement.** Tools write only response metadata to graph_call entries (status, page_count, row_count, row_cap, row_cap_hit), never response bodies. `write_entry()` keeps only an allowlist of request headers, so no Authorization header is logged. scripts/consolidate_run.py unconditionally replaces the token cache path with `<redacted>`. scripts/tool_list_sharepoint_sites.py scrubs the tenant GUID from site URLs. The redact_secrets flag in rejewski.config.json is not read by any tool. PR review checks committed evidence for any UPN, display name, or object ID other than those published values. (Corrected 2026-10-12, B036: earlier text said the SDK hashes named fields into logs/rejewski-audit.jsonl.)

**Scope.** All evidence content committed to the Rejewski repo (samples/, docs/reports/). Only sandbox evidence is committed; output from a run against any other tenant stays in the operator's private archive (G-1, ADR 0008).

**Exceptions.** The cloudharbordemo tenant ID (76b87c33-6178-4ff9-94a7-164792c8e4c6), the Graph Command Line Tools client ID (14d82eec), and sandbox test-account UPNs that a tool signs in as or targets are not redacted. The two IDs identify a sandbox and a public Microsoft client; the UPNs belong to sandbox test accounts (G-7).

---

## G-7 — No real user data

**Statement.** The sandbox tenant is populated only with seeded test accounts. No real CHC employee account, real customer account, or real production data is staged into the sandbox at any phase.

**Rationale.** Real data in a sandbox is a leak waiting to happen. Even with G-6 redaction, real UPNs in evidence files would be one config error away from public exposure. The cost of seeding fake test users is trivial relative to the downside of leaking a real one.

**Enforcement.** Procedural; no code checks for real accounts. scripts/seed-cloudharbordemo.ps1 creates the seeded accounts, which use Microsoft's fictional demo personas (for example Megan Bowen and Adele Vance), and it is the roster of record. Any account added to the sandbox goes through that script or is recorded in it. (Corrected 2026-10-12, B036: earlier text cited a rejewski-test-NN naming pattern and a quarterly roster audit; the seeded accounts use the demo-persona names, and no audit record exists in the repo.)

**Scope.** All users, all groups, all calendar events, all SharePoint content, all Teams chats inside the sandbox tenant. A tenant assessed under G-1 with its owner's consent holds real data by definition; G-7 does not apply to it, and G-6 keeps its evidence out of this repo.

**Exceptions.** None.

---

## G-8 — Time-boxed sessions

**Statement.** Within a run, the refresh token persists across tool invocations in an encrypted MSAL token cache on the operator workstation, as decided in ADR 0005; that persistence produces the T1550.001 silent-reuse evidence. At the end of a run, Rejewski deletes the cache for every account that acquired a token in the run, so the next run signs in again instead of reusing a session from an earlier one. The teardown is local: a refresh token already issued stays valid at Microsoft Entra ID until it expires or an administrator revokes it, because revoking it would need a Graph write call that G-1 and G-3 forbid. (Updated 2026-10-13, ADR 0005 amendment: before this change the cache persisted across runs with no teardown; R016 on 2026-10-12 acquired all 15 tokens by silent reuse of a cached session.)

**Rationale.** Long-lived token persistence is itself a Sprint 2+ technique (T1078.004 sub-scenarios, T1098.001). Holding tokens across runs would conflate the discovery emulations being shipped in Sprint 1 with persistence behaviors that have not been authorized yet. Time-boxing also bounds the blast radius if a refresh token cache ever leaks from the operator workstation.

**Enforcement.** scripts/identity.py stores the cache with msal-extensions `PersistedTokenCache` over OS encryption (DPAPI on Windows, Keychain on macOS, libsecret on Linux) and refuses a plaintext fallback unless REJEWSKI_ALLOW_PLAINTEXT_CACHE=1 is set; each token_event records the persistence kind. scripts/consolidate_run.py, the last step of every run, calls `identity.end_session()` for each account in the run's token_event entries after the run's evidence is written. `end_session()` deletes the cache file and its lock file and makes no network call. The operator can skip teardown with `--keep-session` (for example when consolidating part of a run that is still going); the console output says when teardown was skipped. tests/test_consolidate_run.py and tests/test_identity.py cover deletion, the opt-out, ordering after the evidence write, no teardown on a failed consolidation, and no network call. The session_keep_warm flag in rejewski.config.json is not read by any tool.

**Scope.** Every operator run, on the workstation that holds the token cache.

**Exceptions.** `--keep-session` on consolidate_run.py. A run that is abandoned before consolidation leaves its cache in place; delete it by running consolidation for that run ID or by deleting the cache file (REJEWSKI_CACHE_PATH, or `%LOCALAPPDATA%\rejewski\<account>.bin` on Windows).

---

## G-9 — Enumeration row cap

**Statement.** Every enumeration tool caps the rows it reads per call. The default cap is 1,000 rows (500 for inbox rules), read in pages sized by `$top`. The operator can change the cap for a run with `--row-cap`. (Corrected 2026-10-12, B036: earlier text cited Sprint 1 defaults of 50 rows for /users and /groups and 25 for /me/memberOf.)

**Rationale.** Bounding enumeration volume keeps evidence files manageable, keeps the sign-in trace visible without paginating across hundreds of audit entries, and bounds the noise floor that downstream detection work has to baseline against in Sprint 2. Uncapped enumeration is itself a louder adversary behavior (anomalous-volume signal); Sprint 1 prefers the quieter end of the spectrum.

**Enforcement.** Each tool's paging loop stops when the cap is reached, and its graph_call entry records row_cap and row_cap_hit (outcome row_cap_hit when the cap was reached). The cap is a per-tool constant (DEFAULT_ROW_CAP), not a rejewski.config.json setting. The code does not refuse a large `--row-cap` value or require a justification; a raised cap is visible in the replay log and is checked in PR review. (Corrected 2026-10-12, B036: earlier text said caps live in rejewski.config.json and the SDK refuses uncapped enumeration.)

**Scope.** Every enumeration tool (scripts/tool_*.py). Token acquisition (T1078.004, T1550.001) is unaffected because it does not enumerate.

**Exceptions.** A raised `--row-cap` is allowed; the replay log records the value used.

**Decision.** G-9 entered as a candidate during the Sprint 1 technique-module drafting; promoted to accepted in this PR on the basis that T1087.004 and T1069.003 already cite a row cap in their Procedure sections without a governing guardrail. Promoting G-9 closes that governance gap before PR 4 (threat-model.md v0.2) ships.

---

## Appendix — Guardrail-to-technique map

| Guardrail | T1078.004 | T1087.004 | T1069.003 |
|-----------|-----------|-----------|-----------|
| G-1 consent-bound tenant | yes | yes | yes |
| G-2 no app reg | yes | inherited | inherited |
| G-3 consent floor | yes | yes | yes |
| G-4 FOCI allowlist | yes | inherited | inherited |
| G-5 evidence | yes | yes | yes |
| G-6 redaction | — | yes | yes |
| G-7 no real users | yes | yes | yes |
| G-8 time-boxed | yes | inherited | inherited |
| G-9 row cap | — | yes | yes |

"Inherited" means the guardrail applies because the technique runs inside a session governed by T1078.004; no separate enforcement step at the downstream technique.

# ADR-0005: Token Persistence and Reuse — Encrypted Cache + Silent Refresh

- **Status:** Accepted
- **Date:** 2026-05-19
- **Deciders:** Derek Morgan (Principal Architect)
- **Supersedes:** none
- **Related:** ADR-0001 Rules of Engagement §1 Tenant Scope, §3 Technique Allowlist, §7 Credential Handling; ADR-0003 Technique Module Format; ADR-0004 Identity Token Acquisition Model (this ADR refines the persistence/reuse layer ADR-0004 left implicit); guardrails G-1 Tenant Scope Lock, G-2 No tenant app registration; threat-model.md v0.2 §3 Adversary Model (Silent Operator); `b021-research-report.md` — the B021 token-persistence research report (SharePoint, not in-repo; Tue May 19, 2026), cited by section throughout this ADR.

---

## 1. Context

ADR-0004 settled the token acquisition model: delegated tokens, borrowed first-party client (default Microsoft Graph Command Line Tools `14d82eec-204b-4c2f-b7e8-296a70dab67e`), MSAL ROPC against seeded compromised-user credentials. ADR-0004 did not, however, decide how a refresh token captured on the first ROPC attempt is persisted across tool invocations, what cache backend protects that token at rest, how concurrent tools serialize cache writes, or how Continuous Access Evaluation (CAE) claims challenges are handled.

Backlog item B021 (Sprint 1 W2, spawned 2026-05-15 during Tool 1 scoping) is the work to ship a shared refresh-token reuse helper so every Rejewski tool after Tool 1 acquires tokens silently — no fresh ROPC password grant per invocation. Without this helper the simulation's defender footprint is wrong (interactive ROPC every minute looks like a brute-force run, not a credentialed adversary holding a session), the credential exposure is wrong (the compromised password is materialized to the process memory of every tool), and tradecraft fidelity drops (Midnight Blizzard / Octo Tempest both hold one session across many actions).

The persistence question is therefore: where and how does Rejewski store the borrowed refresh token, so that subsequent tools silently re-acquire access tokens without re-running ROPC, without leaving plaintext credentials on disk, and without diverging from how Microsoft Graph Command Line Tools stores its tokens with the same client ID?

## 2. Decision

Rejewski persists borrowed refresh tokens through msal-extensions' `PersistedTokenCache` wrapping `build_encrypted_persistence(path)`. The cache backend selects automatically per platform: DPAPI (Windows), Keychain (macOS), libsecret via D-Bus (Linux). When `build_encrypted_persistence` cannot bind an OS-native encryption backend (typical on headless Linux without an unlocked Secret Service provider), Rejewski refuses to fall back to plaintext `FilePersistence` unless the operator sets `REJEWSKI_ALLOW_PLAINTEXT_CACHE=1`. Opt-in produces a loud replay-log entry tagged with the unencrypted-cache fact.

The MSAL `PublicClientApplication` is constructed with `client_capabilities=["CP1"]` so the borrowed client advertises CAE-capability and surfaces claims challenges structurally rather than as opaque 401s. Silent acquisition uses `acquire_token_silent_with_error` exclusively; the lossy `acquire_token_silent` is forbidden. Interactive fallback uses ROPC against the seeded compromised-user password (consistent with ADR-0004 §2). Device code flow remains the fallback for the ROPC-disabled tenant case per ADR-0004 §4.

Cache path default is `~/.cache/rejewski/<actor-upn-slug>.bin` on Linux with platform equivalents on Windows (`%LOCALAPPDATA%\rejewski\<actor-upn-slug>.bin`) and macOS (`~/Library/Caches/rejewski/<actor-upn-slug>.bin`). Operators can override via `REJEWSKI_CACHE_PATH`. Cache-write serialization is delegated to msal-extensions' bundled portalocker; Rejewski does not implement custom locking.

Every token acquisition — silent reuse or interactive ROPC — emits a `token_event` replay-log entry to the configured replay-log directory. The entry's request envelope records the token endpoint URL, flow (silent or ropc), and requested scopes; the response envelope records outcome, AADSTS code (on error), correlation id, persistence kind (encrypted or plaintext), and cache path. Access tokens, refresh tokens, and id tokens are never written to the replay log. MSAL PII logging stays off by default per `b021-research-report.md` §9 (SharePoint).

## 3. Rationale

- **MSAL/msal-extensions is the documented path.** Microsoft's identity team ships msal-extensions as the cross-platform persistence layer for MSAL Python; the cache schema is shared across MSAL .NET / Java / Python / JS so the on-disk artifact is structurally identical to what `Connect-MgGraph` writes for the same client ID. Rejewski's cache file does not advertise itself as adversary tooling at rest.
- **Encrypted at rest, by default, no operator opt-in required.** DPAPI / Keychain / libsecret are user-bound encryption surfaces; a Rejewski cache pulled off a host without the originating user session cannot be decrypted. ADR-0001 §7 Credential Handling requires that captured credential material live encrypted; the encrypted-by-default decision satisfies §7 without operator action.
- **Headless Linux is a sharp edge.** `build_encrypted_persistence` silently falls back to plaintext `FilePersistence` on Linux without libsecret + unlocked Secret Service. `b021-research-report.md` §3 (SharePoint) flags this as the second-most-likely failure mode for B021. Rejewski's explicit `REJEWSKI_ALLOW_PLAINTEXT_CACHE` opt-in plus a loud replay-log entry forces the operator to acknowledge plaintext exposure rather than discovering it after a tenant-scope incident.
- **CP1 + acquire_token_silent_with_error matches Midnight Blizzard tradecraft.** A naive client that fails on a CAE claims challenge collapses back into interactive ROPC, which then trips MFA / risk policies. A CAE-capable client surfaces the `claims` parameter to the helper, which feeds it into the next interactive call. `b021-research-report.md` §8 (SharePoint) documents this as Midnight Blizzard-tier emulation fidelity; ADR-0004 §3 already commits to that fidelity bar.
- **Refresh tokens rotate; portalocker matters.** Every silent redemption invalidates the previous refresh token after a short grace window. Concurrent tool runs without serialized cache writes can hand one of two tools a stale refresh token and a confusing AADSTS70008. msal-extensions ships portalocker; reusing it is the obvious decision and avoids inventing a custom lock.
- **Token-event replay-log emission is the audit surface.** schema v0.2 (PR 1, Sun May 17, 2026) added the `kind` discriminator with `token_event` as an enumerated value precisely to let scripts/identity.py emit its own entries alongside graph_call entries. ADR-0001 §7 requires that every credential-touching action is replayable; emission at the helper level (not the tool level) ensures coverage even if a future tool forgets.

## 4. Identity-Decision Factors

- **Token type:** delegated.
- **Client ID source:** borrowed first-party (ADR-0004 §4 default).
- **Specific client ID(s):** Microsoft Graph Command Line Tools `14d82eec-204b-4c2f-b7e8-296a70dab67e` (default). Azure CLI `04b07795-8ddb-461a-bbee-02f9e1bf7b46` retained as the FOCI-confirmed fallback for Sprint 2+ refresh-token cross-client techniques.
- **Grant flow:** silent (MSAL `acquire_token_silent_with_error`) on cache hit; MSAL ROPC password grant on cache miss; device code flow as headless-or-ROPC-disabled fallback per ADR-0004.
- **Scope shape:** requested scopes are determined by the calling tool; helper does not narrow or escalate. Default `https://graph.microsoft.com/.default` when the caller does not specify.
- **Consent path:** pre-consented (ADR-0004 §4).
- **MFA posture:** silent path bypasses MFA challenges by design (refresh token already redeems claims). CAE-driven mid-session claims challenges arrive as `insufficient_claims` errors; helper escalates to interactive ROPC with the `claims_challenge` parameter populated.
- **Dwell-signal expectations:** every silent redemption produces a non-interactive sign-in log entry with `appId=14d82eec...`, `clientAppUsed=Mobile Apps and Desktop clients`, `tokenIssuerType=AzureAD`. Volumetric anomaly (long-running sessions, scope diversity over time, IP/UA drift) is the differentiator from legitimate Graph Command Line Tools admin sessions per `b021-research-report.md` §11 (SharePoint).

## 5. Consequences

### 5.1 Positive

- Every Rejewski tool after the first ROPC acquisition runs without re-prompting for the seeded password; matches Silent Operator threat model in threat-model.md v0.2 §3.
- Cache is encrypted at rest by default; meets ADR-0001 §7 without operator action.
- Helper centralizes CAE claims handling; future tools cannot accidentally skip CP1 or `acquire_token_silent_with_error`.
- Every token acquisition is replay-logged as `token_event`; audit coverage is structural, not per-tool.

### 5.2 Negative

- msal-extensions adds a new pinned dependency to the project (loose lower-bound, hard upper-bound on major). Existing pin policy applies; pin is documented in CHANGELOG.md.
- Plaintext-cache opt-in is a real escape hatch. CI runners on headless Linux without libsecret will need `REJEWSKI_ALLOW_PLAINTEXT_CACHE=1`, and that fact will appear in every replay-log entry from that runner. Defenders auditing Rejewski's own logs will see the opt-in. Tradeoff accepted; the alternative (silent plaintext fallback) is worse.
- Refresh-token rotation means cache writes happen on every silent redemption; portalocker means concurrent tool runs serialize at the cache boundary. Throughput cost is acceptable for the Sprint 1/2 tool fleet; revisit if a future tool needs sustained high-concurrency token reuse.

### 5.3 Neutral

- Cache path defaults under `~/.cache/rejewski/` (Linux), `~/Library/Caches/rejewski/` (macOS), `%LOCALAPPDATA%\rejewski\` (Windows). Operators wanting a project-local cache (for reproducibility tests) override via `REJEWSKI_CACHE_PATH`.
- Cache file naming uses an actor-UPN slug so multi-user test scenarios get one cache file per identity; FOCI cross-client tokens for the same identity share one cache row (per `b021-research-report.md` §5, SharePoint).

## 6. Alternatives Considered

- **`SerializableTokenCache` written to disk by Rejewski directly.** Rejected because (a) no encryption; (b) no cross-process locking; (c) the cache schema we'd be writing is the same MSAL schema msal-extensions already manages — reinventing it adds risk without benefit. Revisit window: never.
- **No persistence — ROPC on every tool invocation.** Rejected because (a) defender footprint diverges from credentialed-adversary tradecraft; (b) the seeded password is materialized in every tool's process memory; (c) defeats the entire purpose of B021. Retained for Sprint 0-style one-shot smoke tests only.
- **Custom file-based token store with operator-supplied key.** Rejected because (a) reinvents what DPAPI / Keychain / libsecret already do; (b) operator-supplied keys turn into operational gotchas (lost keys, wrong keys, keys in git); (c) ADR-0001 §7 prefers OS-native protection over operator-managed protection. Revisit window: never for Sprint 1/2; possibly Sprint 3+ if a customer engagement requires HSM-backed key storage.
- **Pre-issued long-lived refresh token written by an operator-controlled bootstrap step.** Rejected for the same reasons ADR-0004 §6 rejected the pre-issued-RT alternative — sidesteps the credential-theft tradecraft Rejewski exists to exercise. Revisit window: Sprint 3+.

### 5.4 Amendment (2026-10-13): end-of-run session teardown

The cache in §2 was meant to carry one session across the tools of a run. It also carried sessions across runs: R016 (2026-10-12) acquired all 15 tokens silently from a session cached days earlier, and guardrail G-8 says sessions do not outlive a run. Decision: `scripts/consolidate_run.py`, the last step of every run, calls `identity.end_session()` for each account in the run's token_event entries after the run's evidence is written, deleting that account's cache file and lock file. `--keep-session` skips it. Consequences:

- Each run starts with an ROPC sign-in (a `token_event` with flow `ropc`, technique T1078.004) and reuses that session silently for the rest of the run (T1550.001). Within-run tradecraft from §1 is unchanged.
- Teardown is local. Revoking the refresh token at Entra ID needs `POST /users/{id}/revokeSignInSessions`, a write call the GET-only floor forbids. The issued refresh token stays valid at Entra ID until it expires; Rejewski no longer holds a copy.
- The seeded password is used once per run instead of once per cache lifetime.

## 7. Compliance and Verification

- **Module entry point.** All token acquisition routes through `scripts/identity.acquire_token(...)`. Inline MSAL usage in technique tools is forbidden after PR 3 (Sprint 1 W2). CI grep check (B008+ slot): `git grep "PublicClientApplication\|acquire_token_by_username_password" -- scripts/ techniques/ ':!scripts/identity.py'` returns zero matches.
- **Plaintext-cache audit.** Replay-log entries with `response.persistence_kind == "plaintext"` are surfaced in the W2/W3 retro review (B003 retro baseline, PR 5 of this sequence). Any non-zero count outside CI runners is investigated.
- **Schema contract.** `kind == "token_event"` entries are emitted by `scripts/identity.py` exclusively; `kind == "graph_call"` entries are emitted by technique tools. Mixing emission sources is a contract violation and blocks merge.
- **Negative check.** `git grep "FilePersistence" -- scripts/ techniques/ ':!scripts/identity.py'` returns zero matches. The only place plaintext persistence may be constructed is inside the helper's opt-in branch.

## 8. Change Log

| Date | Version | Change | Author |
|------|---------|--------|--------|
| 2026-10-13 | v0.2 | §5.4 amendment: end-of-run session teardown in `scripts/consolidate_run.py` via `identity.end_session()`, `--keep-session` opt-out; local only (no revocation call). Closes the G-8 gap documented in B036. | Derek Morgan |
| 2026-05-19 | v0.1 | Initial decision. `PersistedTokenCache` over `build_encrypted_persistence` as default; `REJEWSKI_ALLOW_PLAINTEXT_CACHE=1` opt-in for headless Linux; CP1 client capability; `acquire_token_silent_with_error` exclusive; `token_event` replay-log emission at every acquisition. Refines ADR-0004 persistence layer. | Derek Morgan |

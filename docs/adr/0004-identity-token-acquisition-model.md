# ADR-0004: Identity Token Acquisition — Borrowed First-Party Client (ROPC + FOCI Fallback)

- **Status:** Accepted
- **Date:** 2026-05-16 (v0.1); 2026-05-19 (v0.2 — persistence layer cross-reference)
- **Deciders:** Derek Morgan (Principal Architect)
- **Supersedes:** none
- **Related:** ADR-0001 Rules of Engagement §1 Tenant Scope, §3 Technique Allowlist, §7 Credential Handling; ADR-0003 Technique Module Format (borrowed_client_id required field); ADR-0005 Token Persistence and Reuse (refines this ADR's persistence layer — encrypted cache, silent reuse, CAE handling); guardrails G-1 Tenant Scope Lock, G-9 No Operator-Created App Registrations; threat-model.md v0.2 §3 Adversary Model; docs/phs-zt-scenarios-v0.1.md ZT-S02 Identity Verification; docs/phs-security-roi-baseline-v0.1.md Q5 Identity-Driven Incident Share.

---

## 1. Context

Project Harbor Sonar emulates a threat actor against the lab tenant (<lab-tenant-id>-6178-4ff9-94a7-164792cre-registered, pre-consented application in the target tenant. Creating one would hand the simulation a trusted credential path no adversary would have and would skip the actual tradecraft Rejewski exists to exercise.

Sprint 1 Week 1 B001 (MCS-MOS3 Azure sandbox tenant standup, shipped Wed May 13, 2026) and the three Sprint 1 technique modules (T1078.004 Valid Accounts Cloud, T1087.004 Account Discovery Cloud, T1069.003 Permission Groups Discovery Cloud) all require a token acquisition path. The Master Plan v1.5 Sprint 1 acceptance criteria require a working end-to-end run against a seeded compromised user without creating any artifact in the target tenant attributable to the operator.

The identity question is therefore: how does Rejewski acquire a delegated Microsoft Graph token against a seeded compromised user without registering an application in the target tenant?

A companion question — how the borrowed refresh token is persisted across tool invocations so that subsequent tools acquire access tokens silently — was left implicit in this ADR's v0.1. ADR-0005 (Tue May 19, 2026) settles that question; this ADR retains the WHAT (borrow a first-party client; ROPC default; FOCI fallback) and delegates the HOW of persistence to ADR-0005.

## 2. Decision

Rejewski acquires delegated Microsoft Graph tokens by borrowing a first-party Microsoft client ID that the target tenant already trusts. The default borrowed client is Microsoft Graph Command Line Tools (`14d82eec-204b-4c2f-b7e8-296a70dab67e`). The default grant flow is MSAL ROPC against seeded compromised-user credentials on cache miss, with silent reuse via msal-extensions' encrypted `PersistedTokenCache` on every subsequent invocation per ADR-0005. The fallback grant is device code flow when ROPC is tenant-disabled. No tenant-side app registration is created in any target tenant for Rejewski's use, ever.

## 3. Rationale

- **Tradecraft fidelity.** A real adversary cannot create a pre-consented enterprise application in the victim tenant on day one. Starting the simulation with one would short-circuit the very surface area Rejewski is supposed to exercise. Borrowing a first-party client that every tenant already trusts is what an adversary with stolen credentials actually does (Microsoft MDDR 2024 reports 600M+ identity attacks per day, >99% password-based).
- **Cite-able signal surface.** ROPC against a borrowed first-party client produces deterministic detections at the tenant's Identity Protection and Defender surfaces — `unfamiliarFeatures` riskEventType on non-interactive sign-in (Microsoft Learn explicit), `AADSTS50076` on MFA-required Conditional Access, `AADSTS53000` when CA requires a compliant device. These are the signals the zt-scenarios doc anchors against.
- **No operator footprint in target tenant.** ADR-0001 §1 Tenant Scope and §7 Credential Handling, plus guardrail G-9, require that the operator leave no durable artifact attributable to Rejewski in the target tenant. App registrations are durable artifacts. Borrowed first-party clients are not.
- **Gaining an app registration is itself a technique to simulate.** T1098.005 Device Registration, T1606 Forge Web Credentials, T1550.001 Application Access Token, and OAuth illicit consent grant are parked in threat-model.md v0.2 §7 as Sprint 2+ techniques. Pre-registering a Rejewski app would burn those techniques before they could be exercised.
- **Persistence layer is now decided.** v0.1 of this ADR left the cross-invocation persistence of the borrowed refresh token implicit; ADR-0005 settles it (encrypted `PersistedTokenCache`, headless-Linux plaintext refusal, CP1 capability, `acquire_token_silent_with_error` exclusive, `token_event` replay-log emission).

## 4. Identity-Decision Factors

- **Token type:** delegated.
- **Client ID source:** borrowed first-party.
- **Specific client ID(s):** Microsoft Graph Command Line Tools `14d82eec-204b-4c2f-b7e8-296a70dab67e` (default). Sprint 2+ FOCI-confirmed fallback: Azure CLI `04b07795-8ddb-461a-bbee-02f9e1bf7b46` (confirmed FOCI member per secureworks); use when a refresh-token-theft technique requires verified FOCI membership. The default client is NOT a confirmed FOCI member — that distinction matters for any technique module that depends on cross-client refresh-token reuse.

  > **SUPERSEDED BY ADR-0006 (2026-07-28) — Azure CLI fallback provision only.**
  > ADR-0006 establishes a formal client allowlist containing
  > `14d82eec-204b-4c2f-b7e8-296a70dab67e` **only**, per guardrail G-3. Azure CLI
  > `04b07795-8ddb-461a-bbee-02f9e1bf7b46` is **no longer an approved client** and must not
  > be used. A technique that genuinely requires verified FOCI membership needs a new ADR
  > adding a confirmed member to the ADR-0006 §2 allowlist; it cannot rely on this
  > provision. The factual statement above — that the default client is not a confirmed
  > FOCI member — **stands** and is carried forward in ADR-0006 §5.3. Everything else in
  > this ADR (borrowed-client model, ROPC default, device-code fallback, no tenant app
  > registration) remains in force.
- **Grant flow:** silent reuse via the encrypted `PersistedTokenCache` per ADR-0005 on cache hit; MSAL ROPC password grant against the v2.0 token endpoint on cache miss; device code flow (fallback) when the target tenant has disabled ROPC via authentication policy.
- **Scope shape:** minimum required scopes per technique module. Static at module level, declared in the module's borrowed_client_id field per ADR-0003. No dynamic scope escalation in Sprint 1.
- **Consent path:** pre-consented. First-party Microsoft clients carry tenant-level pre-consent for delegated Graph scopes; no admin-consent or user-consent click-through.
- **MFA posture:** challenge bypassed by ROPC when MFA is not enforced on the user/app combination. When CA requires MFA, ROPC fails with `AADSTS50076` (verbatim Microsoft text in zt-scenarios doc ZT-S02). That failure is itself a desired Rejewski signal — it proves the defender's MFA-required CA policy is effective. Silent reuse via cache bypasses MFA challenges entirely on the silent path (refresh token has already redeemed claims); CAE-driven mid-session claims challenges escalate to interactive per ADR-0005 §2.
- **Dwell-signal expectations:** see docs/phs-zt-scenarios-v0.1.md Scenario 2. Primary fire: Identity Protection `unfamiliarFeatures` riskEventType on the first ROPC attempt from a new ASN/IP/UA. Secondary fires: `unlikelyTravel`, `anonymizedIPAddress`, `passwordSpray` (only on successful password validation). Sign-in log row carries `clientAppUsed` (expected value `Mobile Apps and Desktop clients`, pending sandbox confirmation per zt-scenarios Gap 1), `ConditionalAccessStatus`, and `riskEventType`.

## 5. Consequences

### 5.1 Positive

- No tenant-side artifact attributable to Rejewski; meets ADR-0001 §1 and G-9.
- Deterministic, cite-able defender signal surface anchored in Microsoft Learn.
- Technique modules T1078.004, T1087.004, T1069.003 work against any Entra tenant without per-tenant setup; the borrowed client is universally trusted.
- App-registration-creation techniques (T1098.005, T1606, T1550.001, OAuth illicit consent grant) remain unburned for Sprint 2+.

### 5.2 Negative

- ROPC is being deprecated by Microsoft for new applications. The borrowed first-party client retains ROPC capability today, but this is a depreciating surface; a Sprint 3+ ADR will need to formalize the migration to device code as default.
- ROPC against a borrowed first-party client makes traffic look like legitimate admin tooling. Defenders cannot block the borrowed client app ID without breaking real admin workflows. The compensating signal is volumetric (MicrosoftGraphActivityLogs reads per ZT-S03) and risk-based (Identity Protection), not app-block-based.
- No documented MCAS alert fires specifically on ROPC against a FOCI client (zt-scenarios Gap 2). Rejewski runs against the lab tenant may not surface an MCAS-side detection chain; downstream demo materials (B007 device compliance demo) must rely on Entra-side signals.
- The default borrowed client (Graph Command Line Tools) is NOT a confirmed FOCI member. Sprint 2+ techniques requiring verified FOCI behavior (refresh-token theft, cross-client reuse) MUST use Azure CLI `04b07795` instead. This is a known correction surfaced Fri May 15, 2026. **Superseded in part by ADR-0006 (2026-07-28):** the "MUST use Azure CLI" instruction no longer applies — Azure CLI is not on the ADR-0006 allowlist. The not-a-confirmed-FOCI-member fact stands; a FOCI-dependent technique now requires a new ADR extending the allowlist.

### 5.3 Neutral

- ROPC requires the seed user's password in cleartext at runtime on cache miss. ADR-0001 §7 Credential Handling and `.gitignore` discipline govern storage; the password lives in the local `.env` only and is rotated on a per-engagement basis. Decision: acceptable for the controlled sandbox; revisit if Rejewski ever runs outside the lab tenant. On cache hit the password is not materialized.

## 6. Alternatives Considered

- **Operator-registered enterprise app in the target tenant.** Rejected because (a) violates G-9 and ADR-0001 §1; (b) burns Sprint 2+ techniques T1098.005, T1606, T1550.001, OAuth illicit consent grant; (c) leaves a durable, attributable artifact in the victim tenant. Revisit window: never as a Sprint 1 path; the artifact-creation surface is itself a Sprint 2+ technique to simulate.
- **Pre-issued long-lived refresh token.** Rejected because (a) sidesteps the entire credential-theft tradecraft Rejewski exists to exercise; (b) a real adversary does not receive a refresh token gift-wrapped; (c) refresh-token theft is itself a Sprint 2+ technique (T1550.001 family). Revisit window: Sprint 3+ when refresh-token theft is on the deck.
- **Application-only (client credentials) flow.** Rejected because (a) requires a tenant-registered app and admin consent, which violates G-9; (b) the threat model Rejewski emulates is a compromised user, not a compromised application; (c) app-only flows do not produce the same Identity Protection signals (`unfamiliarFeatures` is delegated-sign-in-scoped). Revisit window: never as the default Sprint 1 path; may appear in a separate ADR for techniques that explicitly emulate compromised-app scenarios.
- **Device code flow as default.** Rejected as default because (a) requires human-or-script interaction at a separate device endpoint and complicates automation; (b) Sprint 1 acceptance criteria require a single-process end-to-end run. Retained as fallback for the ROPC-disabled tenant case. Revisit window: Sprint 3+ if ROPC deprecation timeline forces the flip.

## 7. Compliance and Verification

- **Per-module declaration.** Every technique module under `techniques/` declares its `borrowed_client_id` per ADR-0003. CI check (TBD, B008+ slot) verifies the declared client ID is one of the approved values: `14d82eec-204b-4c2f-b7e8-296a70dab67e` (default) or `04b07795-8ddb-461a-bbee-02f9e1bf7b46` (Azure CLI fallback for FOCI-required cases). **Superseded by ADR-0006 §2 (2026-07-28):** the approved set is now `14d82eec-204b-4c2f-b7e8-296a70dab67e` only. Any such CI check must validate against the ADR-0006 allowlist, not the two-value set above. See ADR-0006 §7 for the current verification procedure.
- **Evidence schema.** `scripts/tool_list_users.py` and successor tool scripts emit `borrowed_client_id` in the evidence JSON. Replay-log writer middleware (PR 1 of this sequence, Sun May 17, 2026) includes this field in every entry.
- **Persistence layer.** Token acquisition routes exclusively through `scripts/identity.acquire_token(...)` per ADR-0005 §7. Inline `msal.PublicClientApplication` / `acquire_token_by_username_password` usage in technique tools is forbidden after PR 3 (Sprint 1 W2).
- **Grep verification.** `git grep "borrowed_client_id"` across `techniques/` and `scripts/` returns matches for every active technique module and tool script. Zero matches in `docs/` outside this ADR, ADR-0003, ADR-0005, and threat-model.md.
- **Negative check.** `git grep "az ad app create\|New-AzADApplication\|graph applications POST"` returns zero matches across the repo. Any positive match is an ADR-0004 violation and blocks merge.

## 8. Change Log

| Date | Version | Change | Author |
|------|---------|--------|--------|
| 2026-05-16 | v0.1 | Initial decision. Borrowed first-party client (Graph Command Line Tools `14d82eec`) as default; Azure CLI `04b07795` as FOCI-confirmed fallback for Sprint 2+ refresh-token techniques. ROPC default with device-code fallback. No tenant app registration ever. | Derek Morgan |
| 2026-05-19 | v0.2 | Persistence-layer cross-reference. ADR-0005 (Token Persistence and Reuse) refines the silent-reuse behavior, encrypted cache backend, headless-Linux plaintext refusal, CAE/CP1 handling, and `token_event` replay-log emission this ADR left implicit. §2 Decision, §4 Identity-Decision Factors, §5.3 Neutral, and §7 Compliance updated to reference ADR-0005. No reversal of v0.1 decisions. | Derek Morgan |
| 2026-07-28 | v0.3 | Azure CLI fallback provision superseded by ADR-0006. Supersession notes added to §4 (Specific client IDs), §5.2 (the "MUST use Azure CLI" instruction), and §7 (the two-value CI check) — original text retained, not rewritten. Azure CLI `04b07795` is no longer an approved client; the ADR-0006 allowlist holds `14d82eec` only, per G-3. The factual note that `14d82eec` is not a confirmed FOCI member stands. All other v0.1/v0.2 decisions remain in force. | Derek Morgan |

# ADR-0008: Consent-Bound Tenant Lock

- **Status:** Accepted
- **Date:** 2026-10-15
- **Deciders:** Derek Morgan (Principal Architect)
- **Supersedes:** ADR-0001 §1 tenant scope (sandbox tenant only); guardrail G-1 as a sandbox-only lock
- **Related:** ADR-0001 (Rules of Engagement), ADR-0005 (token persistence), docs/guardrails.md G-1, G-6, G-7, docs/external-auth.md, docs/roe-consent-flow.md, schemas/roe-consent/v1.json and v2.json

---

## 1. Context

Rejewski exists to run against a Microsoft 365 tenant whose owner has given Rules of Engagement consent. Until this ADR, guardrail G-1 locked every run to the `cloudharbordemo` sandbox (`76b87c33-6178-4ff9-94a7-164792c8e4c6`) through a constant in `scripts/replay_log.py`. `docs/external-auth.md` defined the authorization chain for a third-party tenant and stated that a superseding ADR would be needed before any such run could execute.

Two gaps followed from the sandbox-only lock. First, the toolkit could not do the job it is published to do. Second, consent was a record the operator wrote, and no code checked for it. The v1.0 release notes draft (2026-10-15) surfaced the first gap, and Derek directed that G-1 be revised the same day.

## 2. Decision

G-1 becomes a **consent-bound tenant lock**. A run may target any tenant, but only the one tenant named in that run's consent record.

1. **A run ID is required.** The consent record is found by run ID in the replay-log directory the tools write to.
2. **One tenant per run.** The run's consent records must all name the same tenant, and it must equal the tenant the run is about to use.
3. **Sandbox tenant.** The v1 replay-log-embedded consent record is enough.
4. **Any other tenant.** The record must be a v2 durable record (`schemas/roe-consent/v2.json`) with `engagement.status` `active` and the current UTC date inside `authorization.effective_date` to `expiry_date`, inclusive. For `engagement.type` `third_party_assessment`, the record must also show `counterparty.is_self_test` false and a signature method other than `self_test_attestation`, per `docs/external-auth.md` §2. An operator assessing a tenant they own uses `engagement.type` `self_test` with that tenant's ID.

Enforcement points:

- `scripts/roe_gate.py` holds the rules (`authorize_run`). It reads local JSON only.
- `scripts/identity.acquire_token` calls `authorize_run` first, before it builds an MSAL client, so a refused run makes no token request and no Graph call.
- `scripts/replay_log.write_entry` calls `authorize_run` for any entry whose tenant is not the sandbox, and refuses any entry whose tenant is not a GUID. It is the backstop for any path that reaches the writer without going through `identity`.
- `scripts/step4-token-smoke.py` and `scripts/demo_b007_device_compliance.py` call MSAL directly, so they are restricted to the sandbox (`roe_gate.require_sandbox`).

## 3. Rationale

- The tenant a run may touch is decided by that run's consent, which is the authorization the program's Rules of Engagement require.
- Every check can only deny. A missing, mismatched, inactive, or out-of-window record stops the run before the first network call.
- The change also tightens sandbox runs. Before this ADR, a sandbox run needed no consent record in code; now every run needs one.
- The check is local and has no dependency on Graph, so it adds no network footprint.

## 5. Consequences

### 5.1 Positive

- Rejewski can assess any tenant whose owner has authorized the run, which is its stated purpose.
- Consent becomes a gate in code. A run cannot start without a consent record for its run ID and tenant.
- A refused run leaves no sign-in or Graph trace in the target tenant.

### 5.2 Negative

- **Real tenant data.** Runs against other tenants touch real accounts. Tools still write only per-call counts to the replay log, but evidence from any tenant other than the sandbox must never be committed to this repo (G-6, G-7). A v2 record also carries counterparty names and email addresses, and `consolidate_run.py` copies the consent record into the consolidated log, so third-party run output stays in the operator's private archive.
- **The gate checks the record, not the signature.** An operator can write a record that passes. The signed letter behind a v2 record is referenced by `authorization.evidence_ref` and is checked by the operator and reviewer, as `docs/external-auth.md` describes.
- **Technique scope is not yet enforced against the consent record.** `docs/external-auth.md` §3 requires a run's techniques to be a subset of the agreed scope. The gate does not check this yet; it is a follow-up item.
- **The interactive consent prompt is still not wired in.** The record is written with `scripts/write_consent_record.py` (or an equivalent JSON file) before the tools run.

### 5.3 Neutral

- Committed sandbox evidence (R002 to R016) is unaffected; the writer still accepts sandbox entries.
- `SANDBOX_TENANT_ID` now lives in `scripts/roe_gate.py`; `scripts/replay_log.py` imports it.

## 6. Alternatives Considered

- **A tenant allowlist in `rejewski.config.json`.** Rejected because it separates authorization from the run: a tenant on the list would be usable by any run, with or without consent for that run.
- **Keep the sandbox lock and let users fork to change it.** Rejected because it defeats the purpose of the toolkit and moves the safety decision outside the code.
- **Require a v2 record for the sandbox too.** Rejected for now. The sandbox is CHC-owned, and every committed sandbox run uses the v1 shape. Revisit if the sandbox is ever shared.

## 7. Compliance and Verification

- `tests/test_roe_gate.py` covers each rule (missing run ID, missing record, record for another run, tenant mismatch, conflicting records, v1-only record for a non-sandbox tenant, each non-active status, both sides of the window and its inclusive bounds, third-party self-attestation, `is_self_test`, non-GUID tenants), both enforcement points (no MSAL client built, no evidence written on refusal), and `require_sandbox`.
- `tests/test_identity.py` writes the run's consent record before calling `acquire_token`.
- `tests/test_autonomy_boundary.py` Category 3 still asserts that an unconsented non-sandbox entry is refused.

## 8. Change Log

| Date | Version | Change | Author |
|------|---------|--------|--------|
| 2026-10-15 | v1.0 | Initial decision. G-1 changes from a sandbox-only lock to a consent-bound tenant lock enforced in `scripts/roe_gate.py`, `identity.acquire_token`, and `replay_log.write_entry`. | Derek Morgan |

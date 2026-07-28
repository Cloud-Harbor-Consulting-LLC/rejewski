# ADR-0006: FOCI Client Allowlist

- **Status:** Accepted
- **Date:** 2026-07-22
- **Deciders:** Derek Morgan (Principal Architect)
- **Supersedes:** none
- **Related:** ADR-0001 (G-3 guardrail), ADR-0004 (identity token acquisition model), docs/guardrails.md

---

## 1. Context

Rejewski acquires Microsoft Graph tokens by borrowing a first-party Microsoft client
registered as a member of the Microsoft FOCI (Family of Client IDs) family. FOCI allows
a refresh token issued to one family-member application to be silently exchanged by any
other family member, enabling token reuse without re-authentication and without a tenant-
side app registration.

The choice of which FOCI client to borrow is a security-relevant decision. Different
clients carry different detection signals (the client ID appears in Entra sign-in logs
and MicrosoftGraphActivityLogs), different scope access, and different threat-intelligence
associations. A wrong choice could suppress realistic detection signals or expand the
tool's scope beyond the ROE guardrails.

ADR-0001 G-3 prohibits new app registrations. ADR-0004 documents the borrowed-client
pattern and ROPC acquisition flow. Neither document formally records which client IDs are
approved for use in Rejewski, what criteria govern future additions, or what process is
required to add a new client. This ADR establishes all three.

---

## 2. Decision

Only the FOCI client IDs listed in the allowlist below may be used in Rejewski. Adding
a new client ID to the allowlist requires a new ADR that supersedes this one. The current
allowlist contains one client:

| Client name | Client ID | Approved sprint | Source |
|---|---|---|---|
| Microsoft Graph Command Line Tools | 14d82eec-204b-4c2f-b7e8-296a70dab67e | Sprint 1 | ADR-0004 |

---

## 3. Rationale

**Why maintain a formal allowlist rather than deferring to ADR-0001 G-3.**
G-3 prohibits new registrations but does not enumerate which borrowed clients are
permitted. Without an explicit allowlist, a future contributor could introduce a different
FOCI client — changing detection signals and scope access — without triggering an
architectural review. A formal list closes that gap.

**Why Microsoft Graph Command Line Tools (14d82eec) as the sole approved client.**
Four factors drove the Sprint 1 selection and remain valid:

1. **Scope breadth.** The Microsoft Graph Command Line Tools client holds admin-consented
   access to a wide range of Graph delegated scopes in Microsoft tenants. This allows
   Rejewski to add new tools without requiring a new client or a new registration.

2. **Detection realism.** The 14d82eec client ID appears in published threat-intelligence
   research (Secureworks CTU, MDSec) as a client used in real-world adversary token-theft
   and ROPC-spray campaigns. Sign-in events from this client ID are therefore detectable
   by analysts using existing threat-intel feeds and KQL hunt rules.

3. **No tenant registration.** As a first-party Microsoft FOCI member, 14d82eec does not
   require an Enterprise Application registration in the target tenant. This maintains
   the no-tenant-app-reg posture required by ADR-0001 and minimises the artifact
   footprint in the sandbox.

4. **Stable, documented identity.** The client ID is publicly documented by Microsoft and
   in third-party research, making it reproducible and auditable across Rejewski's
   programme lifetime.

---

## 4. Identity-Decision Factors

- **Token type:** delegated
- **Client ID source:** borrowed first-party (FOCI)
- **Specific client ID(s):** 14d82eec-204b-4c2f-b7e8-296a70dab67e (Microsoft Graph Command
  Line Tools). Provenance: Microsoft Learn (Graph PowerShell documentation), Secureworks
  CTU research, MDSec research.
- **Grant flow:** ROPC (initial acquisition); silent refresh-token reuse on subsequent calls
  (ADR-0005)
- **Scope shape:** minimum required scopes per tool, incrementally consented. Static at
  programme start; expanded per-tool as new endpoints are added.
- **Consent path:** admin-consent required. The FOCI family pre-consent in a tenant is
  not sufficient for all scopes; delegated scopes used by Rejewski require explicit admin
  consent in the target tenant before first use.
- **MFA posture:** ROPC bypasses interactive MFA challenge by design. This is the emulated
  adversary behaviour (credential-stuffing or stolen-credential scenario where the target
  account lacks Conditional Access enforcement of MFA on ROPC flows).
- **Dwell-signal expectations:** sign-in events from 14d82eec appear in Entra sign-in logs
  with appId=14d82eec-204b-4c2f-b7e8-296a70dab67e and clientAppUsed="Microsoft Graph
  Command Line Tools". MicrosoftGraphActivityLogs records the client ID on every Graph
  call. Defender for Identity and Defender for Cloud Apps can alert on anomalous ROPC
  usage from this client ID.

---

## 5. Consequences

### 5.1 Positive

- All Rejewski tools share a single, consistent identity signal in tenant telemetry.
  Analysts reviewing MicrosoftGraphActivityLogs see one client ID across all tool runs,
  making run attribution straightforward.
- Future tool authors do not need to make client selection decisions; the allowlist
  resolves the choice before the tool is written.
- Detection engineers testing against Rejewski runs can write KQL hunt rules scoped to
  14d82eec without needing to account for multiple client IDs.

### 5.2 Negative

- All Rejewski tools share the same client ID, so a Conditional Access policy or tenant
  block on 14d82eec would block all tools simultaneously. This is acceptable for the
  sandbox programme but limits future production-tenant testing options.
- Adding a second FOCI client (for scope or detection-variety reasons) requires a full
  ADR review, which is intentionally heavyweight. Operators who need a different client
  for a single-tool experiment cannot make that change without a superseding ADR.

### 5.3 Neutral

- The allowlist formalises a decision that was already implicit in ADR-0004. No behaviour
  changes in this sprint; this ADR adds governance documentation only.
- FOCI family membership of 14d82eec could theoretically change if Microsoft removes
  the client from the FOCI family. If that occurs, the ROPC token-reuse pattern documented
  in ADR-0005 would break. The allowlist does not prevent this failure mode; it would
  require re-evaluation at that point.

---

## 6. Alternatives Considered

- **Azure CLI (04b07795-8ddb-461a-bbee-02f9e1bf7b46).** Valid FOCI member. Rejected because
  Azure CLI is more associated with Azure Resource Manager than Microsoft Graph API access,
  producing less realistic Graph-access detection signals for the M365 threat model.
  Revisit window: never for this programme scope; revisit if a Rejewski variant targets
  Azure ARM surfaces.

- **Microsoft Teams Desktop client.** Valid FOCI member. Rejected because Teams client sign-
  ins blend with high-volume legitimate Teams traffic in Entra logs, reducing detection
  signal clarity. The goal is a client that stands out in Graph audit logs for an analyst,
  not one that hides in normal traffic. Revisit window: never.

- **Per-tool FOCI client rotation (different client per tool).** Would produce more varied
  detection signals but complicates the token-persistence model (ADR-0005), breaks the
  single-identity-signal principle, and increases the number of variables an analyst must
  track during a Rejewski replay. Rejected. Revisit window: Sprint 5+ if a multi-identity
  scenario is explicitly added to the adversary model.

---

## 7. Compliance and Verification

**How to confirm an implementation honours this ADR:**

1. Confirm the single source of truth. `grep -n "DEFAULT_CLIENT_ID" scripts/identity.py`
   must show `DEFAULT_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"`. Every tool
   resolves its borrowed client from this constant.

2. Confirm no script hardcodes a different client ID as a value:

   ```
   grep -rEn 'client_id\s*[:=]\s*"[0-9a-f]{8}-' scripts/ --include=*.py
   ```

   Any line returned whose GUID is not `14d82eec-204b-4c2f-b7e8-296a70dab67e` is a
   violation. (A bare `grep -r "client_id" scripts/` is *not* a useful check: `client_id`
   and `borrowed_client_id` are parameter and field names used throughout the codebase and
   return ~78 non-violating lines.)

3. Inspect replay-log samples under `samples/replay-log/`. Every `token_event` and
   `graph_call` entry must carry
   `borrowed_client_id=14d82eec-204b-4c2f-b7e8-296a70dab67e`.

4. Run the full test suite (`pytest`). The committed fixtures under `tests/fixtures/` and
   every sample replay-log entry carry the approved client ID; a switch to a different
   client would surface in schema validation and the replay-log round-trip tests.

**Runtime override caveat.** Tools resolve the borrowed client as
`os.environ.get("FOCI_CLIENT_ID", identity.DEFAULT_CLIENT_ID)`, so an operator can point a
run at a different client via the `FOCI_CLIENT_ID` environment variable. This allowlist is
therefore a **governance control, not a code-enforced one**. A pre-flight or CI check that
rejects a non-allowlisted `FOCI_CLIENT_ID` is a candidate follow-up; ADR-0004 anticipates
the same check under its per-module declaration provision.

A future ADR that supersedes this one must specify the new allowlist in the same table
format as §2 above and document the rationale for each addition in §3.

---

## 8. Change Log

| Date | Version | Change | Author |
|------|---------|--------|--------|
| 2026-07-22 | v0.1 | Initial decision. Formalises Sprint 1 client selection from ADR-0004. | Derek Morgan |

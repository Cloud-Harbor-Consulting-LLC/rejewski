# ADR-NNNN: <Decision Title>

- **Status:** Proposed | Accepted | Deprecated | Superseded by ADR-XXXX
- **Date:** YYYY-MM-DD
- **Deciders:** Derek Morgan (Principal Architect)
- **Supersedes:** none | ADR-XXXX
- **Related:** ADR-XXXX, guardrails G-N, threat-model §N

---

## 1. Context

State the problem, the forces in play, and the constraints. Cite the specific Sprint, backlog item (B-ID), or upstream decision that triggered this ADR. Reference the relevant Master Plan section, threat-model finding, or guardrail being formalized. Keep this section factual — no decision language yet.

## 2. Decision

State the decision in one or two sentences. Use active voice. The decision must be reversible only via a superseding ADR — that is the bar.

## 3. Rationale

Why this decision over the alternatives. Tie each rationale point to a project anchor: Master Plan section, NIST SP 800-207 tenet, Microsoft Zero Trust pillar, ATT&CK technique mapping, or a cite-able source.

## 4. Identity-Decision Factors (omit if not an identity ADR)

For identity-related ADRs, document each factor explicitly. Omit the entire section for non-identity decisions.

- **Token type:** delegated | application | hybrid (delegated with on-behalf-of)
- **Client ID source:** borrowed first-party (FOCI or non-FOCI) | tenant-registered | none
- **Specific client ID(s):** value + provenance (Microsoft Learn, secureworks, mdsec, etc.)
- **Grant flow:** ROPC | device code | authorization code | client credentials | refresh token
- **Scope shape:** minimum required scopes; whether scopes are static or incremental
- **Consent path:** pre-consented (FOCI) | admin-consent required | user-consent required | none
- **MFA posture:** challenge expected | bypassed by flow | not applicable
- **Dwell-signal expectations:** which detections fire (AADSTS code, Identity Protection riskEventType, MCAS anomaly, MicrosoftGraphActivityLogs pattern); cross-link the zt-scenarios doc

## 5. Consequences

Three sub-sections. Be honest about all three.

### 5.1 Positive

- What gets easier, faster, safer, or cheaper.

### 5.2 Negative

- What gets harder. What surface area expands. Which detections become less reliable.

### 5.3 Neutral

- Things that change but cut both ways, or that are observations rather than tradeoffs.

## 6. Alternatives Considered

For each rejected alternative: one-line description, the disqualifying factor, and (when applicable) the Sprint where it could be revisited.

- **Alternative A:** description. Rejected because <reason>. Revisit window: <Sprint N or "never">.
- **Alternative B:** description. Rejected because <reason>.

## 7. Compliance and Verification

How a future contributor confirms an implementation honors this ADR. Pointers to KQL hunts, smoke tests, CI checks, or replay-log evidence schema fields.

## 8. Change Log

| Date | Version | Change | Author |
|------|---------|--------|--------|
| YYYY-MM-DD | v0.1 | Initial decision. | Derek Morgan |

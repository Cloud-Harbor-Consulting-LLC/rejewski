# Rejewski Guardrails

- **Status:** v0.1 outline
- **Date:** 2026-05-14
- **Author:** Derek Morgan
- **Binds to:** ADR 0001 (Rules of Engagement), docs/threat-model.md v0.1

## Purpose

Eight guardrails bind Rejewski's runtime behavior to the Rules of Engagement. Each guardrail is enforceable in code, not aspirational. ADR 0001 sets the contract; this document defines the runtime checks that enforce it.

Sprint 1 ships these guardrails as outline stubs. Full prose buildout and code binding land on the Sprint 1 Sat May 16 paired card.

## G-1 — Tenant Scope Lock

**Binds:** ADR 0001 §1.
**Stub:** At process start, Rejewski reads the operator-provided tenant allowlist file. Any tenant ID present in the hash-match denylist refuses startup. The MCS-MOS3 sandbox tenant ID (cf3f9a61-644f-4d47-a11c-a6600a9bc717) is the Sprint 1 single permitted target.

## G-2 — Consent Floor

**Binds:** ADR 0001 §2.
**Stub:** Per-run interactive consent prompt confirms target tenant ID, technique list, estimated duration, and run ID. The operator types the run ID back to confirm. Consent confirmation is logged to the replay record before any Graph call is issued.

## G-3 — Technique Allowlist

**Binds:** ADR 0001 §3, threat-model section 5.
**Stub:** Technique modules register against a runtime registry. At config load, any technique not present in the threat-model's in-scope list refuses to register. Sprint 1: T1078.004, T1087.004, T1069.003 only.

## G-4 — Read-Default Posture

**Binds:** ADR 0001 §4.
**Stub:** Graph client wrapper rejects non-GET verbs unless the calling technique has declared a per-call write intent in its module manifest. Sprint 1 declares zero write intents.

## G-5 — Replay-Log Immutability

**Binds:** ADR 0001 §5.
**Stub:** Replay log is opened in append-only mode at run start. On run end, the file is closed, hashed (SHA-256), and the hash is written to a sibling .sha256 file. Any subsequent modification invalidates the hash check on the next read.

## G-6 — Rate-Limit Ceiling

**Binds:** —
**Stub:** Graph client wrapper enforces a per-second request ceiling well below Microsoft's documented throttle thresholds. On a 429 response, the technique aborts and the run logs the throttle event. Sprint 1 ceiling: 5 requests per second per technique.

## G-7 — Kill Switch

**Binds:** ADR 0001 §6.
**Stub:** A single config key (rejewski.enabled) is read at process start. If the value is anything other than the literal string "true", every technique module's entrypoint short-circuits before any Graph call. Default state on first deployment: disabled.

## G-8 — Audit Trail

**Binds:** ADR 0001 §5 and §8.
**Stub:** Every Graph call emits an audit record containing: run ID, operator object ID, technique ID, endpoint, verb, response status code, timestamp. Audit records are written to the same replay log as the consent confirmation, in the same append-only stream.

## Change Log

| Version | Date | Author | Notes |
|---------|------|--------|-------|
| v0.1 | 2026-05-14 | Derek Morgan | Outline. G-1 through G-8 stubs committed. Full prose and code binding deferred to Sat May 16. |

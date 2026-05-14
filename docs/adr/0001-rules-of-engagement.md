# ADR 0001 — Rules of Engagement

- **Status:** Proposed (v0.1, outline)
- **Date:** 2026-05-14
- **Author:** Derek Morgan
- **Supersedes:** —
- **Superseded by:** —

## Context

Rejewski simulates adversary tradecraft against a Microsoft 365 tenant under controlled, consented conditions. The threat-model (docs/threat-model.md v0.1) commits Sprint 1 to three ATT&CK techniques (T1078.004, T1087.004, T1069.003) executed from a post-compromise position against a sandbox tenant. Before any run, the tool must establish a binding contract with the operator covering what may be executed, against what tenant, with what evidence trail, and under what stop conditions. This ADR is that contract.

## Decision

Every Rejewski run is bound by the following rules. The tool refuses to execute if any rule cannot be satisfied at run start.

### 1. Tenant scope

Rejewski may only target a tenant whose ID is listed in the operator-provided allowlist file. Sprint 1 floor: exactly one tenant ID, the MCS-MOS3 sandbox (cf3f9a61-644f-4d47-a11c-a6600a9bc717). Production tenant IDs are explicitly excluded by hash-match denylist.

### 2. Consent floor

The operator confirms a per-run consent prompt summarizing: target tenant ID, techniques to be executed, expected duration, and a unique run ID. Sprint 1 exit floor is 5 consented runs logged end-to-end.

### 3. Technique allowlist

Only techniques mapped in the current threat-model section 5 are executable. Sprint 1: T1078.004, T1087.004, T1069.003. Out-of-scope techniques (threat-model section 7) are refused at config load, not at runtime.

### 4. Read-default posture

All Graph calls default to read-only verbs (GET). Write verbs (POST, PATCH, PUT, DELETE) require explicit per-technique allowlist entries and are absent from Sprint 1.

### 5. Replay-log immutability

Every run produces an append-only replay log capturing: run ID, operator, tenant ID, technique IDs invoked, Graph endpoints called, response status codes, and start/end timestamps. The log file is closed and hashed at run end; subsequent edits invalidate the run record.

### 6. Kill switch

A single config flag (rejewski.enabled=false) halts all simulation paths before any Graph call is issued. Default state at first deployment: disabled.

### 7. Credential handling

Tokens acquired during a run live only in process memory. No token, refresh token, or client secret is persisted to disk, log, or replay artifact. The replay log records token acquisition events by timestamp only, never by value.

### 8. Operator identity

The operator is recorded in every replay log by Entra ID object ID, not by display name or UPN. A run executed by a different operator than the one who confirmed consent is refused at the first Graph call.

## Consequences

- Sprint 1 runs are bounded, auditable, and revocable.
- A future ADR will extend the technique allowlist for Sprint 2+; this ADR does not need amendment unless the rules themselves change.
- Write-verb support (Sprint 3+) requires an ADR amendment, not a config flip.

## Change Log

| Version | Date | Author | Notes |
|---------|------|--------|-------|
| v0.1 | 2026-05-14 | Derek Morgan | Outline. Eight rules committed. Full prose buildout deferred. |

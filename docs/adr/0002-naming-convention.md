# ADR 0002 — Naming Convention

- **Status:** Proposed (v0.1, outline)
- **Date:** 2026-05-14
- **Author:** Derek Morgan
- **Supersedes:** —
- **Superseded by:** —

## Context

Rejewski produces three classes of durable artifact during Sprint 1: ADRs, guardrails, and backlog items. Without a binding naming convention, cross-references between artifacts (ADR cites guardrail cites backlog item cites threat-model technique) drift as the project grows. This ADR fixes the convention before the artifact count climbs.

## Decision

### 1. Architecture Decision Records

- **Path:** docs/adr/
- **Filename:** NNNN-kebab-case-title.md (e.g., 0001-rules-of-engagement.md)
- **ID format:** ADR-NNNN, four-digit zero-padded, sequential, never reused
- **In-text reference:** "ADR 0001" with a space, not "ADR-0001" or "ADR0001"
- **Status taxonomy:** Proposed, Accepted, Deprecated, Superseded
- **Required sections:** Status, Date, Author, Context, Decision, Consequences, Change Log

### 2. Guardrails

- **Path:** docs/guardrails.md (single file, all guardrails inline)
- **ID format:** G-N, single digit while N ≤ 9; G-NN once N reaches 10
- **In-text reference:** "G1" through "G8" (no hyphen in chat prose, with-hyphen in headings and tables for sortability)
- **Binding:** every guardrail cites the ADR that introduced it and, where applicable, the ATT&CK technique it constrains

### 3. Backlog items

- **System of record:** Planner (one-way mirror from internal backlog)
- **ID format:** B-NNN, three-digit zero-padded, sequential
- **In-text reference:** "B001" with no hyphen in prose, "B-001" in tables
- **Lifecycle:** Backlog item creates Planner card; Planner card closes when work completes; Planner card carries the canonical due date

### 4. ATT&CK techniques

- **Format:** Full MITRE ID with sub-technique where applicable — T1078.004, not T1078 nor "T1078 sub 4"
- **In-text:** "T1078.004 Valid Accounts — Cloud Accounts" on first mention per document; bare ID thereafter

### 5. Sprints

- **Format:** "Sprint N" — capital S, space, integer (e.g., Sprint 1, Sprint 12)
- **Length:** 4 weeks (committed in PHS project anchors)

### 6. Branch names

- **Format:** feature/<kebab-case-summary> for new work; fix/<summary> for corrections; docs/<summary> for doc-only changes
- **Reference:** never embed an ADR or backlog ID in the branch name — branches are ephemeral, IDs are durable

## Consequences

- All cross-references between artifacts resolve unambiguously.
- File-sort order matches creation order for ADRs (numeric prefix).
- Renaming an artifact is a Supersede event, not a rewrite — original IDs persist permanently.

## Change Log

| Version | Date | Author | Notes |
|---------|------|--------|-------|
| v0.1 | 2026-05-14 | Derek Morgan | Outline. Six artifact classes covered. |

# Project Harbor Sonar — Sprint Review §1 Retrospective Baseline

**Version:** v0.1
**Date:** 2026-05-19
**Owner:** Derek Morgan, Cloud Harbor Consulting
**Backlog:** B003 (Sprint 1, P0 Critical, S)
**Cross-references:** Master Plan v1.5 §6 Sprint Cadence, §9 Sprint Review and Checkpoint Format

---

## 1. Purpose

This document defines the canonical structure for §1 (Retrospective) of every Project Harbor Sonar Sprint Review deck. It establishes:

- The fixed subsection skeleton (What went well, What didn't, Lessons, Carryover).
- Input sources the retrospective draws from at sprint close.
- The grounding pull required before authoring §1 of any Sprint Review.
- Pass and fail criteria for a complete retrospective entry.

Locking the format ensures every sprint's retrospective is comparable across the 9-sprint program (Sprint 1 to Sprint 9, Tue May 12, 2026 to Sat Jan 23, 2027).

---

## 2. Cadence

§1 Retrospective is authored at the close of each sprint, on the final Saturday of the 4-week cycle. Sprint 1 retrospective is due Sat Jun 6, 2026.

---

## 3. Fixed Subsection Skeleton

### 3.1 What Went Well

Three to five bulleted observations grounded in concrete evidence: B-IDs shipped, KPI deltas, demo outcomes. Each bullet cites the B-ID or artifact path. No vague affirmations.

### 3.2 What Didn't

Three to five bulleted observations naming specific blockers, missed deadlines, scope cuts, or quality issues. Each bullet names the failure mode (timing, scope, quality, dependency) and the affected B-ID or surface.

### 3.3 Lessons

Two to four committed standing-rule changes, process adjustments, or anchor decisions derived from §3.1 and §3.2. Each lesson states the trigger and the rule change in plain language. Lessons graduate to auto-memory and Section 9 of chc-developer.md.

### 3.4 Carryover

B-IDs unfinished at sprint close, listed with the reason (under-scoped, blocked, deferred). Each entry maps to the next sprint's backlog row or notes the deferral to a future sprint.

---

## 4. Grounding Pull (Required Before Authoring)

The retrospective is non-fabrication: every bullet traces to one of these surfaces, pulled in this order:

1. PHS product backlog workbook (phs-product-backlog-v*.xlsx). Sprint's B-ID list with final status. Workbook is canonical on B-ID numbering, status, sizing, and sprint assignment.
2. Microsoft Planner board (plan n_IjJzOVx0mwGRlD4I0S4mUAGWqU). Per-card percentComplete and bucket totals.
3. CHANGELOG.md [Unreleased] section. Shipped artifacts and behavior changes for the sprint window.
4. git log on main since sprint start. Commits, merge history, branch hygiene.
5. SharePoint repo mirror. File existence, byte sizes, modification timestamps.
6. KPI Dashboard Weekly KPIs (Build) sheet. Quantitative deltas (Tools Online, Techniques Covered, Evidence Entries, Backlog Δ).

A retrospective draft missing any of these grounding surfaces is rejected.

---

## 5. Pass and Fail Criteria

A §1 Retrospective entry passes when:

- All four subsections (3.1 to 3.4) are populated.
- Every §3.1 and §3.2 bullet cites a B-ID, artifact path, or measurable delta.
- §3.3 lessons identify the trigger and the rule change in plain language.
- §3.4 carryover maps every unfinished B-ID to a next-sprint disposition.
- Grounding pull (§4) is complete and the source surfaces are reachable.

A §1 Retrospective entry fails when:

- Any subsection is empty or hand-waves ("things were busy").
- Bullets reference unnamed work or hypothetical issues.
- Carryover B-IDs lack a next-sprint disposition.
- Grounding surfaces were skipped or unavailable.

---

## 6. Output Format

Retrospective §1 lands in two surfaces per sprint close:

- The sprint's Sprint Review deck (PowerPoint, follows the Sprint Review Template). §1 occupies the first content slide or slides.
- An auto-memory pointer (phs_sprint_N_retrospective.md) summarizing §3.3 Lessons that became standing rules.

---

## 7. Open Items

- Sprint Review Template (PowerPoint) is not yet authored. B003 establishes §1 only. The full template (§2 Velocity, §3 Closed This Sprint, §4 Demo Highlights, §5 Next Sprint Preview) lands as a separate backlog item before Sprint 1 close on Sat Jun 6, 2026.
- KPI Dashboard Weekly KPIs (Build) sheet schema must be finalized before §3.1 and §3.2 quantitative claims can cite specific metric columns.
- Auto-memory pointer schema (phs_sprint_N_retrospective.md) format will be finalized at Sprint 1 close, then back-applied as part of §6.

---

## 8. Revision History

- v0.1 (2026-05-19): Initial baseline. Locks the §1 subsection skeleton, grounding pull, pass and fail criteria, and output format.

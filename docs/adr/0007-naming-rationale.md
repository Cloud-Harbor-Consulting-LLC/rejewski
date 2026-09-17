# ADR 0007 — Naming Rationale and Heritage Attribution

- **Status:** Proposed
- **Date:** 2026-09-17
- **Author:** Derek Morgan
- **Supersedes:** —
- **Superseded by:** —
- **Related:** ADR 0002 (Naming Convention — ID/filename/branch rules; this ADR is the
  *name-origin* record, which ADR 0002 does not cover), README.md (Naming section),
  Risk Register RK018 (trademark clearance, outside-counsel opinion pending)

---

## 1. Context

The project is named **Rejewski**. ADR 0002 (Naming Convention) governs *how* artifacts are
named — ADR IDs, filenames, branch names, in-text reference style — but it does not record
*why the project itself* carries this name, nor the heritage attribution the name invokes. The
README's Naming section previously pointed at a `docs/adr/0002-naming-rejewski.md` file that was
never written; ADR 0002 is the unrelated convention document. This ADR closes that gap by
recording the name's origin and the historical attribution in one durable place, and by stating
the current trademark-clearance posture honestly.

The trigger is the Sprint 5 W19 README v1 deliverable (Master Plan), whose acceptance requires an
80–100 word heritage attribution block placed as the README's Naming section, sourced from a
durable ADR. This ADR is that source.

## 2. Decision

The project name and its heritage attribution are recorded as follows. The attribution paragraph
below is the canonical text; the README Naming section reproduces it verbatim.

> Rejewski is named for Marian Rejewski (1905-1980), the Polish mathematician who in December 1932
> first reconstructed the internal wiring of the German military Enigma cipher machine using
> permutation theory, without access to a captured device. Working with fellow Polish Cipher
> Bureau cryptologists Jerzy Różycki and Henryk Zygalski, he built the foundation later extended
> by British codebreakers at Bletchley Park. The name honors that legacy of applying rigorous
> method to previously "unbreakable" security systems. Trademark clearance research is complete
> internally; a formal opinion from outside counsel is pending as of this writing.

**How the name was chosen.** The name was selected for a direct analogy: Rejewski broke a system
assumed to be unbreakable by applying rigorous, disciplined method rather than by capturing a
device or a secret. Project Harbor Sonar's Rejewski tool mirrors that posture — it applies
systematic, read-only reconnaissance and discovery against a Microsoft 365 tenant whose defenders
assume their configuration is sound, surfacing what a methodical adversary can learn without any
privileged foothold. The analogy is method-over-force, not offense-for-its-own-sake: the tool
stays strictly on the read-only, discovery side of the kill chain (see the guardrails and ADR
0001 Rules of Engagement).

## 3. Rationale

- **One durable home for the name's origin.** Heritage and clearance posture belong in a
  versioned ADR, not only in the README, so the attribution survives README rewrites and can be
  cited by ADR number. This also repairs the dangling `0002-naming-rejewski.md` reference without
  disturbing ADR 0002 (per the ADR 0002 rule that IDs are never reused or renumbered).
- **Historical accuracy over marketing.** The attribution states verifiable facts — the 1932
  reconstruction by permutation theory, the collaboration with Różycki and Zygalski, the later
  extension at Bletchley Park — rather than a simplified "founded modern cryptanalysis" claim.
- **Honest clearance posture.** The name is in use for an internal/private build; internal
  clearance research is complete, but a formal outside-counsel opinion is still pending (Risk
  Register RK018). The attribution says exactly that and claims no more.

## 5. Consequences

### 5.1 Positive

- The README Naming section now has a real, citable source (this ADR), and the broken
  `0002-naming-rejewski.md` link is retired.
- The trademark posture is recorded truthfully and in one place, so no downstream artifact
  overstates clearance.

### 5.2 Negative

- The attribution carries a "pending" clause that will need a one-line update once the
  outside-counsel opinion lands (RK018) — a small, tracked follow-up rather than a silent drift.

### 5.3 Neutral

- This ADR records a name already in use; it does not rename anything and does not alter ADR 0002's
  naming convention.

## 6. Alternatives Considered

- **Fold the heritage text into ADR 0002.** Rejected — ADR 0002 is the naming *convention*
  (ID/filename/branch rules); mixing the project's name-origin narrative into it muddies a
  single-purpose document. Revisit window: never.
- **Keep the attribution only in the README.** Rejected — a README-only home is not durable
  against rewrites and cannot be cited by ADR number; the acceptance criterion explicitly wants an
  ADR source. Revisit window: never.
- **Claim trademark clearance now.** Rejected — the outside-counsel opinion is not yet in hand
  (RK018); claiming clearance would be inaccurate. Revisit when the opinion lands.

## 7. Compliance and Verification

- The README Naming section reproduces the §2 attribution paragraph **verbatim** and links to this
  ADR (not to the nonexistent `0002-naming-rejewski.md`). A reviewer confirms the two paragraphs
  match word-for-word.
- No file in the repo claims trademark clearance beyond "internal research complete, formal opinion
  pending." A reviewer greps changed files for any stronger claim.
- The internal clearance research is retained at `06 - Research & References/rejewski-clearance-memos_2026-08-08.docx`
  (SharePoint, not in-repo). This citation records that internal research exists; it is **not** a
  guarantee of clearance — the outside-counsel opinion (RK018) governs that.

## 8. Change Log

| Date | Version | Change | Author |
|------|---------|--------|--------|
| 2026-09-17 | v0.1 | Initial decision. Records the Rejewski name origin and heritage attribution; states trademark posture as internal-research-complete / outside-counsel-opinion-pending (RK018). Retires the dangling `0002-naming-rejewski.md` reference. | Derek Morgan |

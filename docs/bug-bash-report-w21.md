# Rejewski Bug Bash Report — Sprint 6 Open Week (W21)

- Date: 2026-09-29
- **Scope: FULL REPO** — every directory (scripts, tests, docs incl. ADRs + technique modules, schemas, samples, .github, root files), not the 14-`tool_*.py`-only scope of the W16 precedent. W16 was mid-Sprint-4; this is the last full-repo pass before README v2 (Thu) and Tool 15 (next week).
- Baseline HEAD: `8603a18` (PR #118)
- Test baseline: **192 passed** (recorded before any change)
- Test after changes: **192 passed** (docs/docstring/template changes only — no behavior change, no test delta)
- Format: follows docs/bug-bash-report-w16.md.
- Bound: confirmed items and clear-target stale references fixed directly; anything whose correct target needs the owner's context is **flagged**, not guessed.

> **Two-PR note.** An earlier (superseded) brief scoped this bash to the 14 tools + two docs; that
> subset shipped as **PR #118** — the `docs/attck-coverage.md` (D1) and `docs/guardrails.md` (D2)
> fixes and the 14-tool fleet check. This PR completes the **full-repo** scope: the third confirmed
> item (D3, `replay_log.py`), the sweep across the other 20 scripts and every remaining directory,
> and this report expanded to full-repo. D1/D2 are on `main` and were re-verified still-correct here.

## Part A — Confirmed doc-hygiene items

| # | Item | Status |
|---|---|---|
| D1 | `docs/attck-coverage.md` — leftover "Sprint 3 target TBD at S2 kick-off" / S2-retro planning prose → rewritten as historical record | Fixed in **PR #118**; re-verified |
| D2 | `docs/guardrails.md` — intro "bound every Sprint 1 technique" → present tense; G-1 Scope `tests/replay/` (never materialized) → actual flat `tests/` layout | Fixed in **PR #118**; re-verified |
| D3 | `scripts/replay_log.py` line 24 — docstring "validated against schemas/replay-log/**v0.4**.json" while `SCHEMA_PATH`/`SCHEMA_VERSION` are **v0.5** | **Fixed here** → v0.5.json. (The v0.3/v0.4/v0.5 mentions at lines 5–16 are a legitimate version-history changelog and were left as-is; line 24 was the only drift.) |

## Part B — Full scripts/ sweep (34 script files, not just the 14 tools)

Note: the repo has **34** script files (14 `tool_*.py` + **20** non-tool), not the "31" the brief
estimated — the estimate omitted `reasoning_loop.py` (and miscounted). All 34 were swept.

| Check | Result |
|---|---|
| TODO / FIXME / XXX / HACK / debug prints / `pdb` / `breakpoint()` — repo-wide | **None** (the only `XXXX` hits are intentional fill-in markers in `docs/adr/_template.md`) |
| Schema-version drift in docstrings | Fixed D3 (`replay_log.py`); **no other script** references a stale replay-log schema version — all 14 tools already cite v0.5 (verified, matches the morning pre-check), and no non-tool script cites v0.1–v0.4 |
| G-6 leak scan repo-wide (operator paths `C:\Users`/`USERPROFILE`, cache paths, secret literals) | **None** committed. Tenant/client GUIDs present are the allowed public values only: `76b87c33…` (sandbox tenant), `14d82eec…` (Graph CLI FOCI client), `48df3ad2…` (seeded operator object-id per ADR 0001 §8), `04b07795…` (Azure CLI — **doc references only**, in ADRs 0004/0005/0006 + T1550.001.md, NOT in `rejewski.config.json`, so the G-4 allowlist is intact), and the all-zeros placeholder in the third-party consent sample |
| 14-tool fleet consistency (per W16) | **Clean, 14/14** — empty-result stderr notice consistent, G-6 redaction present in all 14, `--run-id` optional / `replay-logs/` default / `--emit` toggle all 14/14 (W16 N1/N2/N3 stay resolved). (Detail unchanged from PR #118.) |
| Non-tool scripts (20): argparse/`--help`, docstrings | 10 use argparse; no stale schema/path references found; `identity.py`, `replay_log.py`, `write_consent_r0NN.py`, `step4-token-smoke.py`, `seed-cloudharbordemo.ps1` are library/one-off modules (no CLI, by design) |

## Part C — Repo-wide doc-link resolution

- **Markdown links:** 51 markdown files scanned (root docs, all 8 ADRs, all 20 technique modules, demos) → 33 `[](…)` internal links, **0 broken**.
- **Bare path references** (the plain-text `docs/…`, `scripts/…`, `schemas/…` cross-refs the ADRs/techniques use): 101 distinct refs → **3 non-resolving**, triaged:
  1. `docs/adr/0002-naming-rejewski.md` (in ADR 0007) — **confirmed historical**, 0 live links, 4 backticked explanatory mentions describing the reference PR #114 retired. Not broken.
  2. `docs/adr/0004-borrowed-first-party-clients.md` (in `docs/demos/b007-device-compliance.md`) — **broken**: ADR 0004's real filename is `0004-identity-token-acquisition-model.md`. **Fixed here.**
  3. `docs/b021-research-report.md` (×6 in `docs/adr/0005-token-persistence-and-reuse.md`) — **broken, FLAGGED** (see below).
- Also fixed while in `b007-device-compliance.md`: a stale guardrail-ID reference — "G-9 (no operator-created app registrations)" → **G-2 (no tenant app registration)** (current guardrails.md has G-9 = Enumeration row cap; G-2 = No tenant app registration). The identical drift in `docs/adr/0005` line 7 was fixed too. These were the **only two** such stale G-9-as-app-reg references; every other G-9 mention correctly means the row cap.

## Part D — schemas/ (9 files)

- replay-log **v0.1–v0.5** (5), finding-to-control **v0.1**, finding-triage **v0.1**, roe-consent **v1/v2**. v0.5 is the live replay-log schema (`replay_log.py`). The older v0.1–v0.4 are **retained deliberately** to validate the older committed logs (R002–R009 era) — not orphaned.
- No code or doc points at a superseded replay-log schema version as if it were live, except one flagged case (Part F flags).

## Part E — tests/ (25 files)

- All 25 collect and pass (192). Imports resolve to real modules (`replay_log`, `rejewski_runtime`, `consolidate_run`, `finding_dedup`, `finding_coverage_report`, `generate_html_report`, `identity`, `reasoning_loop`). **No orphaned test** references a removed/renamed script or function — an orphaned import would fail collection, and collection is clean.

## Part F — .github/ (wrong-repo content — fixed)

The `.github/` templates were substantially **copied from a different CHC repo (M365-Security-Frameworks) and never adapted to Rejewski**:

- **CODEOWNERS** header read "Code owners for **M365-Security-Frameworks**" → **Fixed** to Rejewski (owner `@dmorgan-chc` and path patterns were already correct).
- **ISSUE_TEMPLATE/config.yml** discussions link pointed at `…/M365-Security-Frameworks/discussions` with "applying the baseline in your tenant" wording → **Fixed** to the `rejewski` repo with Rejewski-appropriate wording.
- **pull_request_template.md** was wholesale the policy-templates repo's template — "New policy template", "cite the principle from **Policy-Design.md**", "**Deploy-CABaseline.ps1 -WhatIf**", "REPLACE_WITH_*_OBJECT_ID", "**markdownlint**" — none of which exist in this Python toolkit → **Rewritten** for Rejewski's actual conventions (types: bug/tool/schema/evidence-run/docs/hygiene; guardrail-or-ADR citation; checklist: suite green, `git diff --check` clean, G-6, CHANGELOG, squash-merge / no Issues / no `Closes #N`) per CONTRIBUTING.md v1.
- The four ISSUE_TEMPLATE forms otherwise reference real fields; `policy_request.yml` is noted in the flags below.

## Part G — samples/ and root files

- `samples/` (replay-log, finding-triage, finding-to-control, roe-consent) validate against their schemas (covered by the suite). No leaked PII beyond the established row-count + operator-UPN convention.
- Root: README, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT (Contributor Covenant v2.1), LICENSE (MIT 2026 Cloud Harbor Consulting LLC), CHANGELOG, `rejewski.config.json` — reviewed; no stale placeholders; the G-4 client allowlist in config is intact (single FOCI client `14d82eec…`).

## Flags — surfaced, NOT fixed (correct remediation needs the owner's context)

- **F1 — `docs/adr/0005` cites `docs/b021-research-report.md` (×6) but the file is not in-repo.** The 6 references cite specific sections (§3, §5, §8, §9, §11) — clearly a substantial B021 research doc, almost certainly in the SharePoint research corpus (as the ADR 0007 clearance memo is). The `docs/` prefix falsely implies an in-repo file. **Recommendation:** either commit the report to `docs/`, or re-annotate the references SharePoint-style like ADR 0007 does ("… — SharePoint, not in-repo"). Not fixed because the true location can't be verified from the repo.
- **F2 — `docs/phs-zt-scenarios-v0.1.md:195` claims replay-log `v0.1.json` carries a `scenario_id` field, but `scenario_id` exists in NO replay-log schema (v0.1–v0.5).** Either the field was planned-but-never-implemented, or it became `run_id` (added in v0.4). This is a v0.1-vintage Pillar-1 scenarios doc; the correct fix depends on whether the ZT-scenario→replay binding still applies. Flagged for a decision.
- **F3 (minor) — `.github/ISSUE_TEMPLATE/policy_request.yml`** ("Propose a new Conditional Access policy") may also be M365-Security-Frameworks heritage. It is arguably in-domain for Rejewski (findings map to CA controls), so it was **left as-is** — noted for a keep/cut decision before public launch.

## Summary

- Confirmed items fixed: **3** (D1 attck-coverage + D2 guardrails in PR #118; **D3 replay_log.py here**).
- Additional stale references fixed by the full-repo sweep: **b007 ADR-0004 filename**, **2× G-9→G-2** guardrail-ID drift (b007 + adr/0005), **3× .github wrong-repo content** (CODEOWNERS, config.yml, PR template). All docs/template only.
- Directories swept: scripts (34), tests (25), docs (51 md incl. 8 ADRs + 20 techniques), schemas (9), samples, .github, root — **repo-wide**. Clean where clean (a valid outcome); findings documented above.
- Doc links: 33 markdown links + 101 bare-path refs verified; the 3 non-resolving triaged (1 historical, 1 fixed, 1 flagged).
- Flags for owner decision: **3** (F1 b021 report, F2 scenario_id, F3 policy_request.yml).
- No functional/behavioral changes; no real functional bug surfaced.
- Test suite: **192 → 192**.
- S6 W21 acceptance ("open bugs closed or moved to v1.1"): no open functional bugs; the confirmed items and clear stale references are closed here; the 3 flags are the only items that may warrant a v1.1/follow-up decision.

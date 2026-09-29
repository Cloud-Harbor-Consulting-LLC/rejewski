# Rejewski Bug Bash Report — Sprint 6 Open Week (W21)

- Date: 2026-09-29
- Scope: doc-hygiene cleanup (2 confirmed items) + QA consistency pass across all 14 tool scripts (`scripts/tool_*.py`), following the W16 template (docs/bug-bash-report-w16.md)
- Baseline HEAD: `9d5f8f8` (PR #117)
- Test baseline: **192 passed** (recorded before any change)
- Test after changes: **192 passed** (docs-only changes — no behavior change, no test delta)
- Bound: confirmed doc-hygiene items fixed directly; fleet check documented whether or not anything needed fixing. No functional/behavioral changes.

## Part A — Doc-hygiene items fixed

**D1 — `docs/attck-coverage.md`: leftover Sprint-1/Sprint-2-era forward-planning language.**
The "Path to Sprint 2 target" section still carried forward-looking planning prose — "Technique
selection for the Sprint 3 checkpoint target (TBD at S2 kick-off) opens when Sprint 2 begins" —
plus an S2-retro "candidates to select" list, never cleaned up across four checkpoints. Sprint 2
closed 2026-07-04; the running total is now 20 techniques. Rewrote the prose as a **historical
record**: the S2 target was reached/exceeded, the total reached 20 by Sprint 4, and the flagged
candidates (T1213.002 → Tool 14; T1580/T1654 → Tools 9/10; T1069.003/T1526 sub-surfaces) were
subsequently implemented. Dropped the forward-looking TBD language and the speculative
T1003/T1552 credential-surface item (out of scope under G-2/G-3 read-only anyway). The growth
table itself is unchanged — it was already the authoritative record.

**D2 — `docs/guardrails.md`: stale Sprint-1 framing + never-materialized `tests/replay/` scope.**
- File intro read "Operational rules that **bound every Sprint 1 technique**" — the guardrails now
  bind all 14 tools across six sprints. Rewrote to "Operational rules that **bind every Rejewski
  technique and tool**" (present tense) and trimmed "ADR 0001 (Sprint 1 Rules of Engagement)" to
  "ADR 0001 (Rules of Engagement)".
- G-1 **Scope** referenced "every replay scenario under `tests/replay/` (when that directory lands
  in Sprint 2)". Confirmed `tests/replay/` **never materialized** — `tests/` is flat at HEAD
  `9d5f8f8` (`test_replay_log.py`, `test_tool_*.py`, no `replay/` subdirectory). Updated the Scope
  line to the actual layout: "the replay-log and per-tool tests under `tests/` (test_replay_log.py,
  test_tool_*.py)" and dropped the never-true parenthetical.

## Part B — Fleet consistency checklist (per W16)

Checklist applied per script:
1. `--help` output format and flag-naming consistency
2. Empty-result stderr messaging pattern
3. G-6 redaction usage (tenant GUIDs, cache/operator paths)
4. No leftover TODO/FIXME comments or debug prints
5. Docstring accuracy against current behavior (schema version, privilege lines, etc.)

### Fleet-wide results

| Check | Result |
|---|---|
| TODO / FIXME / XXX / HACK / debug prints / `pdb` / `breakpoint()` | **None** across all 14 (clean) |
| Empty-result stderr notice (`No <noun> found/returned`, `file=sys.stderr`) | Present and consistent in **all 14** (one distinct per-tool noun each, e.g. "No users found", "No OAuth2 permission grants found") |
| G-6 redaction (`redact_tenant_id` / `_redact` on evidence `tenant_id`) | Present in **all 14**; `tool_list_sharepoint_sites` additionally scrubs the tenant GUID from `webUrl` substrings (the only tool emitting URLs that embed it) — matches W16 |
| Replay-log schema version stamped in docstrings | **v0.5 in all 14** — 22 occurrences of "v0.5 schema", **zero** v0.3/v0.4 drift (the W16 F1 drift did not recur; the morning pre-check confirmed) |
| Flag naming (`--run-id`, `--replay-log-dir`, `--row-cap`) | Consistent, present in **14/14**; argparse used in all 14 |
| `--run-id` optional (default=None) | **14/14** (W16 N2 stays resolved) |
| Default replay-log dir = `REPO_ROOT / "replay-logs"` | **14/14** (W16 N1 stays resolved) |
| `--emit / --no-emit` dry-run toggle | **14/14** (W16 N3 stays resolved) |

### Per-script review table

| # | Script | Issues found | Fixed | Flagged (not fixed) |
|---|---|---|---|---|
| 1 | tool_list_users.py | — | — | — |
| 2 | tool_list_groups.py | — | — | — |
| 3 | tool_list_applications.py | — | — | — |
| 4 | tool_list_ca_policies.py | — | — | — |
| 5 | tool_list_role_assignments.py | — | — | — |
| 6 | tool_list_service_principals.py | — | — | — |
| 7 | tool_dfi_health.py | — | — | — |
| 8 | tool_intune_devices.py | — | — | — |
| 9 | tool_purview_labels.py | — | — | — |
| 10 | tool_signin_logs.py | — | — | — |
| 11 | tool_list_oauth_grants.py | — | — | — |
| 12 | tool_list_security_alerts.py | — | — | — |
| 13 | tool_list_inbox_rules.py | — | — | — |
| 14 | tool_list_sharepoint_sites.py | — | — | — |

**All 14 scripts: zero issues.** This is a clean result — a valid, reportable outcome. Unlike W16
(which found schema-version drift in 5 tools and the N1/N2/N3 fleet inconsistencies, all since
resolved), the fleet is now fully consistent; nothing needed fixing.

### Notes (reviewed, no action — consistent with W16)

- **`--page-size` absent on Tools 13 (inbox_rules) and 14 (sharepoint_sites).** Legitimately
  different — `messageRules` and site-`search` surfaces are not paged the same way. Not an issue
  (same conclusion as W16).
- **`--select` present on 10/14.** Endpoint-specific: tools whose Graph surface does not expose a
  useful `$select` omit it. Informative variance, not drift.
- **`--help` em-dash rendering** can show `—` as `�` under the default Windows console codepage;
  clean under `PYTHONIOENCODING=utf-8`. Terminal display artifact, not a source issue (W16 note).

## Part C — Internal doc-link verification

- **17 internal links** across `README.md`, `SECURITY.md`, `CONTRIBUTING.md` — **0 broken.** Every
  relative link (including the three ADR links on the ROE/Guardrails lines and the
  CONTRIBUTING/SECURITY/Code-of-Conduct cross-links) resolves to a real file.
- **`docs/adr/0007-naming-rationale.md`** mentions of the old `0002-naming-rejewski.md` filename:
  **0 live markdown links**, 4 backticked historical mentions — all explanatory prose describing
  the retired reference (what PR #114 fixed), confirmed **not** live broken links.

## Summary

- Doc-hygiene items fixed: **2** (D1 attck-coverage.md stale S2/S3 planning language; D2 guardrails.md Sprint-1 framing + `tests/replay/` scope line) — documentation only.
- Tool scripts reviewed: **14 / 14** — **zero issues**, no fixes needed (schema-version consistency, redaction, empty-result messaging, flag naming, and the three former W16 findings all verified consistent).
- Internal doc links verified: **17 / 17 resolve**; ADR 0007 historical mentions confirmed non-broken.
- No functional/behavioral changes. No real functional bug surfaced by the fleet check.
- Test suite: **192 → 192** (docs-only, no behavior changed).
- Open-bugs status for the S6 W21 acceptance: **no open functional bugs**; all W16 findings remain resolved; the two doc-hygiene items are closed here.

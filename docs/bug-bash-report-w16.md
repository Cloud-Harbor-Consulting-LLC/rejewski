# Rejewski Bug Bash Report — Sprint 4 Close Week (W16)

- Date: 2026-08-25
- Scope: QA consistency pass across all 14 tool scripts (`scripts/tool_*.py`)
- Baseline HEAD: `b03341a` (PR #91)
- Test baseline: **151 passed** (recorded before any change)
- Test after fixes: **151 passed** (docstring-only fixes — no behavior change, no test delta)
- Bound: trivial issues fixed directly; everything else documented, not fixed.

## Checklist applied per script

1. `--help` output format and flag-naming consistency
2. Empty-result stderr messaging (Sprint 2 W8 pattern)
3. G-6 redaction usage (tenant GUIDs, cache/operator paths)
4. No leftover TODO/FIXME comments or debug prints
5. Docstring accuracy against current behavior (REQUIRED PRIVILEGE lines, schema version, etc.)

## Fleet-wide results

| Check | Result |
|---|---|
| TODO / FIXME / debug prints / breakpoints | **None** across all 14 (clean) |
| Empty-result stderr notice (`No <noun> found`, G-5 comment) | Present and consistent in **all 14** |
| G-6 tenant-id redaction (`redact_tenant_id` on evidence `tenant_id`) | Present in **all 14**; Tool 14 additionally scrubs the tenant GUID from `webUrl` substrings (the only tool emitting URLs that embed it) |
| REQUIRED PRIVILEGE docstring section | Present in **all 14** (heading wording varies by scope-vs-role need — cosmetic, acceptable) |
| Replay-log schema version stamped at runtime | Single source: `replay_log.SCHEMA_VERSION = "0.5"`, `schemas/replay-log/v0.5.json`; all 14 emit v0.5 via shared `write_entry()` |

## Per-script review table

| # | Script | Tool | Issues found | Fixed | Flagged (not fixed) |
|---|---|---|---|---|---|
| 1 | tool_list_users.py | 1 | — | — | N3 (no `--emit/--no-emit`) |
| 2 | tool_list_groups.py | 2 | Stale schema ver (v0.3) in docstring | ✅ → v0.5 | N3 |
| 3 | tool_list_applications.py | 3 | Stale schema ver (v0.3) | ✅ → v0.5 | N3 |
| 4 | tool_list_ca_policies.py | 4 | Stale schema ver (v0.3, ×2) | ✅ → v0.5 | N3 |
| 5 | tool_list_role_assignments.py | 5 | Stale `$expand` behavior desc + stale schema ver (v0.3, ×2) | ✅ both | N3 |
| 6 | tool_list_service_principals.py | 6 | Stale schema ver (v0.4, ×2) | ✅ → v0.5 | N3 |
| 7 | tool_dfi_health.py | 7 | — | — | — |
| 8 | tool_intune_devices.py | 8 | — | — | — |
| 9 | tool_purview_labels.py | 9 | — | — | — |
| 10 | tool_signin_logs.py | 10 | — | — | — |
| 11 | tool_list_oauth_grants.py | 11 | — | — | N3 (no `--emit/--no-emit`) |
| 12 | tool_list_security_alerts.py | 12 | — | — | — |
| 13 | tool_list_inbox_rules.py | 13 | — | — | — |
| 14 | tool_list_sharepoint_sites.py | 14 | — | — | N1 (`logs/` default dir), N2 (`--run-id` required) |

## Issues fixed (trivial — docstring accuracy only, no behavior change)

**F1 — Stale replay-log schema version in 5 docstrings.**
Tools 2, 3, 4, 5 documented "v0.3 schema" and Tool 6 documented "v0.4 schema", but
the schema bumped to v0.5 and every tool stamps `schema_version` from the single
`replay_log.SCHEMA_VERSION = "0.5"` at runtime. The docstrings were snapshots left
behind by the schema bumps. Updated all occurrences to v0.5 (groups ×1, applications
×1, ca_policies ×2, role_assignments ×2, service_principals ×2). Service_principals
even said "the schema version is set from replay_log.SCHEMA_VERSION" one line after
hardcoding "v0.4", confirming the drift.

**F2 — Stale `$expand` behavior description in Tool 5 (role_assignments).**
The module docstring claimed the tool "uses `$expand=principal,roleDefinition` … in a
single paginated call." That is the pre-B030 behavior. Graph v1.0 rejects expanding
both properties in one query (HTTP 400); the B030 fix (PR #71) replaced it with a
two-call merge (`$expand=principal` then `$expand=roleDefinition`, merged by
assignment id), and the `--expand` flag is now accepted-but-ignored. The test suite
(`tests/test_tool_list_role_assignments.py`) explicitly covers this fix, confirming the
docstring — not the code — was wrong. Rewrote the docstring to describe the two-call
merge accurately.

*Both fixes are documentation-only. No code path, no CLI behavior, and no test changed;
the suite stays at 151.*

## Issues flagged — NOT fixed (behavioral / feature changes; need sign-off)

**N1 — Tool 14 (sharepoint_sites) writes replay logs to a different default directory.**
`DEFAULT_REPLAY_LOG_DIR = REPO_ROOT / "logs"` in Tool 14, versus `REPO_ROOT / "replay-logs"`
in all other 13 tools. Impact: a canonical run of Tool 14 lands its replay-log entries in
`logs/` while the rest of the fleet writes to `replay-logs/`, so anyone collecting evidence
from the conventional directory would miss Tool 14's entries.
*Not a G-6/leak risk* — both `logs/` and `replay-logs/` are in `.gitignore` (lines 87 and 65),
so nothing is committed either way. **Why not fixed:** changing the default output directory
changes what the script does (where files are written). Recommend aligning Tool 14 to
`replay-logs/` in a follow-up, pending confirmation that `logs/` was not intentional.

> **RESOLVED (signed off, follow-up PR):** Tool 14's default changed to `replay-logs/`,
> matching the fleet.

**N2 — Tool 14 (sharepoint_sites) requires `--run-id`; the other 13 make it optional.**
Tool 14 declares `--run-id ... required=True`; all other tools use `default=None` (optional).
Impact: an inconsistent CLI contract — Tool 14 aborts with an argparse error if `--run-id` is
omitted, whereas every other tool runs without it. **Why not fixed:** changing required/optional
status changes input validation behavior. Recommend a fleet decision on whether `--run-id`
should be mandatory everywhere (arguably more correct for evidence binding) or optional
everywhere, then align — rather than silently changing one tool.

> **RESOLVED (signed off, follow-up PR):** Tool 14's `--run-id` changed to optional
> (`default=None`), matching the fleet convention.

**N3 — `--emit / --no-emit` dry-run toggle is present on only 7 of 14 tools.**
Present: Tools 7, 8, 9, 10, 12, 13, 14. Absent: Tools 1–6 and 11. The flag (perform the Graph
read but skip the replay-log write, for a local dry run) was introduced at Tool 7 (Sprint 2 W7)
and never backported to the Sprint 1 tools (1–6); Tool 11 (oauth_grants, Sprint 3) also omitted
it. Impact: the earlier tools always write a replay-log entry with no dry-run escape hatch.
**Why not fixed:** adding `--emit/--no-emit` to 7 scripts adds a capability / changes behavior —
a feature, not a typo. Recommend backporting as a small dedicated task (7 scripts + tests) if the
dry-run affordance should be fleet-wide.

## Notes (reviewed, no action)

- **`--help` em-dash rendering.** Some help strings render `—` as `�` under the default Windows
  console codepage; clean under `PYTHONIOENCODING=utf-8`. Source uses proper em-dashes — a
  terminal display artifact, not a source issue.
- **`--page-size` help text varies by endpoint** ("Graph maximum for /users is 999", "for
  /servicePrincipals is 100", etc.). This is endpoint-specific and informative, not drift —
  left as-is.
- **`--page-size` absent on Tools 13 (inbox_rules) and 14 (sharepoint_sites).** Legitimately
  different: `messageRules` and site-`search` surfaces are not paged the same way. Not an issue.

## Summary

- Scripts reviewed: **14 / 14**
- Trivial fixes applied: **2** (F1 schema-version drift in 5 tools; F2 `$expand` docstring in Tool 5) — documentation only
- Behavioral/feature issues flagged for sign-off: **3** (N1 default log dir, N2 `--run-id` required, N3 `--emit` coverage)
  - **N1 and N2 subsequently signed off and fixed** in the follow-up Tool 14 alignment PR (suite → 153); **N3 remains open.**
- Test suite: **151 → 151** at bug-bash close (docstring-only, no behavior changed); **153** after the N1/N2 follow-up.

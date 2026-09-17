# Changelog

All notable changes to **Rejewski** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- **README v1 + ADR 0007 naming rationale (S5 W19).** New `docs/adr/0007-naming-rationale.md`
  (Status: Proposed) records the project's name origin and the Marian Rejewski heritage attribution
  in one durable, citable place, and states the trademark posture honestly (internal clearance
  research complete; formal outside-counsel opinion pending, Risk Register RK018 — no clearance is
  claimed). It cites the internal clearance memo as a reference, not a guarantee, and retires the
  dangling `0002-naming-rejewski.md` reference **without touching ADR 0002** (the separate
  ID/filename/branch naming-convention doc). `README.md` upgraded to v1: the **Naming** section now
  carries the verbatim 91-word attribution paragraph and links to ADR 0007 (not the nonexistent
  `0002-naming-rejewski.md`); the **Quickstart** section replaces its Sprint-6 deferral with real
  prerequisites / install / `.env` configure / run steps; the **Rules of Engagement** and
  **Guardrails** sections expand from pointer stubs into brief inline summaries. Two pre-existing
  doc bugs fixed along the way: the ROE section's broken `0001-roe-consent.md` link now points at
  `docs/roe-consent-flow.md` / `docs/adr/0001-rules-of-engagement.md`, and the guardrails list —
  previously a stale G1–G8 set that contradicted its own linked source — is reconciled to the
  actual **G-1…G-9** in `docs/guardrails.md`.

- **External authorization flow + ROE consent record v2 (S5 W18).** New `docs/external-auth.md`
  documents the third-party tenant-assessment scenario that `docs/roe-consent-flow.md` never
  covered: the authorization chain (signed engagement letter, recorded counterparty identity,
  enumerated scope surface, time-boxed window), scope-boundary enforcement (tenant lock, techniques
  ⊆ scope surface, authorization window — all deny-only), how it differs from the self-test flow,
  and a field-by-field mapping onto the SharePoint ROE Consent Archive workbook. It is explicit that
  **G-1 still locks all live execution to `cloudharbordemo`** — the doc is process/authorization
  only, not a guardrail change, and a real third-party run needs a superseding ADR. New
  `schemas/roe-consent/v1.json` freezes the committed 9-field replay-log-embedded consent shape
  (R010/R011 stay valid); `schemas/roe-consent/v2.json` is a strict superset adding the durable
  long-term-archive block (engagement / counterparty / scope / authorization / archive). New
  `scripts/write_consent_record.py` emits a v2 record (`build_consent_record`, plus `v1_core()` that
  extracts the embedded shape so the replay-log write path is unchanged and additive). Self-test
  records carry an explicit self-test marker, never blank. Samples: `samples/roe-consent/selftest-example.json`
  and `…/thirdparty-example.json` (fictional counterparty, illustrative). Tests in
  `tests/test_roe_consent_schema.py` validate both scenarios, the v1→v2 superset separation, and the
  builder.

- **ROI / business-impact section in the HTML run report (S5 W18).**
  `scripts/generate_html_report.py` now computes a real ROI section in place of the old
  `ROI_PLACEHOLDER` scaffold: for each finding it looks the technique up in the §6
  findings-to-ROI bridge of `docs/phs-security-roi-model-v0.1.md` (the already-reviewed
  grounding source of truth, parsed at runtime so the doc stays the single source) and renders
  that technique's risk category and direction-of-risk verbatim. Every finding gets a line;
  a technique absent from the bridge renders an explicit "not yet in the ROI model" line
  rather than a fabricated one. No dollar figure is invented — the only figure that can appear
  is the established fraction-of-$728K framing (T1550.001) already in the reviewed table. The
  §6 bridge is extended with two later-evidenced techniques, **T1213.002** (evidenced R013)
  and **T1033** (evidenced R012), same style/rigor as the original nine (direction-of-risk,
  no dollar figure). `docs/reports/replay-report-R012.html` and `-R013.html` regenerated to
  reflect the real ROI section. Also refreshed the stale "successful evidence awaits a
  post-fix re-run" prose in the T1213.002 finding-to-control mapping to record that R013
  already evidenced it (status/observed_in were already correct).

### Changed

- **Reporting polish — HTML run report visual pass (S5 W19).** `scripts/generate_html_report.py`
  CSS/markup only (no change to what data renders): (1) **severity ramp** reworked to a distinct
  hue per level — gray → blue → amber → **orange** (`high`, was pink) → solid red (`critical`) — so
  `medium` and `high` are unambiguous at a glance and `high` no longer collides with the pink error
  badge (verified by rendering, not just hex); (2) **control reference links** relabeled from a bare
  "ref" to "**Microsoft Docs ↗**" (clear outbound affordance, `target=_blank rel=noopener`; hrefs
  unchanged) and the column header "Ref" → "Reference"; (3) **table styles** — rounded borders,
  clearer header shading, row hover, pill-shaped bolder badges, monospace `code` chips, explicit
  white `body` background so reports render cleanly regardless of the viewer's theme.
  `docs/reports/replay-report-R012.html` and `-R013.html` regenerated. No functional/data change.

- **Severity rubric → v1.0 (locked): CIS Controls v8 tie-in + defensive-evasion escalator adopted
  (S5 W18, PM decision).** `docs/finding-severity-rubric-v0.1.md` bumped v0.2 → v1.0 (filename slug
  kept at `-v0.1` for link stability): (a) added a **CIS Controls v8** framework cross-reference —
  one CIS anchor per severity level tied to the P/B/D dimensions, with stated reasoning for choosing
  CIS over Microsoft Secure Score (a rubric needs a stable reference; Secure Score is a per-tenant,
  fluctuating posture metric); (b) **adopted the defensive-evasion escalator** — a `D = 2` defender's-
  own-detection map (CA-policy posture, security-sensor health, sign-in/alert telemetry) now routes
  to **high** via new decision-table row 3; §2 high/medium tests, §3 D=2 anchor, §5.4, and §6 updated
  from "deferred" to "adopted". The escalator cascaded across every artifact that embedded these three
  severities, each with a dated footnote preserving the original medium assessment (T1580 precedent):
  - `samples/finding-triage/t1526-r011-ca-policy-discovery.json`, `…/t1526-r013-ca-policy-discovery-001.json`
  - `samples/finding-triage/t1518.001-r011-dfi-sensor-health.json`, `…/t1518-001-r013-dfi-sensor-health-001.json`
  - `samples/finding-triage/t1654-r011-signin-logs.json`, `…/t1654-r013-log-enumeration-001.json`
    (all six re-triaged `medium` → `high`, `triage_status` `open` → `reviewed`)
  - `samples/finding-to-control/t1526-rbac-reports-reader.json`, `t1518.001-rbac-security-reader.json`,
    `t1654-rbac-reports-reader.json` (severity → `high`, dated note in `rationale`)
  - `docs/findings-report-r011.md` (§2 summary rows + §3 detail blocks → `high`, shared `[‡]` footnote)
  - `docs/phs-security-roi-model-v0.1.md` (§6 bridge severity column → `high [‡]`, `[‡]` footnote, §9 row)
  - `docs/reports/replay-report-R013.html` regenerated (T1526/T1518.001/T1654 badges now `high`).
    R012 was regenerated too but is unchanged — neither of its findings (T1087.004, T1550.001) is in the
    escalated set. Scoped to exactly those three techniques; no other severity changed.

- **W17 PM decisions (R013 wrap) — docs-only.** (R2) `docs/roe-consent-flow.md` v0.1 → v0.2:
  added a prominent §1 operator-safety callout requiring `-TenantId` to be pinned on every admin /
  Graph-PowerShell action against the sandbox, after the R013-setup incident where WAM silently
  authenticated to a production tenant and grants/roles landed there. (R3) `docs/techniques/T1114.002.md`
  and `T1114.003.md` cross-user Evidence reworded from "successful evidence awaits … an ADR relaxing
  G-2/G-3" to a **permanent scope boundary** (self-mailbox only; cross-user needs a tenant app
  registration, out of scope under ADR 0001 §1 / G-2/G-3, PM-confirmed not planned) — no longer
  framed as pending/future work. (R1 periodic live-smoke run and R5 SharePoint admin-API surface are
  PM backlog items, no repo change; R4 `security.alert` `category` deprecation parked.)

- **Severity rubric → v0.2** (`docs/finding-severity-rubric-v0.1.md`, filename slug kept stable
  for link stability). Codifies the `D = 1` vs `D = 2` boundary with an explicit test and worked
  anchors — a Collection-steering data-classification taxonomy is now unambiguously `D = 2`
  (moving "classification taxonomy" out of the old `D = 1` cell), resolving the ambiguity that
  produced the T1580 case. The defensive-evasion escalator (T1526/T1518.001/T1654 → high) was
  evaluated and **deliberately not adopted** — deferred to a PM decision because it cascades into
  a multi-finding re-triage.

- **Reconciled T1580 severity to `medium` across the remaining downstream artifacts** (following
  the re-triage of the authoritative record). Updated `docs/findings-report-r011.md`,
  `docs/phs-security-roi-model-v0.1.md` (§6 bridge + §9 change log), and the
  `t1580-conditional-access-purview-require-compliant-app` finding-to-control mapping from `low`
  → `medium`, each with a dated footnote preserving the original point-in-time assessment. The
  rubric §5.2 downstream note updated to record the reconciliation.

- **Re-triaged `samples/finding-triage/t1580-r011-purview-labels` from `low` to `medium`**
  (triage_status `open` → `reviewed`), acting on the divergence flagged in
  `docs/finding-severity-rubric-v0.1.md` §5.2: the Purview label taxonomy is a
  Collection-targeting map (B=2 tenant-wide, D=2), not infra-only metadata. Rubric §5.2/§6
  and the worked-example table updated to reflect the resolution (agreement now 5/5).
  Note: `docs/findings-report-r011.md` and `docs/phs-security-roi-model-v0.1.md` still cite
  T1580 as `low` and are intentionally left as authored (dated point-in-time artifacts).

### Fixed

- **`tool_list_security_alerts` (T1654 Surface B) — second invalid `$select` field
  (`lastModifiedDateTime` → `lastUpdateDateTime`).** After the `alertType` removal, the clean
  R013 re-run returned a further HTTP 400: `lastModifiedDateTime` is not a property of
  `microsoft.graph.security.alert` either — the correct field is **`lastUpdateDateTime`**
  (confirmed against the authoritative Graph v1.0 `security-alert` resource docs; the whole
  `$select` was validated against the schema, so this is the complete fix). The date is only
  requested, not projected/aggregated. Strengthened the regression test to validate every
  `$select` field against the documented property set. (`category` is accepted but marked
  deprecated in favor of `categories`; left as-is since it still functions and changing it
  alters the `by_category` aggregation — noted for a future pass.)

- **`tool_list_sharepoint_sites` (T1213.002) — removed the non-existent `sharingCapability`
  field; re-scoped Tool 14 to site enumeration (W17 R013 finding).** `sharingCapability` is
  **not a property of `microsoft.graph.site`** in Graph v1.0, so `GET /sites?search=*` returned
  HTTP 400 BadRequest on the first real-tenant run (R013) — the tool had never worked against a
  live tenant (its tests fabricated the field). Dropped `sharingCapability` from `$select` and
  removed the external-sharing-risk classification (high/medium/low/none) and flagged-site
  gating. The tool now enumerates the site inventory (id, displayName, webUrl, description,
  timestamps); `--include-drives` / `--include-lists` apply to **every** enumerated site rather
  than "flagged" ones. Per-site external-sharing posture is only available via the SharePoint
  admin surface (Get-SPOSite), out of Graph scope — noted as a candidate future surface.
  Reconciled `docs/techniques/T1213.002.md`, the T1213.002 finding-to-control mapping rationale,
  and the test suite (dropped the classification tests; added a `SITES_SELECT` regression guard).
  Evidence for T1213.002 awaits a post-fix re-run.

- **`tool_list_inbox_rules` (T1114.002/003) — corrected scope docs and documented the
  cross-user block (W17 R013 finding).** The tool's docstring/`--help`/403-hint claimed
  `MailboxSettings.Read` and that a directory role enables cross-user reads; the R013 real-tenant
  run showed (a) the `mailFolders/messageRules` path is gated on **`Mail.Read`**, and (b) a
  **cross-user read returns HTTP 403 `ErrorAccessDenied` even with `Mail.Read` + Exchange
  Administrator** — delegated `Mail.*` only reaches the signed-in user's own mailbox. Corrected
  the tool text and reconciled `docs/techniques/T1114.002.md` / `T1114.003.md` (scope → Mail.Read;
  Evidence records the block). **T1114.002/003 remain evidence-blocked**: the only guardrail-
  compatible posture is self-mailbox, unavailable in the sandbox (operator identity has no
  mailbox); cross-user needs app-only permissions, out of scope per G-2/G-3. The finding-to-control
  mappings stay `draft` (no success evidence). Docs-only; no code-path change (tool already uses
  `.default`, inheriting whatever is consented).

- **`tool_list_security_alerts` (T1654 Surface B) — invalid `$select` field.** Removed
  `alertType` from `DEFAULT_SELECT`: it is not a property of `microsoft.graph.security.alert`,
  so `GET /security/alerts_v2` returned HTTP 400 BadRequest on the first real-tenant run (R013).
  The field was requested but never projected (dead). Added a regression test. Surfaced by the
  W17 end-to-end run — the mocked unit tests could not catch it because they fabricate the
  response schema.

- **`--emit/--no-emit` backported to the 7 tools that lacked it (W16 N3, signed off).**
  Closes the last of the three W16 bug-bash inconsistencies: the dry-run toggle
  (perform the Graph read, skip the replay-log write) is now on all 14 tools. Added to
  `tool_list_users`, `tool_list_groups`, `tool_list_applications`, `tool_list_ca_policies`,
  `tool_list_role_assignments`, `tool_list_service_principals`, and `tool_list_oauth_grants`,
  matching the existing tools exactly: `--emit` defaults on (G-5), `--no-emit` skips the
  `graph_call` entry and reports `replay_log_entry: null`; the token acquisition's
  `token_event` is unaffected, as in the rest of the fleet. Docstrings updated
  ("Every emitted invocation writes …"). New shared parametrized suite
  `tests/test_tool_emit_flag.py` (14 cases) covers `--no-emit` and default-emit for all
  seven — the first dedicated coverage for the five Sprint 1 core tools. Suite 153 → 167.

- **Tool 14 (sharepoint_sites) fleet alignment (W16 N1 + N2, signed off).**
  Resolves two of the three behavioral inconsistencies flagged in the W16 bug bash:
  - **N1:** default replay-log directory `logs/` → `replay-logs/`, matching the other
    13 tools, so canonical Tool 14 runs land evidence in the conventional directory.
  - **N2:** `--run-id` changed from `required=True` to optional (`default=None`),
    matching every other tool's CLI contract; a null run binding is propagated exactly
    as the fleet does.
  Two tests added (`TestFleetConventions`): default-dir assertion and a run without
  `--run-id`. Suite 151 → 153. (N3 — `--emit/--no-emit` coverage — remains open.)

- **Bug bash (Sprint 4 W16) — docstring-accuracy fixes across the 14 tool scripts.**
  Documentation-only; no CLI or Graph-call behavior changed, suite unchanged at 151.
  - Corrected the stale replay-log schema version in five tool docstrings that predated
    schema bumps: `tool_list_groups.py`, `tool_list_applications.py`,
    `tool_list_ca_policies.py`, `tool_list_role_assignments.py` (were "v0.3") and
    `tool_list_service_principals.py` (was "v0.4") → all now "v0.5", matching the
    runtime `replay_log.SCHEMA_VERSION`.
  - Rewrote the stale `$expand` description in `tool_list_role_assignments.py`: it
    described the pre-B030 single-call `$expand=principal,roleDefinition`; the tool now
    uses the two-call merge (B030 fix, PR #71) and accepts-but-ignores `--expand`.
  - Full review recorded in `docs/bug-bash-report-w16.md`, including three behavioral
    inconsistencies flagged for sign-off (not fixed): Tool 14's `logs/` default
    replay-log dir vs `replay-logs/` fleet-wide; Tool 14's required `--run-id` vs
    optional elsewhere; and `--emit/--no-emit` present on only 7 of 14 tools.

### Added

- **W17 R013 end-to-end evidence run (2026-09-03) — the canonical full-fleet sweep.**
  `samples/replay-log/R013.json` (Playbook full sweep, cloudharbordemo): 28 entries —
  14 `graph_call` (13 success + the documented `inbox_rules` cross-user block) + 14
  `token_event` (T1550.001 silent reuse); `cache_path` redacted per B023/G-6; sandbox tenant
  only. `docs/reports/replay-report-R013.html` — the run rendered by `generate_html_report.py`
  (now populating the Findings + Control-mappings sections). Nine `samples/finding-triage/*-r013-*`
  records for the observed techniques (T1087.004, T1069.003, T1526, T1518.001, T1082, T1580,
  T1654, T1213.002 medium; T1550.001 high), severities per `docs/finding-severity-rubric-v0.1.md`
  v0.2. **T1213.002 now genuinely evidenced** (first real Tool 14 success after the W17 re-scope) —
  its finding-to-control mapping promoted `draft → active` with `observed_in: [R013]`; **T1654
  Surface B** (`security_alerts`) evidenced for the first time after the `$select` fixes.
  `T1213.002.md` and `T1654.md` Evidence sections updated. T1114.002/003 remain the documented
  block (no success). Closes the W17 end-to-end.

- `scripts/generate_html_report.py` + `tests/test_generate_html_report.py` +
  `docs/reports/replay-report-R012.html` (generated sample) — HTML run-report template v1.
  Formalizes the hand-built one-off `docs/replay-report-r011.html` into a reusable,
  script-driven generator: reads a replay-log sample plus its finding-triage and
  finding-to-control records and renders a complete HTML report to `--output` (read-only,
  no Graph calls; CLI shape mirrors `finding_coverage_report.py`; output convention
  `docs/reports/replay-report-<run-id>.html`). Sections: header/meta, consent summary (when
  the run carries a consent record), graph-calls and token-events tables, findings summary
  with a per-finding severity badge (informational/low/medium/high/critical per
  `docs/finding-severity-rubric-v0.1.md` v0.2), and control mappings per finding. **The ROI
  section is an explicit placeholder ("ROI scoring — Sprint 5 Week 18") — not computed; ROI
  scoring is S5 W18 scope.** CSS is centralized in one stylesheet in the script (reusing the
  badge/table/`.consent` style of the historical report), which is never modified. G-6: the
  report reuses only already-scrubbed source fields — tenant shown truncated, operator object
  id from consent records not rendered. Tests (5): fixture render (incl. consent) asserting
  technique IDs / severity badges / control refs / ROI placeholder, the real R012 sample, the
  G-6 checks, and a guard that the historical report is never touched.

- `scripts/rotate_replay_logs.py` + `docs/replay-archive.md` + `tests/test_rotate_replay_logs.py`
  — replay-log rotation/compression and the archive policy. Compresses `replay-logs/` working-
  directory entries strictly older than 30 days (age from the entry's `<YYYYMMDDThhmmssZ>`
  filename prefix) into `replay-logs/archive/<YYYY-MM>/<name>.json.gz` (gzip, per-entry,
  lossless round-trip) and removes the uncompressed originals. `--dry-run` previews without
  moving anything. **Hard path guard** refuses to operate on `samples/replay-log/` (committed
  evidence) or any path containing/contained by it — an explicit `is_protected_path` check.
  Local-filesystem only (no Graph calls; G-1/G-3 N/A to its execution path); G-6 respected in
  output (basenames + repo-relative archive paths only). Tests (5) cover the age boundary, gzip
  validity/round-trip, dry-run no-op, and the guard. Master Plan S5 W17 acceptance.

- Finding-to-control mappings for the four previously-uncovered implemented techniques,
  taking control-mapping coverage **9/13 (69.2%) → 13/13 (100%)**:
  `samples/finding-to-control/t1033-rbac-pim-eligible-roles.json` (status `active`,
  observed in R012), `t1213.002-conditional_access-ca-spo-requirecompliantapp.json`,
  `t1114.002-rbac-exchange-administrator.json`, and
  `t1114.003-conditional_access-ca-exo-requirecompliantapp.json` (the last three status
  `draft` with empty `observed_in` — recommended controls for techniques whose tools have
  no committed run yet). `docs/finding-coverage-report.md` regenerated (history row appended:
  69.2% → 100%). Controls constrained to the schema's `conditional_access`/`rbac` families.

- `samples/finding-triage/t1087.004-r012-account-discovery.json` and
  `samples/finding-triage/t1550.001-r012-token-reuse.json` — triage records for the two R012
  checkpoint findings, severities set per `docs/finding-severity-rubric-v0.1.md` (T1087.004
  medium; T1550.001 high). `finding_dedup.py --run-id R012` classifies both as **recurring**.
  Technique-module evidence updated to cite R012: `docs/techniques/T1033.md` Surface B is now
  **evidenced** (the R011 role-assignments HTTP 400 was the B030 defect fixed in #71; R012 is
  the post-B030 successful run), plus R012 citations added to `docs/techniques/T1550.001.md`
  and `docs/techniques/T1087.004.md`.

- `samples/replay-log/R012.json` — Sprint 4 checkpoint demo consented run sample: threat
  actor playbook v1 Recipe R-01 (Privileged Account Discovery), run R012, cloudharbordemo
  sandbox (2026-08-29). JSON array: 3 token_event entries (T1550.001, silent cache reuse)
  + 3 graph_call entries (T1087.004 Account Discovery: Cloud Account — `tool_list_users`
  9 users, `tool_list_role_assignments` 14 assignments/2 pages, `tool_list_service_principals`
  419 principals/5 pages); `cache_path` redacted per B023/G-6; all outcomes success.

- `docs/finding-severity-rubric-v0.1.md` — severity scoring rubric. Documents objective
  tests for each of the five `severity` levels in `schemas/finding-triage/v0.1.json`
  (informational/low/medium/high/critical), three scored dimensions (privilege,
  blast radius, data value), a decision table combining them, and a confidence/evidence
  gate. Applied retroactively to five `samples/finding-triage/` records as worked
  examples; one genuine divergence flagged (T1580 assigned `low`, rubric scores `medium`).
  Docs-only; no schema, script, or test changes.

- `scripts/finding_dedup.py` — finding deduplication classifier. Reads all finding-triage
  records from `samples/finding-triage/`, groups by `technique_id`, and classifies each
  finding in the target run as `new_technique`, `recurring`, or `variant` relative to prior
  runs. Read-only; does not modify any finding records. CLI: --finding-dir / --run-id /
  --output. Output: JSON summary with per-finding classification and severity diffs.
- `scripts/finding_coverage_report.py` — control-mapping coverage report. Reads implemented
  techniques from docs/attck-coverage.md and finding-to-control records from
  samples/finding-to-control/; emits docs/finding-coverage-report.md with covered/gap
  tables and running coverage history. CLI: --attck-coverage / --mapping-dir / --output.
  Read-only; does not modify any finding or mapping records.
- `docs/finding-coverage-report.md` — generated coverage report (first run): 13 implemented
  techniques, 9 covered (69.2%), 4 gap (T1213.002, T1114.002, T1114.003, T1033).
- `tests/test_finding_dedup.py`: test suite for finding_dedup.py (8 cases). Covers
  new_technique / recurring / variant classification, severity-diff detection, prior-run-only
  tracking, missing run-id, empty directory, invalid JSON skip, and summary count
  correctness.
- `tests/test_finding_coverage_report.py`: test suite for finding_coverage_report.py
  (8 cases). Covers full coverage, gap detection, Implemented-only parsing, multi-mapping
  dedup, missing-dir error, missing-file error, history-row append, and version extraction.

- **ATT&CK Sprint 4 expansion** (docs-only, no new script) — three technique
  modules added to close the Sprint 4 ATT&CK-coverage KPI gap, taking the mapped
  count 17 → 20 (implemented/catalogued 11/6 → 13/7):
  - `docs/techniques/T1114.003.md` — Email Collection: Email Forwarding Rule
    (Collection, Implemented). The forwarding-rule view of the existing inbox-rule
    inventory (scripts/tool_list_inbox_rules.py, shared with T1114.002 Surface A);
    forwardTo/forwardAsAttachmentTo/redirectTo actions are the technique artifacts.
    Read-only — enumerates existing rules, does not create them. Evidence pending
    first sandbox run (Tool 13 shipped after R011).
  - `docs/techniques/T1033.md` — System Owner/User Discovery (Discovery,
    Implemented). Surface A operator identity resolution via scripts/identity.py
    (identity context) with the GET /me profile read in
    scripts/step4-token-smoke.py; Surface B tenant owner/admin identification via
    scripts/tool_list_role_assignments.py. Surface A evidenced in R011; Surface B
    evidence pending a post-B030 run (R011 role-assignments call returned HTTP 400).
  - `docs/techniques/T1528.md` — Steal Application Access Token (Credential Access,
    Catalogued) — first Credential Access tactic entry. Reconnaissance surface only
    (scripts/tool_list_oauth_grants.py + scripts/tool_list_service_principals.py);
    the token-theft action is prohibited by G-1/G-2 and not emulated.
  - `docs/attck-coverage.md` v0.7 → v0.8 and `docs/threat-model.md` v1.3 → v1.4
    updated for the three techniques (counts, tactic distribution, §5/§8, change logs).

- `docs/phs-security-roi-model-v0.1.md` — Pillar 2 business case model (B011).
  Applies the ROI baseline (docs/phs-security-roi-baseline-v0.1.md) to a
  representative 750-employee mid-market M365 E5 scenario. Covers: credential
  attack exposure ($728K expected credential breach cost), control effectiveness
  (99.2% MFA block rate), Rejewski positioning (residual 0.8% post-MFA attack
  surface), findings-to-ROI bridge table (R011 9 findings mapped to risk
  categories), and honest limitations. All figures source-cited with confidence
  bands; vendor bias disclosed inline. Sprint 4 W14 Pillar 2 build.

- **Tool 14** (`scripts/tool_list_sharepoint_sites.py`): T1213.002 Data from
  Information Repositories: SharePoint — Surface A (SharePoint site enumeration
  with external sharing policy read). Enumerates all SharePoint Online site
  collections accessible to the operator account via GET /sites?search=* (Graph
  v1.0). Scope: Sites.Read.All (delegated). No Entra directory role required.
  Projects per site: id, displayName, webUrl, sharingCapability (classified as
  high/medium/low/none sharing risk), createdDateTime, lastModifiedDateTime.
  High and medium sharing-risk sites optionally proceed to drives enumeration
  (GET /sites/{id}/drives: id, name, driveType, quota) and lists enumeration
  (GET /sites/{id}/lists: id, displayName, list.template, itemCount) when
  --include-drives / --include-lists flags are set. G-9 row cap default 1 000
  sites. webUrl tenant GUID redacted in evidence output. Promotes T1213.002
  from Catalogued to Implemented — Sprint 4 W14.
- `tests/test_tool_list_sharepoint_sites.py`: test suite for Tool 14 (12 cases).
  Covers happy path, sharingCapability classification (all 4 enum values), drive
  enumeration gating, row-cap truncation, empty site list, 429 retry, 401
  mid-pagination recovery, webUrl redaction, replay-log entry shape, include-drives/
  include-lists default-off, and Sites.Read.All 403 error path.
- `docs/techniques/T1213.002.md`: status Catalogued → Implemented (Surface A).
  Adds Surface A implementation note and script reference; procedure updated from
  pending to implemented; evidence section added.
- `docs/attck-coverage.md` v0.7: T1213.002 row Implemented (Surface A); script
  column updated; implemented/catalogued split 10/7 → 11/6.
- `docs/threat-model.md` v1.3: T1213.002 promoted to Implemented in §5 table
  and Sprint 2+ subsection.

- `tests/test_autonomy_boundary.py` — agent autonomy boundary suite (11 tests) verifying the G-1..G-9 guardrails hold when the layer is pushed toward write / persistence / lateral-movement actions. Write-operation refusal (structural + behavioural GET-only proof), prohibited-technique routing (T1053 / T1078.003 / T1136 / T1098 blocked by refusal-by-absence), and the G-1/G-3 sandbox tenant lock (write_entry rejects wrong/empty tenant and missing borrowed_client_id). **Two gaps found (both since CLOSED — see Fixed below):** (GAP-1) `RoutingConfig` is_hard/select_model are model-routing only and never refuse a prohibited technique_id — `load_config()` does no technique-allowlist check despite ADR 0001 §3; (GAP-2) `replay_log.write_entry()` does not validate `request.method`, so GET-only has no active write-verb guard — it holds structurally (no tool issues a write verb) and via the SDK config only.

- `docs/threat-actor-playbook-v1.md` — operator manual defining five canonical
  TTP-chain recipes (R-01 Privileged Account Discovery, R-02 OAuth Permission
  Sprawl, R-03 Security Posture Gap Assessment, R-04 Email Forwarding Risk
  Discovery, R-05 Device and Sign-In Correlation) run against cloudharbordemo.
  Each recipe carries a threat-actor goal, prerequisites, exact tool sequence with
  CLI flags, expected output indicators, ATT&CK techniques exercised, detection
  signals, and a per-recipe guardrail block (G-1/G-3/G-5/G-6). Docs-only; no
  script or test changes.

- **Tool 13** (`scripts/tool_list_inbox_rules.py`): T1114.002 Email Collection —
  Surface A (inbox message rules). Enumerates a mailbox's inbox rules via Graph
  GET /users/{id}/mailFolders/inbox/messageRules (v1.0), promoting T1114.002 from
  Catalogued to Implemented. Scope: MailboxSettings.Read (delegated). Role: none for
  self (`--user-id me`, default), Exchange Administrator or Global Reader for
  cross-user. Projects per rule: id, displayName, isEnabled, hasError, actions
  (forwardTo / forwardAsAttachmentTo / redirectTo / delete / moveToFolder) and
  conditions (senderContains / subjectContains / bodyContains) — forwarding targets
  retained as the high-signal indicator, no message body content read. G-9 row cap
  default 500. Sandbox tenant GUID redacted from the evidence stdout. G-1: GET only.
  CLI: --user-id / --row-cap / --output / --replay-log-dir / --run-id / --emit.
  See docs/techniques/T1114.002.md Surface A.
- `tests/test_tool_list_inbox_rules.py`: test suite for Tool 13 (11 cases). Covers
  happy path, empty mailbox, forwarding-rule and deletion-rule serialization, row-cap
  hit, 429 retry exhaustion, 401 mid-run recovery, tenant-GUID scrubbing, replay-log
  entry validity against schemas/replay-log/v0.5.json, and --user-id endpoint
  construction (me vs cross-user).
- `docs/techniques/T1114.002.md`: status Catalogued → Implemented (Surface A). Adds a
  Surface A — Inbox Message Rule Enumeration section (endpoint, scope, role, procedure,
  detection signals, guardrails); the originally-catalogued folder/message-metadata
  surface is retained as a deferred surface.
- `docs/attck-coverage.md` v0.6: T1114.002 row Catalogued → Implemented — Sprint 4
  (Surface A), script added; current count split updated 9/8 → 10/7 implemented/
  catalogued (total unchanged at 17).
- `docs/threat-model.md` v1.2: §5 T1114.002 promoted to Implemented — Surface A with
  the messageRules endpoint, scope, and role; deferred folder/message surface noted.
- `tests/test_tool_list_security_alerts.py::TestStatusEnum` — regression guard pinning
  the v1.0 `alertStatus` enum for /security/alerts_v2. Asserts the legacy
  `--status active` value is rejected by argparse (exit 2) and that `new`,
  `inProgress`, and `resolved` are accepted. Closes the coverage gap left by the
  PR #78 fix, which was verified inline but had no durable guard: a future edit
  re-adding `active` to `choices` would otherwise have passed CI silently.
  Exercises `parse_args()` directly, not `main()`, so no live Graph call is
  reachable. Suite 86 -> 88.
- **Tool 12** (`scripts/tool_list_security_alerts.py`): T1654 Log Enumeration — Surface B. Reads Defender XDR security alerts via GET /security/alerts_v2 (Graph v1.0). Scope: SecurityAlert.Read.All (delegated, admin consent). Minimum role: Security Reader. Aggregate metrics: total_alerts, by_severity, by_status, by_category. G-9 row cap applied.
- `tests/test_tool_list_security_alerts.py`: test suite for Tool 12. Covers single-page, multi-page, empty result, HTTP 403, row cap, and $filter construction.
- `docs/techniques/T1654.md`: restructured with explicit Surface A (Sign-In Logs) and Surface B (Security Alerts) sections. Surface B covers GET /security/alerts_v2.
- `docs/attck-coverage.md` v0.5: T1654 Scripts column updated to include scripts/tool_list_security_alerts.py.
- `docs/threat-model.md` v1.1: T1654 §5 entry updated to note Surface A and Surface B scripts.
- `docs/adr/0006-foci-client-allowlist.md`: ADR-0006 formalises the approved FOCI client allowlist (14d82eec only), selection criteria, and the process for future additions.
- `docs/replay-report-r011.html` — canonical human-readable HTML report for run
  R011, rendered from `samples/replay-log/R011.json` by
  `scripts/replay_log_viewer.py --format html` (v0.2). Self-contained (no
  external resources, no JavaScript); 21 entries (1 consent, 10 graph_call,
  10 token_event) with the one T1087.004 role-assignments error badge (the
  HTTP 400 fixed under B030). Derived view of already-committed sandbox data —
  no full tenant GUID or token material.
- `scripts/tool_list_oauth_grants.py` (Tool 11) — OAuth2 delegated permission
  grant inventory. Enumerates tenant-wide delegated permission grants via Graph
  GET /oauth2PermissionGrants (T1087.004 Account Discovery: Cloud Account,
  Surface E). Each grant reveals which client service principal (clientId) has
  been consented — admin-wide (consentType AllPrincipals) or per-user (Principal)
  — for which delegated scopes against which resource API (resourceId). Required
  delegated scope: Directory.Read.All. Privilege prerequisite: Directory Readers
  (minimum), Global Reader, or Application Administrator on the operator user;
  the API returns 403 without a qualifying role regardless of scope consent. No
  $expand on this endpoint (all fields inline). $select=id,clientId,resourceId,
  consentType,principalId,scope. $top=100 with @odata.nextLink pagination, G-9
  row cap (default 1000), 429/5xx Retry-After (max 3), 401 mid-pagination
  recovery. Computes aggregates into the evidence JSON: admin- vs user-consented
  grant counts, unique client/resource SP counts, and high-privilege grant count
  (grants whose scope string contains a high-privilege API permission, matched
  case-insensitively). Empty tenant (no grants) prints "No OAuth2 permission
  grants found" to stderr, writes row_count 0 graph_call entry, exits 0. CLI:
  --select/--page-size/--row-cap/--output/--replay-log-dir/--run-id. See
  docs/techniques/T1087.004.md Surface E.
- `tests/test_tool_list_oauth_grants.py` — pytest suite for Tool 11, mocking the
  Graph HTTP layer and token helper. Single-page success (assert endpoint URL,
  GET method, object_count in replay-log entry), empty-grants response
  (object_count 0, no error), multi-page @odata.nextLink pagination (all grants
  across both pages, object_count is total), and evidence-aggregate computation
  (admin/user consent split, unique client/resource SP counts, and the
  high-privilege scope flag with a case-insensitive match). Suite grows from 58
  to 62 tests.
- `docs/techniques/T1087.004.md` — Surface E section added (OAuth2 delegated
  permission grant enumeration, Tool 11); front-matter sprint field extended to
  include Sprint 3 W11; Limitations note added documenting that Surface E covers
  delegated grants (oauth2PermissionGrants) only and that application role
  assignments (appRoleAssignments on service principals) are a deferred surface.
- `docs/attck-coverage.md` — v0.3 → v0.4. T1087.004 Script(s) column updated to
  append scripts/tool_list_oauth_grants.py. Technique count unchanged at 17
  (Surface E is an additional surface of the existing T1087.004, not a new
  technique).
- `docs/threat-model.md` — v0.9 → v1.0. §5 adds a T1087.004 Surface E note
  (GET /oauth2PermissionGrants; Directory.Read.All scope; Directory Readers role;
  deferred appRoleAssignments application-permission surface). Change log v1.0
  entry prepended. Total mapped techniques unchanged at 17.
- `schemas/finding-triage/v0.1.json` — JSON Schema (draft 2020-12) for Rejewski
  finding triage records. Required fields: finding_id (kebab-case slug),
  technique_id (ATT&CK ID), technique_name, run_id, severity
  (informational/low/medium/high/critical), confidence (low/medium/high),
  evidence (array of replay-log paths), triage_status
  (open/reviewed/accepted/false_positive/deferred), triage_metadata (created_utc,
  author, schema_version const "0.1"). Optional fields: control_mapping_id
  (cross-reference to a finding-to-control mapping slug), notes.
  additionalProperties: false everywhere; draft 2020-12.
- `samples/finding-triage/t1087.004-r010-account-discovery.json` — first triage
  finding sample: T1087.004 Account Discovery: Cloud Account, run R010, severity
  medium, confidence high, control_mapping_id cross-referencing the existing
  CA-COV008-BlockByLocation finding-to-control mapping.
- `tests/test_finding_triage_schema.py` — pytest suite: validates all samples
  under samples/finding-triage/, asserts missing-required-field fails, asserts
  wrong-schema-version fails.
- `samples/finding-to-control/t1518.001-rbac-security-reader.json`,
  `samples/finding-to-control/t1082-rbac-intune-service-admin.json`,
  `samples/finding-to-control/t1580-conditional-access-purview-require-compliant-app.json`,
  `samples/finding-to-control/t1654-rbac-reports-reader.json` — four new
  finding-to-control mapping records for the implemented techniques that lacked
  control mappings. T1518.001 maps to Security Reader (RBAC, Identities pillar,
  NIST T3/T4). T1082 maps to Intune Service Administrator (RBAC, Endpoints
  pillar, NIST T3/T4). T1580 maps to CA-PUR-001-RequireCompliantApp
  (conditional_access, Data pillar, NIST T3/T4/T5). T1654 maps to Reports Reader
  (RBAC, Identities pillar, NIST T3/T4). All four validate against
  schemas/finding-to-control/v0.1.json. After this PR all 9 implemented
  techniques have at least one finding-to-control mapping.
- `docs/findings-report-r011.md` — Sprint 3 W10 findings report skeleton for run
  R011 (Sat Jul 18, 2026). Pre-filled with all 9 implemented techniques, their
  tools, endpoints, and control mappings. Object counts, severity, and
  per-finding triage records are TBD; populated in Part B (post-run brief).
- `samples/finding-triage/t1078.004-r011-valid-accounts.json` — finding-triage record for T1078.004 R011
- `samples/finding-triage/t1087.004-r011-account-discovery.json` — finding-triage record for T1087.004 R011
- `samples/finding-triage/t1069.003-r011-group-discovery.json` — finding-triage record for T1069.003 R011
- `samples/finding-triage/t1550.001-r011-token-reuse.json` — finding-triage record for T1550.001 R011
- `samples/finding-triage/t1526-r011-ca-policy-discovery.json` — finding-triage record for T1526 R011
- `samples/finding-triage/t1518.001-r011-dfi-sensor-health.json` — finding-triage record for T1518.001 R011
- `samples/finding-triage/t1082-r011-intune-devices.json` — finding-triage record for T1082 R011
- `samples/finding-triage/t1580-r011-purview-labels.json` — finding-triage record for T1580 R011
- `samples/finding-triage/t1654-r011-signin-logs.json` — finding-triage record for T1654 R011
- `samples/replay-log/R010.json` — Sprint 2 checkpoint demo formal consent run
  (cloudharbordemo sandbox, 2026-07-02). JSON array of 11 entries: five T1550.001
  token_event entries from scripts.identity (cache_path redacted per B023/G-6) +
  five graph_call entries: T1087.004 (tool_list_users; GET /users; 8 users, 1 page,
  outcome=success) + T1526 (tool_list_ca_policies;
  GET /identity/conditionalAccess/policies; 24 policies, 1 page, outcome=success) +
  T1518.001 (tool_dfi_health; GET /security/identities/sensors; 3 sensors, 1 page,
  outcome=success) + T1580 (tool_purview_labels;
  GET /security/dataSecurityAndGovernance/sensitivityLabels; 4 labels, 1 page,
  outcome=success) + T1654 (tool_signin_logs; GET /auditLogs/signIns; 10 sign-ins,
  1 page, outcome=success). Consent record (consent.granted) present as first entry;
  all five graph_call entries bound to run R010. Formal ROE consent run count: 5 → 6.
- `samples/replay-log/R009.json` — consented run sample R009 (cloudharbordemo sandbox, 2026-06-23). JSON array of 4 entries: two T1550.001 token_event entries from `scripts.identity` (silent reuse; `cache_path` redacted by `scripts/consolidate_run.py` per B023/G-6) + a T1580 graph_call entry (`tool_purview_labels`; GET /security/dataSecurityAndGovernance/sensitivityLabels; **4 sensitivity labels enumerated, 1 page, outcome=success**) + a T1654 graph_call entry (`tool_signin_logs`; GET /auditLogs/signIns; 53 sign-ins, 1 page, outcome=success). Tool 9 initially returned HTTP 403 InsufficientGraphPermissions because `SensitivityLabel.Read` was not admin-consented on the borrowed Microsoft Graph Command Line Tools client (14d82eec) in cloudharbordemo; granting that scope on the FOCI client + clearing the MSAL encrypted cache (so silent reuse no longer returned the pre-grant access token) was the one-time sandbox-admin action that unblocked the success run. The T1654 success run confirms meganb@cloudharbor-demo.com holds the Reports Reader (or higher) role the endpoint gates on.
- `scripts/tool_purview_labels.py` (Tool 9) — Purview sensitivity label inventory. Enumerates all sensitivity labels configured in the tenant via Graph GET /security/dataSecurityAndGovernance/sensitivityLabels (T1580 Cloud Infrastructure Discovery). Required delegated scope: SensitivityLabel.Read (no Entra directory role required — any authenticated member with the scope consented). Surfaces per label: id, name, description, priority, isEnabled, isEndpointProtectionEnabled, actionSource, applicableTo, sublabels; computes enabled/disabled counts, applicableTo breakdown (email/file/teamwork coverage), and actionSource distribution into the evidence JSON. $top=100 with defensive @odata.nextLink pagination, G-9 row cap, 429/5xx Retry-After (max 3), 401 mid-pagination recovery. Empty tenant (no labels configured) prints "No sensitivity labels found" to stderr, writes row_count 0 graph_call entry, exits 0. --emit/--no-emit (default emit). See docs/techniques/T1580.md.
- `scripts/tool_signin_logs.py` (Tool 10) — Entra ID sign-in log reader. Enumerates sign-in events via Graph GET /auditLogs/signIns (T1654 Log Enumeration). Required delegated scope: AuditLog.Read.All. Privilege prerequisite: the operator user must hold Reports Reader, Security Reader, or higher in cloudharbordemo — the API returns 403 without a qualifying role regardless of scope consent (see docs/techniques/T1654.md §Required privilege for operator setup). Mandatory date filter (default: last 7 days via --days argument) to prevent timeout on large tenants. Optional --event-type filter (interactiveUser / nonInteractiveUser / servicePrincipal / managedIdentity / all). $select projection to key identity, risk, app, and status fields. $top=100 with @odata.nextLink pagination, G-9 row cap (default 1000), 429/5xx Retry-After (max 3), 401 mid-pagination recovery. Computes aggregates: by signInEventType, by riskLevelAggregated, failed_count, unique_apps, unique_users. --emit/--no-emit (default emit). See docs/techniques/T1654.md.
- `docs/techniques/T1654.md` — T1654 Log Enumeration technique module per ADR 0003 format. New to the Rejewski technique catalogue; added directly as implemented (no prior catalogued stub). Documents the sign-in log surface, the AuditLog.Read.All + Reports/Security Reader privilege prerequisite, attack strategy for a post-foothold adversary enumerating authentication telemetry, detection signals (reflexive: a member-account reading audit logs is itself anomalous in MicrosoftGraphActivityLogs), and the 30-day retention boundary.
- `tests/test_tool_purview_labels.py`, `tests/test_tool_signin_logs.py` — pytest suites for Tools 9 and 10, mocking the Graph HTTP layer and token helper. Tool 9: successful single-page list (assert endpoint URL, GET method, object_count in replay-log entry) and empty-labels response (object_count 0, no error). Tool 10: successful single-page list with date filter (assert endpoint, $filter contains createdDateTime, object_count), empty sign-ins response (object_count 0, no error), and multi-page @odata.nextLink pagination (assert all sign-ins across both pages returned and object_count is total). Suite grows from 49 to 54 tests.
- Six new catalogued technique modules (documentation only — no scripts) per ADR 0003 format, status `catalogued`: `docs/techniques/T1580.md` (Cloud Infrastructure Discovery; GET /organization, /domains, /subscribedSkus), `docs/techniques/T1538.md` (Cloud Service Dashboard; programmatic Graph /admin/serviceAnnouncement + /reports surface — see re-scope note below), `docs/techniques/T1213.003.md` (Data from Information Repositories: Code Repositories; SharePoint-surfaced code content via GET /sites, /drives, /lists), `docs/techniques/T1530.md` (Data from Cloud Storage; GET /drives, OneDrive/group drive root children), `docs/techniques/T1619.md` (Cloud Storage Object Discovery; the discovery phase preceding T1530), and `docs/techniques/T1114.002.md` (Email Collection: Remote Email Collection; GET /users/{id}/mailFolders + /messages metadata projection, documenting both the delegated Mail.Read and application-scope Mail.ReadBasic.All/Mail.Read.All postures).
- `scripts/tool_dfi_health.py` (Tool 7) — DfI sensor health check. Enumerates the Microsoft Defender for Identity sensor fleet via Graph GET /security/identities/sensors (`microsoft.graph.security` namespace; T1518.001 Software Discovery: Security Software Discovery). Required delegated scope: SecurityIdentitiesSensors.Read.All (admin-consented on the borrowed Graph Command Line Tools client 14d82eec; a post-foothold, Security-Reader-class grant). Surfaces per sensor: id, displayName, sensorType, version, deploymentStatus, healthStatus, openHealthIssuesCount, domainName, serviceStatus, createdDateTime; computes coverage-gap aggregates (healthy vs not-healthy, total open issues, per-status breakdowns) into the evidence JSON only (kept out of the replay-log response, which the v0.5 schema locks to status_code/page_count/row_count). $top=100 with defensive @odata.nextLink pagination, standard G-9 row cap, 429/5xx Retry-After loop (max 3), 401 mid-pagination cache-backed recovery. An empty fleet prints "No DfI sensors found" to stderr and still writes a graph_call entry with row_count (object_count) 0 — never an error. `--emit/--no-emit` (default emit, honoring G-5). See docs/techniques/T1518.001.md.
- `scripts/tool_intune_devices.py` (Tool 8) — Intune device inventory. Enumerates Intune-managed devices via Graph GET /deviceManagement/managedDevices (T1082 System Information Discovery). Required delegated scope: DeviceManagementManagedDevices.Read.All (admin-consented; Intune-admin-class grant). `$select` restricts the projection to id, deviceName, managedDeviceOwnerType, operatingSystem, osVersion, complianceState, managementState, lastSyncDateTime, enrolledDateTime, azureADDeviceId, userPrincipalName, userDisplayName, manufacturer, model, isEncrypted; computes compliant/encrypted counts and compliance/owner/OS breakdowns into the evidence JSON only. $top=100 with @odata.nextLink pagination followed until exhausted (the device inventory routinely spans multiple pages), standard G-9 row cap, 429/5xx Retry-After loop (max 3), 401 mid-pagination cache-backed recovery. An empty inventory prints "No managed devices found" to stderr and still writes a graph_call entry with row_count (object_count) 0 — never an error. `--emit/--no-emit` (default emit, honoring G-5). See docs/techniques/T1082.md.
- `tests/test_tool_dfi_health.py`, `tests/test_tool_intune_devices.py` — pytest suites for Tools 7 and 8, mocking the Graph HTTP layer (requests.get) and the token helper (identity.acquire_token) so the tools run offline. Tool 7: successful single-page list (asserts endpoint, GET method, and object_count in the replay-log entry) and empty-fleet (object_count 0, no error). Tool 8: successful single-page list, empty-inventory, and multi-page @odata.nextLink pagination (asserts all devices across both pages are returned and object_count is the total). Suite is now 49 tests (was 43).
- `samples/replay-log/R008.json` — consented run sample R008 (cloudharbordemo sandbox, 2026-06-16). JSON array: two T1550.001 token_event entries (cache_path redacted to "<redacted>" by scripts/consolidate_run.py, B023/G-6) + a T1518.001 graph_call entry (tool_dfi_health; GET /security/identities/sensors; 2 sensors, 1 page, success) + a T1082 graph_call entry (tool_intune_devices; GET /deviceManagement/managedDevices; 1 device, 1 page, success).
- docs/techniques/T1518.001.md and docs/techniques/T1082.md moved from catalogued to **implemented**: front-matter status updated, Procedure rewritten to reference the new scripts and their Graph endpoints, Detection updated to note MicrosoftGraphActivityLogs captures the respective GET calls, guardrails scoped to G-1/G-3/G-6/G-7, and the R008 evidence sample linked. Both docs note their originally-catalogued surfaces (GET /subscribedSkus for T1518.001; GET /organization for T1082) as deferred, complementary surfaces rather than discarding that prior cataloguing.
- docs/attck-coverage.md — T1518.001 and T1082 rows moved from catalogued to implemented with their script paths; current count updated from 7 implemented / 3 catalogued split (header now reads 7 implemented, 3 catalogued of 10 unique techniques). NOTE: the repo baseline before this change was 5 implemented / 5 catalogued (not the 6/4 some planning notes assumed), so the implemented tally moves 5→7 and catalogued 5→3.
- **B026** — `.gitattributes` at repo root with `* text=auto eol=lf`. Establishes an explicit line-ending policy so `core.autocrlf=true` on Windows clients can no longer produce spurious CRLF/LF diffs — the root cause of the PR #53 173-line `docs/threat-model.md` churn (text-mode Python writes flipped CRLF→LF; caught in self-review and reverted at byte level). As a one-time consequence of activating the policy, `docs/threat-model.md` (the sole tracked file still stored CRLF in the index) is renormalized to LF: a pure EOL change (173 lines, byte-identical to the prior content with CRs stripped — zero content change) that aligns the file with the new policy and removes the otherwise-permanent index/worktree EOL diff `eol=lf` would surface on every checkout.
- `schemas/replay-log/v0.5.json` — extends v0.4: adds optional `model_id` field recording which Claude model handled the reasoning-loop step that produced the entry (Sonnet/Opus routing). `schema_version` const updated to `"0.5"`. Optional and additive — entries written outside a model-routed reasoning loop omit it, so every v0.4 producer remains valid. All other v0.4 structure (optional `run_id`, kind-discriminated response shapes) is unchanged.
- `scripts/reasoning_loop.py` — Sonnet/Opus reasoning-loop driver. Walks a representative sandbox-tenant recon plan one step at a time; for each step it asks the committed routing config (`rejewski.config.json` → `rejewski.routing`, loaded via `scripts/rejewski_runtime.py`) which model should handle the step — Sonnet 4.6 for routine enumeration, Opus 4.6 for hard multi-hop analysis (privilege-graph correlation, alternate-auth token chaining, domain-trust analysis, finding-to-control mapping) — then writes one replay-log entry per step stamped with the chosen `model_id`. Runs OFFLINE: it routes and records, it does not make live Microsoft Graph calls (live recon is performed by the operator-run technique tools; wiring them to the agent loop needs a Graph MCP server, intentionally not configured). `--emit` writes routed entries to `replay-logs/` for inspection by `replay_log_viewer.py`; exits 1 if routing collapses to a single model.
- `tests/test_reasoning_loop.py` — pytest suite for routing + the reasoning loop: `RoutingConfig.select_model` defaults to Sonnet, escalates to Opus for registered hard step names / techniques, and honors an explicit `hard=` override; the committed config routes Sonnet-default / Opus-hard; `run_plan` over the sample plan produces a mix of both models; `--emit` writes schema-valid (v0.5) entries each carrying the routed `model_id`, the run ID, and the sandbox tenant lock.
- docs/techniques/T1082.md — System Information Discovery; catalogued Sprint 2; GET /organization surface; hybrid-status detection and provisioned plan enumeration.
- docs/techniques/T1213.002.md — Data from Information Repositories: Sharepoint; catalogued Sprint 2; GET /sites, /drives, /lists; requires Sites.Read.All scope.
- docs/techniques/T1482.md — Domain Trust Discovery; catalogued Sprint 2; GET /domains and /federationConfiguration; Managed vs Federated domain classification.
- `schemas/replay-log/v0.4.json` — extends v0.3: adds optional `run_id` binding field (propagates the consent.granted run ID into all downstream graph_call and token_event entries in the same run); `schema_version` const updated to `"0.4"`. Consent records themselves follow the separate roe-consent-flow.md §3 schema and are not validated by this schema.
- `samples/replay-log/R002.json` — Sprint 1 consented run sample: T1087.004 Account Discovery: Cloud Account (tool_list_users), run R002, cloudharbordemo sandbox (2026-05-27). JSON array: consent.granted record + graph_call entry; 8 users enumerated, 1 page, outcome success.
- `samples/replay-log/R003.json` — Sprint 1 consented run sample: T1069.003 Permission Groups Discovery: Cloud Groups (tool_list_groups), run R003, cloudharbordemo sandbox (2026-05-27). JSON array: consent.granted record + graph_call entry; 19 groups enumerated, 1 page, outcome success.
- `samples/replay-log/R004.json` — Sprint 1 consented run sample: T1087.004 Account Discovery: Cloud Account Surface B (tool_list_applications), run R004, cloudharbordemo sandbox (2026-05-27). JSON array: consent.granted record + graph_call entry; 6 applications enumerated, 1 page, outcome success.
- `samples/replay-log/R005.json` — Sprint 1 consented run sample: T1526 Cloud Service Discovery (tool_list_ca_policies), run R005, cloudharbordemo sandbox (2026-05-27). JSON array: consent.granted record + graph_call entry; 20 CA policies enumerated, 1 page, outcome success.
- `samples/replay-log/R006.json` — consented run sample: T1087.004 Account Discovery: Cloud Account Surface D (tool_list_service_principals), run R006, cloudharbordemo sandbox (2026-05-27). JSON array: consent.granted record + graph_call entry; 279 service principals enumerated, 3 pages, outcome success.
- `samples/replay-log/R007.json` — Sprint 1 consented run sample: T1550.001 Use Alternate Authentication Material: Application Access Token + T1087.004 Account Discovery: Cloud Account, run R007, cloudharbordemo sandbox (2026-06-06). JSON array: consent.granted record + 2 token_event entries (T1550.001) + 1 graph_call entry (T1087.004); cache_path field redacted to "<redacted>" in both token_event entries before commit (G-6 compliance; root fix tracked as B023).
- `schemas/finding-to-control/v0.1.json` — JSON Schema (draft 2020-12) for hand-authored finding-to-control mapping records. Required fields: mapping_id (stable kebab-case slug), finding (technique_id, technique_name, observed_in, severity, rationale), control (control_family, control_id, control_type, microsoft_pillar, nist_800_207_tenets, reference_url), mapping_metadata (created_utc, author, schema_version const "0.1", status). additionalProperties: false everywhere; control_family enum: conditional_access | rbac.
- `samples/finding-to-control/t1078.004-conditional_access-ca-sig003-guests-requiremfa.json` — T1078.004 Valid Accounts: Cloud Accounts → CA-SIG003-Guests-RequireMFA (preventive, Identities pillar, NIST 800-207 T4 T6).
- `samples/finding-to-control/t1087.004-conditional_access-ca-cov008-blockbylocation.json` — T1087.004 Account Discovery: Cloud Account → CA-COV008-BlockByLocation (preventive, Identities pillar, NIST 800-207 T3 T4).
- `samples/finding-to-control/t1069.003-conditional_access-ca-sif001-signinfrequency-8h.json` — T1069.003 Permission Groups Discovery: Cloud Groups → CA-SIF001-SignInFrequency-8h (preventive, Identities pillar, NIST 800-207 T3 T4 T6).
- `samples/finding-to-control/t1550.001-rbac-directory-readers.json` — T1550.001 Use Alternate Authentication Material: Application Access Token → Directory Readers RBAC scope (preventive, Identities pillar, NIST 800-207 T4 T6).
- `samples/finding-to-control/t1526-rbac-reports-reader.json` — T1526 Cloud Service Discovery → Reports Reader RBAC scope (preventive, Identities pillar, NIST 800-207 T4 T6).
- `tests/test_finding_to_control_schema.py` — pytest test suite: loads v0.1.json, validates all 5 samples, asserts missing-required-field and wrong-schema-version payloads fail.
- `scripts/tool_list_service_principals.py` (Tool 6) — enumerates Entra ID service principals via Graph GET /servicePrincipals; maps to T1087.004 Account Discovery: Cloud Account Surface D (service principal layer). Required delegated scope: Application.Read.All (pre-consented on Graph PowerShell client 14d82eec); required directory role: Directory Readers for full tenant-wide visibility (under-privileged principals receive HTTP 200 with empty result — not a 403). $top=100 (Graph endpoint maximum; distinct from /users which accepts $top=999). SP-specific aggregate metrics: enabled/disabled count, servicePrincipalType breakdown (Application/ManagedIdentity/Legacy/SocialIdp), multi-tenant SP count, cross-tenant owner count, unique homepage count. Standard G-9 row cap (default 1000), 429/5xx Retry-After loop (max 3), 401 mid-pagination cache-backed recovery, v0.4 replay-log entry per run. See docs/techniques/T1087.004.md.
- `docs/attck-coverage.md` — standalone ATT&CK coverage reference doc. Maps 7 techniques (5 implemented, 2 catalogued) with a path-to-Sprint-2-target table, notes the T1550.001 module gap, and includes an excluded-technique table documenting techniques deliberately out of Rejewski scope.
- `docs/techniques/T1087.003.md` — T1087.003 Account Discovery: Email Account technique module per ADR 0003 format. Catalogued for Sprint 2; no script yet.
- `docs/techniques/T1518.001.md` — T1518.001 Software Discovery: Security Software Discovery technique module per ADR 0003 format. Catalogued for Sprint 2; carries a dual-attribution note re T1526 overlap; no script yet.
- **B024** — `docs/techniques/T1550.001.md` — T1550.001 Use Alternate Authentication Material: Application Access Token technique module per ADR 0003 format. Implemented Sprint 1; documents the borrowed Microsoft Graph Command Line Tools client (14d82eec), the scripts/identity.py encrypted-cache + silent-reuse mechanism (ADR 0005), guardrails (G-1, G-2, G-3, G-4, G-6, G-7, G-8), detection signals (MicrosoftGraphActivityLogs and the token_event replay-log kind), and the R007.json evidence sample. Closes the previously-noted T1550.001 module gap.
- `scripts/replay_log_viewer.py` (v0.1 prototype) — CLI that reads any Rejewski replay-log file (single JSON object or array) and prints each entry in compact human-readable form to stdout. Renders graph_call, token_event, and consent records, then a `--- N entries (X graph_call, Y token_event, Z consent) ---` summary. Accepts a path argument or `-` for stdin. Pure local file reader: no Graph calls, no network, no schema validation. Detects consent records by either the `event` key (roe-consent-flow.md §3 shape) or a `consent.`-prefixed `kind`. Exits 1 with a stderr message on missing file or JSON parse error.
- `scripts/consolidate_run.py` (B022 + B023) — CLI that reads **every** `.json` file in `replay-logs/` (single object or array), selects entries whose `run_id` matches `--run-id`, and writes them as a pretty-printed JSON array to `samples/replay-log/<run-id>.json` (overwriting if present). Replaces the Sprint 1 Checkpoint demo's `[-3:]` combine step, which silently dropped entries on any run larger than one tool (a 3-tool run produces 6 files). Consent records (detected by an `event` key rather than `kind`) are included when their `run_id` matches. Unconditionally redacts `cache_path` to `"<redacted>"` on every token_event before writing (G-6; no flag to disable), so no operator-local filesystem path can reach `samples/` through this tool. Exits 0 on success; exits 1 with a stderr message when `replay-logs/` is missing or no matching entry is found.
- `tests/test_consolidate_run.py` + `tests/fixtures/consolidate-run/` — pytest suite for the consolidator: a 6-file 3-tool run yields all 6 entries (not 3), token_event `cache_path` is `"<redacted>"` regardless of input value, entries from a different `run_id` are excluded, missing `replay-logs/` exits 1, and an unknown `run_id` exits 1. Fixtures are six minimal single-entry files (token_event + graph_call per tool) carrying real-looking operator paths to prove redaction.

### Fixed

- **Guardrail gaps closed (from the autonomy boundary suite).** (GAP-1, G-1/G-4) `scripts/rejewski_runtime.py` now defines `PROHIBITED_TECHNIQUES` + `is_prohibited_technique()` (permanent out-of-scope set: T1053, T1078.003, T1136, T1098 — parents also cover sub-techniques), and `load_config()` raises `ValueError` if the config references any of them, implementing ADR 0001 §3's "out-of-scope techniques are refused at config load." (GAP-2, G-1) `scripts/replay_log.py` `write_entry()` now raises `ValueError` when a `graph_call` entry's `request.method` is not GET, giving the read-only posture an active write-verb guard; `token_event` (the OAuth token-endpoint POST) is exempt. Both guards mutation-tested (each boundary test fails when its guard is neutered). One pre-existing scrubbing test that used a POST graph_call fixture was conformed to GET.

- **B029** (`scripts/identity.py`): `_emit_token_event()` now emits T1078.004 (Valid
  Accounts: Cloud Accounts) on FLOW_ROPC (interactive acquisition) and T1550.001
  (Application Access Token) on FLOW_SILENT (cache reuse). Previously emitted
  T1550.001 on both flows, so T1078.004 was never written to a replay log by any
  run — cold cache included.
- **B029 follow-up** (`scripts/identity.py`): `flow` is now assigned `FLOW_ROPC`
  *before* the `acquire_token_by_username_password` call rather than after the
  success check, so `flow` means "ROPC was attempted" rather than "ROPC
  succeeded". A **failed** sign-in — including the AADSTS50076 MFA-required
  outcome ADR-0004 §4 calls a desired Rejewski signal — is now correctly recorded
  as FLOW_ROPC / T1078.004 instead of FLOW_SILENT / T1550.001. The no-password
  cache-miss path returns before that assignment, so it stays FLOW_SILENT /
  T1550.001 (no sign-in was attempted); that boundary is pinned by a test. All
  four acquisition paths are now covered: silent success, ROPC success, ROPC
  failure, and cache-miss-without-password.
- fix(tool-12): replace legacy `--status 'active'` with v1.0 enum value `'new'` in
  `scripts/tool_list_security_alerts.py`. The v1.0 `alertStatus` enum for
  /security/alerts_v2 is `unknown | new | inProgress | resolved |
  unknownFutureValue`; `active` is a legacy /security/alerts (v1) value and would
  have returned zero rows or HTTP 400 on the v1.0 endpoint. `--status` choices and
  the `by_status` aggregate bucket are both corrected to `new`; the uncertainty
  note in the code is replaced with the confirmed enum. Flagged in the PR #76
  delivery report before the first sandbox run.
- **B030** — `scripts/tool_list_role_assignments.py` (Tool 5, T1087.004 Surface C)
  no longer fails with HTTP 400. Graph v1.0 rejects
  `$expand=principal,roleDefinition` ("Only one property can be expanded in a
  single query"), which had been failing silently on every run (caught by the
  try/except and recorded as `outcome: "error"` — surfaced in the R011 sweep).
  Fix: two sequential paginated GET calls — one `$expand=principal`, one
  `$expand=roleDefinition` — merged on assignment `id`. Both calls are read-only
  (G-1); `_compute_ra_summary()` is unaffected (both `principal` and
  `roleDefinition` are populated in the merged result). The `--expand` CLI arg is
  deprecated (kept for backward compatibility, no longer forwarded to the URL).
  Adds `tests/test_tool_list_role_assignments.py` (two-call merge, merged
  aggregates, empty-list).
- `docs/techniques/T1654.md` — Evidence section: R009 T1580 outcome corrected from "error 403" to "success, 4 sensitivity labels enumerated"
- docs(threat-model): §5 T1518.001 and T1082 status rows corrected from
  Catalogued to Implemented — Sprint 2 W6 (2026-06-16) in both summary and
  surface tables. T1550.001 Module column updated to
  docs/techniques/T1550.001.md. threat-model.md → v0.9.
- docs(attck-coverage): Sprint 2 checkpoint target date corrected from
  Sat 2026-07-04 to Thu 2026-07-02 in both the Overview target line and the
  Path-to-Sprint-2-target narrative.
- **B022** — replay-log run consolidation no longer drops entries. The Sprint 1 Checkpoint demo used a `[-3:]` slice to pick "the last 3" replay-log files; a run exercising N tools writes 2N files (token_event + graph_call per tool), so any multi-tool run lost data. `scripts/consolidate_run.py` reads all files in `replay-logs/` and filters by `run_id`. (No committed script contained the `[-3:]` slice — a repo-wide grep found zero matches — so the offending combine step lived only in the operator's ad-hoc demo shell; the consolidator supersedes it.)
- **B023** — operator-local Windows paths in token_event `cache_path` (G-6 violation) are now redacted automatically. `R007.json` was redacted by hand before commit; `scripts/consolidate_run.py` now replaces `cache_path` with `"<redacted>"` on every token_event unconditionally before writing to `samples/`, making the redaction automatic going forward.
- **B025** — `tests/test_identity.py` three stale failures fixed. `test_silent_reuse_hit` asserted the dropped top-level `technique_id` field; updated to read the current nested `technique.id` shape that `replay_log._shape_technique` writes. `test_linux_default` and `test_darwin_default` asserted forward-slash path substrings against `str(path)`, which fails when the suite runs on Windows; switched to `path.as_posix()` so the platform-branch assertions hold on any host. No tests skipped or mocked around; all 12 pass against the real code.

### Changed

- **Tenant-GUID redaction unified across all tool evidence.** Adds
  `replay_log.redact_tenant_id()`, a shared helper that replaces the sandbox
  tenant GUID with the REDACTED zero-GUID in a tool's evidence output (stdout /
  --output). Every tool now routes its evidence `tenant_id` through it — the 12
  numbered Graph tools (`tool_list_users`, `tool_list_groups`,
  `tool_list_applications`, `tool_list_ca_policies`, `tool_list_role_assignments`,
  `tool_list_service_principals`, `tool_dfi_health`, `tool_intune_devices`,
  `tool_purview_labels`, `tool_signin_logs`, `tool_list_oauth_grants`,
  `tool_list_security_alerts`), Tool 13 (`tool_list_inbox_rules`, refactored off
  its own inline redaction onto the shared helper), and the
  `demo_b007_device_compliance` demo. Previously only Tool 13 redacted; the rest
  emitted the raw sandbox GUID in evidence. The replay-log ENTRY still carries the
  real `tenant_id` — G-1 requires `write_entry` to validate it — so this changes
  only the human-facing evidence blob, not the audit record. `TestRedactTenantId`
  in tests/test_replay_log.py pins the helper. (Follow-up to the Tool 13 review;
  the sandbox GUID is already published across the ADRs, threat-model, and
  replay-log samples, so this is a consistency/hygiene change, not a leak fix.)

- docs(scripts): tidy stale ADR-0004 version pointers in six tool docstrings
  (`tool_dfi_health`, `tool_intune_devices`, `tool_list_service_principals`,
  `tool_list_users`, `tool_purview_labels`, `tool_signin_logs`). "per ADR 0004
  v0.2" → "per ADR 0004"; the ADR number is stable, the version pointer went
  stale when ADR-0004 reached v0.3. **`tool_list_service_principals` also still
  advertised the superseded fallback** ("with FOCI fallback per ADR 0004 v0.2")
  — it escaped the PR #77 sweep because that grep keyed on "Azure CLI"/"04b07795"
  and this phrasing named neither. Now reads "The FOCI client is fixed to
  14d82eec per ADR-0006 and guardrail G-3", matching the five updated in #77.
  Docstring text only — no logic, schema, or test changes.
- docs: reconcile ADR-0006 and ADR-0004 on FOCI client selection; add Supersedes
  field to ADR-0006; update 5 tool docstrings. ADR-0006 now records
  `Supersedes: ADR-0004 §4 (Azure CLI fallback provision)` and its
  FOCI-membership assertions are softened to governance-designation language
  (ADR-0004 §4 records 14d82eec as *not* a confirmed FOCI member; ADR-0006 no
  longer contradicts that). ADR-0004 carries supersession notes at §4, §5.2, and
  §7 — original mandate text retained, not rewritten. The 5 tool docstrings that
  advertised the Azure CLI (04b07795) FOCI fallback "per ADR 0004 v0.2"
  (`tool_list_applications`, `tool_list_ca_policies`, `tool_list_groups`,
  `tool_list_oauth_grants`, `tool_list_role_assignments`) now state the client is
  fixed to 14d82eec per ADR-0006 and G-3. No code logic, schema, or test changes.
- `scripts/replay_log_viewer.py` — v0.1 → v0.2. Adds a `--format {text,html}`
  flag; text (default, stdout) is unchanged. `--format html --output FILE`
  writes a self-contained HTML report (no external resources, no JavaScript,
  valid HTML5): run-metadata header, consent section (granted/declined
  left-border styling), a Graph-calls table (time, technique, tool, endpoint,
  rows, outcome), a token-events table (time, technique, outcome), and a summary
  footer. Outcome badges colour success/row_cap_hit green and error red.
  `--format html` without `--output` exits 1 with a clear error. Adds
  `tests/test_replay_log_viewer.py` (HTML metadata/badges/empty-consent, the
  unchanged text path, and CLI validation).
- `docs/findings-report-r011.md` — completed with R011 run data; status DRAFT → Complete
- `samples/finding-to-control/t1078.004-conditional_access-ca-sig003-guests-requiremfa.json` — R011.json appended to observed_in
- `samples/finding-to-control/t1087.004-conditional_access-ca-cov008-blockbylocation.json` — R011.json appended to observed_in
- `samples/finding-to-control/t1069.003-conditional_access-ca-sif001-signinfrequency-8h.json` — R011.json appended to observed_in
- `samples/finding-to-control/t1550.001-rbac-directory-readers.json` — R011.json appended to observed_in
- `samples/finding-to-control/t1526-rbac-reports-reader.json` — R011.json appended to observed_in
- `samples/finding-to-control/t1518.001-rbac-security-reader.json` — R011.json appended to observed_in; status draft → active
- `samples/finding-to-control/t1082-rbac-intune-service-admin.json` — R011.json appended to observed_in; status draft → active
- `samples/finding-to-control/t1580-conditional-access-purview-require-compliant-app.json` — R011.json appended to observed_in; status draft → active
- `samples/finding-to-control/t1654-rbac-reports-reader.json` — R011.json appended to observed_in; status draft → active
- chore(persona): system_prompt in rejewski.config.json updated to reflect
  10-tool scope, FOCI borrowed-client model (14d82eec, no tenant-side app
  registration), per-run ROE consent requirement, replay-log evidence capture,
  and full ATT&CK-mapped output requirement. The Sprint-1 "defensive
  reconnaissance agent" framing was corrected to "adversary-emulation … security
  reconnaissance agent" — Rejewski itself acts offensively (as a compromised
  account) inside an authorized defensive engagement; calling the agent
  "defensive" mislabelled its runtime behaviour. 117 words. Planner W7
  (Gu1lVDMYI0OQ7F4K7epjT2UAGbDv).
- chore(voice): voice audit of all 10 scripts/tool_*.py against the
  tool_purview_labels.py / tool_signin_logs.py reference pattern (stderr for
  status/error/empty notices, stdout for structured JSON). Findings and
  corrections:
  - (a) stderr/stdout routing — all 10 already conformed. No tool routes
    status/error text to stdout; error detail is carried in the JSON evidence
    `error_block`. No change.
  - (b) empty-result handling — Tools 7–10 already conformed. Added the missing
    `print("No <X> found", file=sys.stderr)` notice to Tools 1–6
    (tool_list_users "No users found", tool_list_groups "No groups found",
    tool_list_applications "No applications found", tool_list_ca_policies "No
    conditional access policies found", tool_list_role_assignments "No role
    assignments found", tool_list_service_principals "No service principals
    found"). All six already exited 0 on an empty-but-valid Graph response
    (outcome=success); only the stderr notice was absent. Exit codes and
    structured output unchanged.
  - (c) module docstrings — added the "No tenant-side app registration"
    paragraph to tool_list_users.py (the only script missing it; the other 9
    carry it). Added a REQUIRED PRIVILEGE section to Tools 1–3 (list_users,
    list_groups, list_applications) to match the section Tools 4–10 already
    carry, documenting the delegated scope and the no-elevated-role Sprint-1
    ordinary-user posture (threat-model.md §3). Tools 4–10 docstrings already
    conformed and were left unchanged.
  No new tests added: the stderr notice mirrors the already-tested Tools 7–10
  empty-result path and changes no exit code or structured output; suite stays
  54 green.
- `scripts/tool_signin_logs.py` — v1.0 compatibility fix. The `signInEventType` property is **beta-only**; querying it via `/v1.0/auditLogs/signIns` returns HTTP 400 ("Could not find a property named 'signInEventType' on type 'microsoft.graph.signIn'"), caught on the first live sandbox run (R009). Removed `signInEventType` from `DEFAULT_SELECT`, removed the `--event-type` CLI argument and its `signInEventType eq '<type>'` $filter clause, and replaced the `by_event_type` aggregate with `interactive_count` / `non_interactive_count` derived from the `isInteractive` boolean (which v1.0 does expose). Procedure and Limitations in `docs/techniques/T1654.md` updated to match. `tests/test_tool_signin_logs.py` re-asserted on the new aggregate shape; suite still 54 green.
- `docs/techniques/T1654.md` — Evidence section populated with the R009 success run (53 sign-ins, 1 page, outcome=success, meganb holds Reports Reader). Procedure step 3 dropped the `--event-type` description (see v1.0 compatibility fix above). Limitations note added documenting `signInEventType` as a beta-only field with a pointer to the future beta-endpoint module.
- `scripts/tool_purview_labels.py` — `_count_applicable_to` now splits the comma-delimited `applicableTo` string returned by the live Graph API ("email,teamwork,file") into per-scope counts. Caught on the first sandbox success run, where the pre-fix breakdown grouped by the whole comma-delimited combination (`{"email,teamwork,file": 3}`) instead of per-scope (`{"email": 4, "teamwork": 4, "file": 4, ...}`). Array-shape `applicableTo` (the OpenAPI alternative) is still accepted. Test fixture updated to use the real comma-string shape; new assertions cover the per-scope breakdown.
- `docs/techniques/T1580.md` — Evidence section populated with the R009 success run (4 sensitivity labels enumerated: Personal, Public, General, Confidential). Documents the operator workflow that unblocked the run (scope grant on FOCI client + MSAL cache clear to drop the pre-grant access token).
- `docs/techniques/T1580.md` — status catalogued → implemented. Procedure updated to describe the sensitivity labels surface (GET /security/dataSecurityAndGovernance/sensitivityLabels via tool_purview_labels.py). Original catalogued surfaces (GET /organization, GET /domains, GET /subscribedSkus) documented as deferred complementary surfaces in Limitations, following the T1082 precedent. Required privilege updated (SensitivityLabel.Read delegated, no role required). Evidence placeholder added for first sandbox run.
- `docs/attck-coverage.md` — v0.2 → v0.3. T1580 row: catalogued → implemented, script path added. T1654 row: new implemented row (Log Enumeration, Discovery, docs/techniques/T1654.md, scripts/tool_signin_logs.py). Current count 16 → 17 (9 implemented, 8 catalogued). Tactic distribution Discovery 10 → 11. Kill chain diagram and path-to-target table extended with 2026-06-23 row.
- `docs/threat-model.md` — v0.7 → v0.8. T1580 status updated to implemented. T1654 added to §5 technique table as implemented. Change log v0.8 entry prepended. §8 references updated. Total technique count 16 → 17.
- `docs/attck-coverage.md` — coverage map 10 → 16 (7 implemented / 9 catalogued); six new catalogued rows (T1580, T1538, T1213.003, T1530, T1619, T1114.002); tactic distribution updated (Discovery 7 → 10, Collection 1 → 4); kill-chain diagram and path-to-target table extended (new 2026-06-19 catalogue-expansion row marking the Sprint 2 target met and exceeded ahead of the 2026-07-04 checkpoint); doc version v0.1 → v0.2.
- `docs/threat-model.md` — v0.6 → v0.7. Six techniques added to the §5 active technique table and the Sprint 2+ catalogued subsection; total mapped techniques 10 → 16. §8 references extended with the six new module paths.
- **T1538 Cloud Service Dashboard re-scoped (excluded → catalogued).** T1538 was documented as explicitly out of programmatic Rejewski scope (GUI-based) in `docs/attck-coverage.md` (Excluded table) and `docs/threat-model.md` §5/§7. The exclusion is refined, not reversed wholesale: the *interactive GUI-navigation* posture stays out of scope (Rejewski drives no browser sessions), while the *programmatic* service-health/usage surface exposed through Graph `/admin/serviceAnnouncement` and `/reports` is now in scope and catalogued at `docs/techniques/T1538.md`. The attck-coverage Excluded table is emptied (now zero excluded-and-counted) with a re-scope note; threat-model §5 prose, the Sprint 2+ catalogued table, and the §7 out-of-scope entry are all updated to the GUI-only posture.
- `rejewski.config.json` — adds a `rejewski.routing` block committing the Sonnet/Opus reasoning-loop routing decision: `default_model` `"claude-sonnet-4-6"`, `hard_step_model` `"claude-opus-4-6"`, `hard_steps` (`finding_to_control`, `role_assignment_analysis`, `privilege_correlation`, `token_chaining`, `domain_trust_analysis`), and `hard_techniques` (`T1550.001`, `T1482`). Routing lives in config, not hardcoded inline; the SDK-bound top-level `model` (Sonnet 4.6) is unchanged.
- `scripts/rejewski_runtime.py` — adds a `RoutingConfig` dataclass (`default_model`, `hard_step_model`, `hard_steps`, `hard_techniques`) with `is_hard(...)` and `select_model(...)` (the latter accepting an explicit `hard=` override); `load_config()` parses `rejewski.routing` into `RejewskiConfig.routing` (defaulting to Sonnet-default / Opus-hard when the block is absent). `__main__` now prints the resolved routing.
- `scripts/replay_log.py` — `SCHEMA_VERSION` bumped `"0.4"→"0.5"`, `SCHEMA_PATH` updated to `v0.5.json`, optional `model_id: str | None = None` field added to `ReplayLogEntry` (stripped from the serialized payload when `None`, same pattern as `run_id`, to satisfy `additionalProperties: false`). Docstring updated with the v0.5 changelog.
- `tests/test_replay_log.py` — `SCHEMA_VERSION` and `TestRoundTrip` schema_version assertions updated `"0.4"→"0.5"`; new `TestModelId` covers `model_id` round-tripping when present and being omitted when `None`.
- `tests/fixtures/entries/*.json` (3) and every committed replay entry in `samples/replay-log/` (the three standalone `2026…Z-*.json` graph entries and the graph_call/token_event entries inside `R002`–`R007`) — `schema_version` bumped `"0.4"→"0.5"`. Consent records (no `schema_version`) are untouched; all pre-existing samples continue to validate against the v0.5 schema (`model_id` is optional; no other breaking changes).
- Borrowed-client name corrected repo-wide: app ID `14d82eec-204b-4c2f-b7e8-296a70dab67e` is "Microsoft Graph Command Line Tools", not "Microsoft Graph PowerShell" (a distinct app ID). Renamed every reference (38 occurrences across 18 files) to the correct name — 9 technique modules, `docs/guardrails.md` (G-4), ADRs 0001/0003/0005, `docs/threat-model.md`, `docs/phs-zt-scenarios-v0.1.md`, and the `step4-token-smoke.py`, `tool_list_ca_policies.py`, `tool_list_role_assignments.py` comments — to match `scripts/identity.py`, ADR 0004, and the actual Microsoft display name. The format-defining ADR 0003 example front matter is corrected so future modules inherit the right name. The app ID itself is unchanged everywhere (verified). Historical CHANGELOG entries below are left as-written (record of what shipped at the time).
- docs/threat-model.md — v0.5 → v0.6; three new techniques added to §5 table and Sprint 2+ catalogued subsection; technique count updated to 10.
- docs/attck-coverage.md — technique count updated to 10 (5 implemented, 5 catalogued); three new rows in technique table; tactic distribution and kill chain updated; path-to-S2 target marked complete.
- `scripts/identity.py`, `tool_list_users.py`, `tool_list_groups.py`, `tool_list_applications.py`, `tool_list_ca_policies.py`, `tool_list_role_assignments.py`, `tool_list_service_principals.py`: thread `run_id` through `identity.acquire_token()` → `_emit_token_event()` → `ReplayLogEntry` for token_event entries. Each tool's `token_getter` closure now passes `run_id=args.run_id`; eliminates unbound token_event side-effect files during canonical sample runs.
- `scripts/replay_log.py`: `SCHEMA_VERSION` bumped `"0.3"→"0.4"`, `SCHEMA_PATH` updated to `v0.4.json`, optional `run_id: str | None = None` field added to `ReplayLogEntry` dataclass (stripped from serialized payload when `None` to satisfy `additionalProperties: false`). Docstring updated to reflect v0.4 changelog.
- `scripts/tool_list_users.py`, `tool_list_groups.py`, `tool_list_applications.py`, `tool_list_ca_policies.py`, `tool_list_role_assignments.py`: add `--run-id` CLI argument (optional string, default `None`); passed as `run_id` to `ReplayLogEntry` to bind each run's replay-log entry to the consent-flow run ID.
- `tests/test_replay_log.py`: `SCHEMA_VERSION` assertion updated `"0.3"→"0.4"`; `test_committed_samples_validate` extended to handle JSON array sample files — consent records (detected by `event` key, no `schema_version`) are skipped, replay entries (graph_call/token_event) are validated against the v0.4 schema; `TestRoundTrip` schema_version assertion updated `"0.3"→"0.4"`.
- `tests/fixtures/entries/minimal-success.json`, `error-outcome.json`, `success-with-response.json`: `schema_version` bumped `"0.3"→"0.4"`.
- `samples/replay-log/20260515T143015Z-a1b2c3d4-*.json`, `20260515T143112Z-b2c3d4e5-*.json`, `20260515T221433Z-d2359cc0-*.json`: `schema_version` bumped `"0.3"→"0.4"`. All 3 pre-existing samples continue to validate against the v0.4 schema (run_id is optional; no other breaking changes).
- `docs/threat-model.md` v0.4 → v0.5 — Status column added to the §5 technique table; T1550.001, T1087.003, and T1518.001 rows added; Sprint 2+ catalogued subsection updated; §8 references extended with ADR 0005 and attck-coverage.md.

- `scripts/tool_list_role_assignments.py` (Tool 5) — enumerates Entra ID directory role assignments via Graph GET /roleManagement/directory/roleAssignments with $expand=principal,roleDefinition; maps to T1087.004 Account Discovery: Cloud Account (Surface C — privilege layer). Requires RoleManagement.Read.Directory scope and Directory Readers role (minimum for full visibility; Security Reader gives partial visibility). Evidence JSON includes role-specific aggregate metrics: Global Administrator count, high-privilege role count, external principal count, tenant-wide scope count, unique principal count, unique role count. G-9 row cap, 429/5xx retry, 401 mid-pagination recovery, v0.3 replay-log entry per run.
- `docs/techniques/T1087.004.md` updated to document Surface B (Tool 3 / GET /applications) and Surface C (Tool 5 / GET /roleManagement/directory/roleAssignments) as additional exercised surfaces alongside the original Surface A (Tool 1 / GET /users). Limitations section updated to remove stale service-principal note and document Security Reader partial-visibility caveat.
- `docs/techniques/T1087.004.md` updated to document Surface D (Tool 6 / GET /servicePrincipals — service principal layer) alongside Surfaces A–C. Adds Surface D procedure steps, SP-specific detection signals (MicrosoftGraphActivityLogs, Microsoft Defender for Cloud Apps), and removes the stale "service principals deferred to Tool 6" Limitations note. YAML front matter sprint field updated to reflect Sprint 2 W5 pull-forward activation of Surface D.
- `scripts/tool_list_ca_policies.py` (Tool 4) — enumerates Entra ID Conditional Access policies via Graph GET /identity/conditionalAccess/policies; maps to T1526 Cloud Service Discovery; G-9 row cap (default 1 000), 429/5xx Retry-After retry loop (max 3), 401 mid-pagination cache-backed recovery, v0.3 replay-log entry per run. Evidence JSON includes CA-specific aggregate metrics: enabled/disabled/report-only policy counts, MFA, block, and compliant-device policy counts. Requires Policy.Read.All scope (pre-consented on Graph PowerShell client 14d82eec) and Security Reader or higher directory role on the signed-in user. Docstring documents the privilege prerequisite and operator attack-strategy guidance for simulations where the test account does not already hold the required role.
- `docs/techniques/T1526.md` — T1526 Cloud Service Discovery technique module per ADR 0003 format. Documents the CA policies emulation procedure, required privilege (Security Reader minimum), attack strategy context for privilege escalation to that role, detection signals, guardrails (G-1, G-3, G-5, G-6, G-7, G-9), and limitations (named locations, auth strength policies, and application-level service principal enumeration deferred).
- `docs/threat-model.md` v0.4 (2026-05-26) — T1526 activated via Sprint 2 W5 pull-forward. §5 section heading and intro updated to reflect multi-sprint active technique table; T1526 added as fourth active technique; Sprint 2+ catalogued subsection updated with implementation status and CA policies surface; T1526 prose paragraph updated to describe the active emulation and catalogue remaining surfaces for Sprint 2 main body. §8 adds T1526.md cross-reference.
- docs/roe-consent-flow.md v0.1 baseline. Operationalizes ADR 0001 §2 with the per-run consent prompt shape (target tenant, techniques, expected duration, operator object ID, runtime-generated run ID), the verbatim run-ID echo confirmation mechanic, the `consent.granted` / `consent.declined` replay-log record schema, the run-ID binding between consent and all downstream replay-log entries, the Sprint 1 exit floor of 5 end-to-end consented runs, and refusal/abort behaviors. Headless flows, multi-operator handoffs, and mid-run revocation explicitly deferred.
- schemas/replay-log/v0.3.json: kind-discriminated response shapes via top-level allOf if/then. graph_call requires (status_code, page_count, row_count) with optional (row_cap, row_cap_hit, retry_count). token_event requires (status_code) with optional (aadsts_code, correlation_id, persistence_kind, cache_path, flow). Both branches enforce additionalProperties: false.
- First canonical replay-log samples emitted against cloudharbordemo sandbox tenant 76b87c33: one token_event entry from scripts/identity.acquire_token (T1550.001) and one graph_call entry from scripts/tool_list_users.py (T1087.004). Both pass jsonschema validation against v0.3.
- docs/phs-sprint-review-retrospective-baseline-v0.1.md. Locks the canonical §1 Retrospective subsection skeleton (What went well, What didn't, Lessons, Carryover), the grounding pull required before authoring (backlog workbook, Planner board, CHANGELOG, git log on main, SharePoint mirror, KPI Dashboard Weekly KPIs Build sheet), and pass and fail criteria for every Sprint Review retrospective entry across the 9-sprint program. Cadence locked to the final Saturday of each 4-week sprint cycle. (B003)
- samples/replay-log/20260519T140000Z-a7f8b3c2-1e4d-4567-89ab-cdef01234567.json. Canonical T1078.004 Valid Accounts Cloud replay-log sample from a clean step4-token-smoke run against the cloudharbordemo sandbox tenant (76b87c33) on Tue May 19, 2026. Actor Megan Bowen (<meganb@cloudharbor-demo.com>), borrowed Microsoft Graph PowerShell client (14d82eec), GET /me returning the seed user's profile in 1 page with 0 retries. Demonstrates the v0.1 schema for an identity-validation technique (no row enumeration, no row_cap semantics).
- samples/replay-log/20260519T140030Z-b8e9c4d3-2f5e-4678-90bc-def012345678.json. Canonical T1069.003 Permission Groups Discovery Cloud replay-log sample from a tool_list_groups run against the cloudharbordemo sandbox tenant on Tue May 19, 2026. Same actor and borrowed client; GET /me/memberOf with $select=id,displayName,groupTypes,securityEnabled,mailEnabled and $top=999 returning 3 Microsoft 365 Unified groups (All Company, Marketing, Retail) in 1 page with 0 retries, row_cap 1000, row_cap_hit false. ConsistencyLevel:eventual header recorded in the scrubbed request envelope.
- docs/dependency-license-audit.md (v0.1). SPDX identifier and MIT-inbound verdict for every direct and transitive dependency (jsonschema and pytest plus 7 transitive packages). Establishes the version-pin policy (loose lower + major cap, no lockfile at v0.1), attribution guardrail for any future redistribution scenario, 6-tier classifier-ambiguity fallback, and evidence-emission shape. Forward-compatible to CycloneDX 1.6+ and SPDX 2.3.
- scripts/audit_licenses.py. Reproducible offline license collector. Invokes pip-licenses, post-processes raw license strings to SPDX via the in-script mapping table, emits per-package JSON evidence to evidence/<date>/dependency-licenses.json, regenerates the Section 4 Markdown table, and fails loud on UNKNOWN licenses, non-permissive licenses, or transitive-set drift from the grounding baseline. Implements B008.
- B007 Pillar 1 Zero Trust device compliance demo: scripts/demo_b007_device_compliance.py (MSAL ROPC against borrowed Graph CLI client, expects AADSTS53000) and docs/demos/b007-device-compliance.md (prereqs, run, expected SigninLogs row, KQL hunt, pass/fail criteria). Validates ZT-S01 against ATT&CK T1078.004 with MITRE M1036 as the defensive control under test.
- ADR-0004 Identity Token Acquisition — Borrowed First-Party Client (ROPC + FOCI Fallback). Locks the no-tenant-app-registration posture, borrowed-client model (Graph Command Line Tools 14d82eec default, Azure CLI 04b07795 FOCI fallback), ROPC default with device-code fallback, and the per-module borrowed_client_id declaration requirement. Cross-references ADR-0001 §1/§3/§7, ADR-0003, guardrails G-1 and G-9, threat-model.md v0.2 §3, zt-scenarios ZT-S02, and security-roi-baseline Q5. (B005)
- docs/adr/_template.md reusable ADR skeleton with optional §4 Identity-Decision Factors block (token type, client ID source, grant flow, scope shape, consent path, MFA posture, dwell-signal expectations). (B005)
- docs/phs-security-roi-baseline-v0.1.md — Pillar 2 (Security ROI and Business Case) baseline assumption table. 27 grounded data points across breach cost, dwell time, identity-driven incident share, SOC operational load, MFA effectiveness, Zero Trust deployment delta, AI/automation savings, and Forrester TEI ROI. Confidence bands and vendor-bias flags surfaced inline. Mandiant 11-day dwell vs IBM 194-day MTTI reconciled as different populations — that delta is the Rejewski business case. 9 known gaps documented honestly. Backlog B004.
- Zero Trust baseline scenarios at docs/phs-zt-scenarios-v0.1.md — Pillar 1 anchor defining ZT-S01 Device Compliance, ZT-S02 Identity Verification, and ZT-S03 Network Segmentation; each scenario carries NIST 800-207 tenet mapping, Microsoft pillar mapping, ATT&CK technique, defensive control surface, expected alert pattern with cite-able signals, KQL hunt query, and pass/fail criteria for replay. (B002)
- Canonical T1087.004 replay-log entry at samples/replay-log/20260515T221433Z-d2359cc0-f634-4be1-84af-1533d47216dc.json. Captures a clean Tool 1 success run against the cloudharbordemo sandbox tenant (76b87c33) on Fri May 15, 2026. Actor Megan Bowen (<meganb@cloudharbor-demo.com>), borrowed Microsoft Graph PowerShell client (14d82eec), 6 users enumerated in 1 page with 0 retries, row_cap 1000, row_cap_hit false. Demonstrates the v0.1 schema end-to-end: nested technique block, scrubbed request headers (Authorization stripped by allow-list, User-Agent + Content-Type retained), response audit metadata only (no row contents), outcome=success.
- Three good-entries fixtures under tests/fixtures/entries/ (minimal-success, success-with-response, error-outcome) covering the positive validation surface for the replay-log schema.
- TestSchemaFidelity.test_good_fixtures_validate to exercise the new fixtures against the v0.1 schema.
- Tenant-GUID redaction in RFC 9457 error block string fields (type, detail, instance) in scripts/replay_log.py. Closes pre-mortem failure mode #1 from the replay-log writer design report.
- tests/fixtures/entries/ with 3 valid sample entries (minimal-success, success-with-response, error-outcome) for positive schema validation.
- tests/test_replay_log.py::TestScrubbing::test_tenant_guid_redacted_in_error_message.
- pytest test surface for the replay-log writer middleware. Four test classes: schema fidelity (validates committed samples + asserts bad fixtures fail), round-trip (write → read → re-validate → JSON-equal), refusal (overwrite + missing borrowed_client_id + wrong tenant + unknown outcome + unknown kind), scrubbing (Authorization header allow-list + access_token deny-list + nested credentials + tenant-GUID redaction in RFC 9457 error block).
- tests/fixtures/bad-entries/ with three negative-validation fixtures: missing-tenant-id.json, invalid-outcome.json, wrong-schema-version.json.
- requirements-dev.txt pinning pytest>=8,<9.
- Guardrail G-9 — Enumeration row cap. Bounds discovery technique row counts at the configured per-endpoint default; promotes the row-cap rule already referenced in T1087.004 and T1069.003 Procedure sections to governed status.
- Sprint 1 technique modules — T1078.004 (Valid Accounts: Cloud Accounts), T1087.004 (Account Discovery: Cloud Account), and T1069.003 (Permission Groups Discovery: Cloud Groups) — under docs/techniques/. All three follow the ADR 0003 format and cite ADR 0001, threat-model.md, and the relevant guardrails.
- ADR 0003: Technique Module Format defines required front matter, section order, and cross-referencing rules for docs/techniques/<TID>.md modules. Locks the borrowed-client field to keep the no-tenant-app-reg posture explicit in every module.
- scripts/tool_list_users.py — Sprint 1 Tool 1, the first Rejewski threat-actor enumeration primitive (ATT&CK T1087.004 Account Discovery: Cloud Account). Acquires a delegated Microsoft Graph token via MSAL ROPC against the borrowed Microsoft Graph Command Line Tools client (14d82eec-204b-4c2f-b7e8-296a70dab67e — no tenant-side app registration in the target tenant per ADR 0001 §1 and guardrail G-3), then pages GET /users with $select + $top=999 until @odata.nextLink is empty or the G-9 enumeration row cap is hit. Handles 429/5xx with Retry-After backoff (max 3 retries), 401 mid-pagination via MSAL acquire_token_silent, explicit (connect=5, read=30) timeout, and a stable User-Agent for tenant-side log correlation. Emits JSON evidence (tool, technique, tenant, borrowed client, actor UPN, UTC timestamps, $select, page size, row cap, row count, row_cap_hit, users) to stdout by default or to a file via --output. Cites docs/techniques/T1087.004.md.
- Replay log schema v0.1 (schemas/replay-log/v0.1.json). JSON Schema 2020-12 definition for the execution metadata envelope written per tool invocation. Foundation for the Sprint 5 replay harness (B013). Captures schema_version, entry_id, tool, technique (ATT&CK ID + name), tenant_id, borrowed_client_id, actor_upn, started_at_utc / completed_at_utc, request envelope, response envelope (status_code, page_count, row_count, row_cap, row_cap_hit, retry_count), outcome classifier, and optional error block.
- Replay log writer middleware at scripts/replay_log.py — Draft 2020-12 schema validation (cached validator, FormatChecker), two-layer secret scrubbing (allow-list request headers, deny-list response keys, tenant-GUID URL redaction), atomic file writes (tempfile → fsync → os.replace → directory fsync), refuse-overwrite append-only enforcement, RFC 9457 Problem Details helper, G-1 tenant scope lock, no-tenant-app-reg posture (borrowed_client_id required). Sourced patterns from python.org docs, RFC 9457/9562/3339, OWASP Logging Cheat Sheet, OWASP ASVS v5 §16.3, and NIST SP 800-92 Rev 1 IPD.
- Thin wrapper at scripts/run_with_replay_log.py — runs a Rejewski tool as a subprocess, captures stdout/stderr and return code, writes a replay-log entry without modifying the wrapped tool.
- First end-to-end replay-log samples at samples/replay-log/ — T1087.004 success-path entry and RFC 9457 error-path entry against the cloudharbordemo sandbox.

### Changed

- docs/threat-model.md bumped to v0.3 with Sprint 1 W3 catalogue expansion. §5 adds a Sprint 2+ catalogued techniques subsection covering T1526 Cloud Service Discovery (candidate Graph surfaces /subscribedSkus, /servicePrincipals, /applications, /organization documented for Sprint 2+ modelling) and T1538 Cloud Service Dashboard (catalogued as out of programmatic Rejewski scope; preserved for consumer awareness). §7 adds T1538 to the out-of-scope list.
- `scripts/tool_list_groups.py` now reads its borrowed-client default from `identity.DEFAULT_CLIENT_ID` instead of a duplicated literal, declares a module-level `GRAPH_SCOPE` constant, and passes `scopes=GRAPH_SCOPE` explicitly to `identity.acquire_token` via its `token_getter` closure. Brings the Tool 2 consumer to interface parity with Tool 1 (`scripts/tool_list_users.py`) and lets future scope narrowing happen at the call site. Docstring corrected from `v0.2 schema` to `v0.3 schema` to match the replay-log writer's current `SCHEMA_VERSION = 0.3`.
- `scripts/tool_list_applications.py` (Tool 3) brought to interface parity with Tool 1 and Tool 2: adds module-level `GRAPH_SCOPE` constant, passes `scopes=GRAPH_SCOPE` to `identity.acquire_token()` in `token_getter`, defers borrowed-client default to `identity.DEFAULT_CLIENT_ID` (was a duplicated literal), corrects docstring schema reference from v0.2 to v0.3.
- scripts/replay_log.py: SCHEMA_VERSION bumped to 0.3, SCHEMA_PATH points at v0.3.json, _shape_response is now kind-aware and validates required/optional keys per the graph_call vs token_event split. Closes the schema/code mismatch surfaced on Wed May 20, 2026 (response envelope missing required key: page_count for token_event entries).
- scripts/identity.py: _emit_token_event response payload now includes the flow field on the response side as well (graph_call branch unaffected). No change to acquisition logic.
- scripts/run_with_replay_log.py: stderr capture for failed subprocesses bumped from 500-char head to 4000-char tail so the actionable last line of Python tracebacks survives. Twice this session the head-truncated message hid the root cause.
- scripts/tool_list_users.py wires the replay-log writer. Every invocation emits a single replay-log entry (success or error) via replay_log.write_entry. Defaults to replay-logs/ (gitignored). Pass --replay-log-dir samples/replay-log to produce a canonical entry. Error paths now capture an RFC 9457 problem-details block in the entry's error field. The legacy evidence JSON on stdout/--output adds an outcome field and a replay_log_entry path pointer.
- docs(adr): correct ADR 0001 §1 sandbox tenant ID from cf3f9a61-644f-4d47-a11c-a6600a9bc717 (Planner host) to 76b87c33-6178-4ff9-94a7-164792c8e4c6 (cloudharbordemo)
- docs(guardrails): correct G-1 Sandbox Tenant Lock statement, enforcement, and rationale to reference cloudharbordemo (76b87c33) instead of the Planner host tenant (cf3f9a61)
- docs/threat-model.md: bump v0.1 → v0.2 with four bundled corrections — §1 tenant ID corrected to 76b87c33 (was cf3f9a61), §3 adversary-model section expanded with the no-tenant-app-reg posture and first-party client borrowing note, §5 extended with the T1069.003 deferred surface (/me/transitiveMemberOf and /directoryRoles as Sprint 2+ uplift), ADR 0003 added to the cross-references.
- docs/guardrails.md: replaced G-1 to G-8 stubs with full prose (Statement / Rationale / Enforcement / Scope / Exceptions per guardrail). Added the guardrail-to-technique appendix mapping each rule to the Sprint 1 technique modules.

### Fixed

- scripts/replay_log.py: request.headers now passes through an explicit allow-list (User-Agent, Content-Type, Accept, ConsistencyLevel, Prefer, Client-Request-Id; case-insensitive match) before _scrub runs. Authorization and any other non-listed header are dropped key-and-value, not just value-redacted. Closes tests/test_replay_log.py::TestScrubbing::test_authorization_header_scrubbed which asserted the literal string "Authorization" must not appear in the serialized payload, surfaced Wed May 20, 2026. Restores the two-layer scrubbing design intent stated in the writer docstring (allow-list for headers, deny-list for response keys).
- scripts/replay_log.py: writer now reshapes technique into the v0.3 nested {id, name} object before schema validation. The ReplayLogEntry dataclass keeps flat technique_id/technique_name fields for caller ergonomics; asdict() output is transformed via a new _shape_technique helper between response shaping and _scrub. Closes the additionalProperties violation surfaced by tests/test_replay_log.py::TestRoundTrip on Wed May 20, 2026 (technique_id, technique_name were unexpected at the top level under v0.3).
- scripts/replay_log.py — guard the post-replace directory fsync behind sys.platform != "win32" so the writer runs cleanly on Windows. NTFS's metadata journal already orders the directory entry after the atomic os.replace; the explicit dir-fsync was POSIX-only durability belt-and-suspenders that raised PermissionError [Errno 13] on Windows because NTFS does not expose directories as file descriptors. Behavior on Linux/macOS is unchanged.

### Pinned

- jsonschema>=4.26,<5 (replay-log writer validation).

### Removed

- samples/replay-log/20260519T140000Z-a7f8b3c2-1e4d-4567-89ab-cdef01234567.json: stale 2026-05-19 v0.1-shape mock, retired in favor of the Wed May 20, 2026 canonical sample generated by the new middleware.
- samples/replay-log/20260519T140030Z-b8e9c4d3-2f5e-4678-90bc-def012345678.json: stale 2026-05-19 v0.1-shape mock, retired alongside the file above.

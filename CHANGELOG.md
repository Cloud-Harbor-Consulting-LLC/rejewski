# Changelog

All notable changes to **Rejewski** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Changed

- docs(adr): correct ADR 0001 §1 sandbox tenant ID from cf3f9a61-644f-4d47-a11c-a6600a9bc717 (Planner host) to 76b87c33-6178-4ff9-94a7-164792c8e4c6 (cloudharbordemo)
- docs(guardrails): correct G-1 Sandbox Tenant Lock statement, enforcement, and rationale to reference cloudharbordemo (76b87c33) instead of the Planner host tenant (cf3f9a61)
- docs/threat-model.md: bump v0.1 → v0.2 with four bundled corrections — §1 tenant ID corrected to 76b87c33 (was cf3f9a61), §3 adversary-model section expanded with the no-tenant-app-reg posture and first-party client borrowing note, §5 extended with the T1069.003 deferred surface (/me/transitiveMemberOf and /directoryRoles as Sprint 2+ uplift), ADR 0003 added to the cross-references.
- docs/guardrails.md: replaced G-1 to G-8 stubs with full prose (Statement / Rationale / Enforcement / Scope / Exceptions per guardrail). Added the guardrail-to-technique appendix mapping each rule to the Sprint 1 technique modules.

### Added

- Guardrail G-9 — Enumeration row cap. Bounds discovery technique row counts at the configured per-endpoint default; promotes the row-cap rule already referenced in T1087.004 and T1069.003 Procedure sections to governed status.
- Sprint 1 technique modules — T1078.004 (Valid Accounts: Cloud Accounts), T1087.004 (Account Discovery: Cloud Account), and T1069.003 (Permission Groups Discovery: Cloud Groups) — under docs/techniques/. All three follow the ADR 0003 format and cite ADR 0001, threat-model.md, and the relevant guardrails.
- ADR 0003: Technique Module Format defines required front matter, section order, and cross-referencing rules for docs/techniques/<TID>.md modules. Locks the borrowed-client field to keep the no-tenant-app-reg posture explicit in every module.
- scripts/tool_list_users.py — Sprint 1 Tool 1, the first Rejewski threat-actor enumeration primitive (ATT&CK T1087.004 Account Discovery: Cloud Account). Acquires a delegated Microsoft Graph token via MSAL ROPC against the borrowed Microsoft Graph Command Line Tools client (14d82eec-204b-4c2f-b7e8-296a70dab67e — no tenant-side app registration in the target tenant per ADR 0001 §1 and guardrail G-3), then pages GET /users with $select + $top=999 until @odata.nextLink is empty or the G-9 enumeration row cap is hit. Handles 429/5xx with Retry-After backoff (max 3 retries), 401 mid-pagination via MSAL acquire_token_silent, explicit (connect=5, read=30) timeout, and a stable User-Agent for tenant-side log correlation. Emits JSON evidence (tool, technique, tenant, borrowed client, actor UPN, UTC timestamps, $select, page size, row cap, row count, row_cap_hit, users) to stdout by default or to a file via --output. Cites docs/techniques/T1087.004.md.
- Replay log schema v0.1 (schemas/replay-log/v0.1.json). JSON Schema 2020-12 definition for the execution metadata envelope written per tool invocation. Foundation for the Sprint 5 replay harness (B013). Captures schema_version, entry_id, tool, technique (ATT&CK ID + name), tenant_id, borrowed_client_id, actor_upn, started_at_utc / completed_at_utc, request envelope, response envelope (status_code, page_count, row_count, row_cap, row_cap_hit, retry_count), outcome classifier, and optional error block.
- Replay log writer middleware at scripts/replay_log.py — Draft 2020-12 schema validation (cached validator, FormatChecker), two-layer secret scrubbing (allow-list request headers, deny-list response keys, tenant-GUID URL redaction), atomic file writes (tempfile → fsync → os.replace → directory fsync), refuse-overwrite append-only enforcement, RFC 9457 Problem Details helper, G-1 tenant scope lock, no-tenant-app-reg posture (borrowed_client_id required). Sourced patterns from python.org docs, RFC 9457/9562/3339, OWASP Logging Cheat Sheet, OWASP ASVS v5 §16.3, and NIST SP 800-92 Rev 1 IPD.
- Thin wrapper at scripts/run_with_replay_log.py — runs a Rejewski tool as a subprocess, captures stdout/stderr and return code, writes a replay-log entry without modifying the wrapped tool.
- First end-to-end replay-log samples at samples/replay-log/ — T1087.004 success-path entry and RFC 9457 error-path entry against the cloudharbordemo sandbox.

### Pinned

- jsonschema>=4.26,<5 (replay-log writer validation).

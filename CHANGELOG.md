# Changelog

All notable changes to **Rejewski** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Fixed

- scripts/replay_log.py — schema alignment with schemas/replay-log/v0.1.json. Five defects corrected: (1) schema_version literal flipped from "0.1.0" to the schema's const "0.1"; (2) ReplayLogEntry.to_dict() now emits nested technique:{id,name} instead of flat technique_id/technique_name; (3) response envelope reshaped from {status, body, headers} to audit metadata {status_code, page_count, row_count, row_cap?, row_cap_hit?, retry_count?} — response bodies and headers no longer touch disk; (4) RFC 9457 problem_details helper replaced by a typed make_error helper returning {type, message, status_code?} to match the schema's simpler error block; (5) writer now refuses outcome values outside {success, error, throttled, row_cap_hit}.
- scripts/tool_list_users.py — adopts the new replay_log surface. Tracks page_count and retry_count via a stats dict threaded through graph_get and list_users. Reports outcome="row_cap_hit" when the G-9 row cap is reached. Builds response_obj as audit metadata only. Error path calls make_error with type/message/status_code.
- scripts/run_with_replay_log.py — adopts make_error for non-zero exit paths and emits audit-metadata response envelopes. Stdout JSON arrays are counted into row_count; bodies are no longer logged.
- tests/test_replay_log.py — _valid_entry helper rebuilt for the new shape. TestRoundTrip asserts nested technique, schema_version "0.1", and audit-metadata response. TestRefusal gains an unknown-outcome case. TestScrubbing splits into request-body credential scrubbing (positive scope) and response-body-dropped-entirely (defense-in-depth — verifies that even if a caller passes a body in response, it is removed before disk).
- samples/replay-log/ — both committed samples (T1087.004 success and error) regenerated against the v0.1 schema with nested technique, audit-metadata response, and typed error block.
- tests/fixtures/entries/ — three good fixtures (minimal-success, success-with-response, error-outcome) regenerated against the v0.1 schema. Failure modes in tests/fixtures/bad-entries/ (invalid-outcome, missing-tenant-id, wrong-schema-version) survive the rewrite; the three bad fixtures get cosmetic updates to the new envelope shape so the file format is consistent across the fixture surface.

### Changed

- scripts/tool_list_users.py wires the replay-log writer. Every invocation emits a single replay-log entry (success, error, throttled, or row_cap_hit) via replay_log.write_entry. Defaults to replay-logs/ (gitignored). Pass --replay-log-dir samples/replay-log to produce a canonical entry. Error paths capture a typed error block ({type, message, status_code?}) in the entry's error field. The legacy evidence JSON on stdout/--output adds an outcome field and a replay_log_entry path pointer.
- docs(adr): correct ADR 0001 §1 sandbox tenant ID from cf3f9a61-644f-4d47-a11c-a6600a9bc717 (Planner host) to 76b87c33-6178-4ff9-94a7-164792c8e4c6 (cloudharbordemo)
- docs(guardrails): correct G-1 Sandbox Tenant Lock statement, enforcement, and rationale to reference cloudharbordemo (76b87c33) instead of the Planner host tenant (cf3f9a61)
- docs/threat-model.md: bump v0.1 → v0.2 with four bundled corrections — §1 tenant ID corrected to 76b87c33 (was cf3f9a61), §3 adversary-model section expanded with the no-tenant-app-reg posture and first-party client borrowing note, §5 extended with the T1069.003 deferred surface (/me/transitiveMemberOf and /directoryRoles as Sprint 2+ uplift), ADR 0003 added to the cross-references.
- docs/guardrails.md: replaced G-1 to G-8 stubs with full prose (Statement / Rationale / Enforcement / Scope / Exceptions per guardrail). Added the guardrail-to-technique appendix mapping each rule to the Sprint 1 technique modules.

### Added

- Three good-entries fixtures under tests/fixtures/entries/ (minimal-success, success-with-response, error-outcome) covering the positive validation surface for the replay-log schema.
- TestSchemaFidelity.test_good_fixtures_validate to exercise the new fixtures against the v0.1 schema.
- Tenant-GUID redaction in typed error block string fields (type, message) in scripts/replay_log.py. Closes pre-mortem failure mode #1 from the replay-log writer design report.
- tests/fixtures/entries/ with 3 valid sample entries (minimal-success, success-with-response, error-outcome) for positive schema validation.
- tests/test_replay_log.py::TestScrubbing::test_tenant_guid_redacted_in_error_message.
- pytest test surface for the replay-log writer middleware. Five test classes: schema fidelity (validates committed samples + asserts bad fixtures fail), round-trip (write → read → re-validate → shape-asserted), refusal (overwrite + missing borrowed_client_id + wrong tenant + unknown outcome), scrubbing (Authorization header allow-list + request-body credential deny-list + response-body dropped entirely + tenant-GUID redacted in error message).
- tests/fixtures/bad-entries/ with three negative-validation fixtures: missing-tenant-id.json, invalid-outcome.json, wrong-schema-version.json.
- requirements-dev.txt pinning pytest>=8,<9.
- Guardrail G-9 — Enumeration row cap. Bounds discovery technique row counts at the configured per-endpoint default; promotes the row-cap rule already referenced in T1087.004 and T1069.003 Procedure sections to governed status.
- Sprint 1 technique modules — T1078.004 (Valid Accounts: Cloud Accounts), T1087.004 (Account Discovery: Cloud Account), and T1069.003 (Permission Groups Discovery: Cloud Groups) — under docs/techniques/. All three follow the ADR 0003 format and cite ADR 0001, threat-model.md, and the relevant guardrails.
- ADR 0003: Technique Module Format defines required front matter, section order, and cross-referencing rules for docs/techniques/<TID>.md modules. Locks the borrowed-client field to keep the no-tenant-app-reg posture explicit in every module.
- scripts/tool_list_users.py — Sprint 1 Tool 1, the first Rejewski threat-actor enumeration primitive (ATT&CK T1087.004 Account Discovery: Cloud Account). Acquires a delegated Microsoft Graph token via MSAL ROPC against the borrowed Microsoft Graph Command Line Tools client (14d82eec-204b-4c2f-b7e8-296a70dab67e — no tenant-side app registration in the target tenant per ADR 0001 §1 and guardrail G-3), then pages GET /users with $select + $top=999 until @odata.nextLink is empty or the G-9 enumeration row cap is hit. Handles 429/5xx with Retry-After backoff (max 3 retries), 401 mid-pagination via MSAL acquire_token_silent, explicit (connect=5, read=30) timeout, and a stable User-Agent for tenant-side log correlation. Emits JSON evidence (tool, technique, tenant, borrowed client, actor UPN, UTC timestamps, $select, page size, row cap, row count, row_cap_hit, page_count, retry_count, users) to stdout by default or to a file via --output. Cites docs/techniques/T1087.004.md.
- Replay log schema v0.1 (schemas/replay-log/v0.1.json). JSON Schema 2020-12 definition for the execution metadata envelope written per tool invocation. Foundation for the Sprint 5 replay harness (B013). Captures schema_version, entry_id, tool, technique (ATT&CK ID + name), tenant_id, borrowed_client_id, actor_upn, started_at_utc / completed_at_utc, request envelope, response envelope (status_code, page_count, row_count, row_cap, row_cap_hit, retry_count), outcome classifier, and optional error block.
- Replay log writer middleware at scripts/replay_log.py — Draft 2020-12 schema validation (cached validator, FormatChecker), two-layer secret scrubbing (allow-list request headers, deny-list request-body keys, tenant-GUID URL and error-string redaction), response envelope reshaped to audit metadata only (no response body or headers ever touch disk), atomic file writes (tempfile → fsync → os.replace → directory fsync), refuse-overwrite append-only enforcement, typed error block helper (make_error), G-1 tenant scope lock, outcome enum enforcement, no-tenant-app-reg posture (borrowed_client_id required). Sourced patterns from python.org docs, RFC 9562/3339, OWASP Logging Cheat Sheet, OWASP ASVS v5 §16.3, and NIST SP 800-92 Rev 1 IPD.
- Thin wrapper at scripts/run_with_replay_log.py — runs a Rejewski tool as a subprocess, captures stdout/stderr and return code, writes a replay-log entry without modifying the wrapped tool.
- First end-to-end replay-log samples at samples/replay-log/ — T1087.004 success-path entry and typed-error-path entry against the cloudharbordemo sandbox.

### Pinned

- jsonschema>=4.26,<5 (replay-log writer validation).

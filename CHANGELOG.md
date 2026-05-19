# Changelog

All notable changes to Rejewski are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- docs/adr/0005-token-persistence-and-reuse.md — ADR-0005 settles the persistence layer ADR-0004 left implicit. `PersistedTokenCache` over `build_encrypted_persistence`, `client_capabilities=["CP1"]`, `acquire_token_silent_with_error` exclusive, headless-Linux plaintext refusal via `REJEWSKI_ALLOW_PLAINTEXT_CACHE` opt-in, `token_event` replay-log emission on every acquisition.
- scripts/identity.py — shared MSAL + msal-extensions token acquisition helper (B021). Routes silent reuse through the encrypted cache; falls back to ROPC on cache miss; emits a `token_event` replay-log entry on every invocation. Cache path defaults to `~/.cache/rejewski/<actor-upn-slug>.bin` (Linux) with Windows / macOS equivalents; overridable via `REJEWSKI_CACHE_PATH`.
- tests/test_identity.py — coverage for cache path resolution per OS, silent-reuse cache hit, ROPC fallback on cache miss, ROPC AADSTS-error capture, plaintext-fallback refusal without opt-in, plaintext-kind propagation into the replay log.
- schemas/replay-log/v0.2.json — JSON Schema 2020-12 with the top-level `kind` discriminator (`graph_call` | `token_event`); `schema_version` const `"0.2"`.

### Changed

- scripts/tool_list_users.py — first consumer of scripts/identity. Drops inline `msal.PublicClientApplication` / `acquire_token_by_username_password` / `refresh_token_silently`; routes token acquisition through `identity.acquire_token(...)`. `graph_get` now accepts a `token_getter` callable so 401 recovery re-enters the encrypted cache rather than refreshing MSAL state inline. User-Agent bumped to `rejewski-tool-list-users/0.2`. Evidence shape and `borrowed_client_id` emission unchanged.
- docs/adr/0004-identity-token-acquisition-model.md — v0.2 amendment. Status / Date dual-stamped; §1 Context, §2 Decision, §4 Identity-Decision Factors, §5.3 Neutral, and §7 Compliance updated to cross-reference ADR-0005. Change Log row added. No reversal of v0.1 decisions.
- scripts/replay_log.py — schema target bumped to v0.2; `ReplayLogEntry` carries a `kind` field; `ALLOWED_KINDS = {"graph_call", "token_event"}`; `write_entry` validates `kind` against the allow-list before writing.
- scripts/run_with_replay_log.py — emits `kind=DEFAULT_KIND` (i.e., `graph_call`) on every wrapped invocation.
- tests/test_replay_log.py — schema-version assertions flipped to `"0.2"`; new `test_unknown_kind_refused` case; round-trip test asserts `kind == "graph_call"`.
- samples/replay-log/*.json — restamped to schema_version `0.2` with `kind: "graph_call"` injected on each pre-existing entry; GUIDs / timestamps preserved.

### Pinned

- msal-extensions>=1.1,<2 — required by scripts/identity.py for `PersistedTokenCache` + `build_encrypted_persistence` per ADR-0005 §2.

## [1.1.0] - 2026-05-16

(see prior entries)

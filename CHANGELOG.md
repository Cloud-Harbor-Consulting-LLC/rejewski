# Changelog

All notable changes to **Rejewski** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Changed

- docs/guardrails.md: replaced G-1 to G-8 stubs with full prose (Statement / Rationale / Enforcement / Scope / Exceptions per guardrail). Added the guardrail-to-technique appendix mapping each rule to the Sprint 1 technique modules.

### Added

- Guardrail G-9 — Enumeration row cap. Bounds discovery technique row counts at the configured per-endpoint default; promotes the row-cap rule already referenced in T1087.004 and T1069.003 Procedure sections to governed status.
- Sprint 1 technique modules — T1078.004 (Valid Accounts: Cloud Accounts), T1087.004 (Account Discovery: Cloud Account), and T1069.003 (Permission Groups Discovery: Cloud Groups) — under docs/techniques/. All three follow the ADR 0003 format and cite ADR 0001, threat-model.md, and the relevant guardrails.
- ADR 0003: Technique Module Format defines required front matter, section order, and cross-referencing rules for docs/techniques/<TID>.md modules. Locks the borrowed-client field to keep the no-tenant-app-reg posture explicit in every module.

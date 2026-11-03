# Rejewski v1.0.1 release notes

- **Status:** Final. Tagged `v1.0.1` and published as the GitHub Release on Thu Nov 5, 2026.
- **License:** MIT
- **Previous release:** [v1.0](release-notes-v1.0.md) (Mon Oct 26, 2026)

## Why this release

v1.0 shipped with the maintainers' lab tenant built into its scripts, tests, schemas, samples, and documentation: the tenant ID and name, its domain, its test account names, the operator's object ID, and the maintainers' organization tenant. A user had to edit code to point Rejewski at their own lab, and the source read as a record of one lab rather than a toolkit.

v1.0.1 makes every one of those values configurable. Scripts read the tenant, account, and operator from arguments or environment variables, and the files outside evidence use placeholders such as `<lab-tenant-id>` and `meganb@<lab-domain>`. Committed evidence (replay logs, finding-triage records, HTML reports, and the canonical run) is kept as recorded.

No tool, Graph call, schema, rubric, or guardrail changes behavior. Rejewski is still read-only and still covers Stage 1 (Initial Access, Discovery, read-only Collection, and token reuse).

## Upgrading from v1.0

1. Copy `.env.example` to `.env` (or compare it with your existing `.env`). It lists every variable the scripts read.
2. **If you run against your own lab tenant,** set `REJEWSKI_LAB_TENANT_ID` to its tenant ID. That tenant keeps the run-level (v1) consent-record rule. Leave the variable unset to require an active v2 durable record for every tenant. For any tenant other than the maintainers' lab, this is the rule v1.0 already applied (G-1, ADR 0008 v1.1).
3. **If you write consent records,** set `REJEWSKI_OPERATOR_OBJECT_ID`, `REJEWSKI_OPERATOR_NAME`, and `REJEWSKI_OPERATOR_EMAIL`, or pass them as arguments. `scripts/write_consent_record.py` refuses to run without them and without `AZURE_TENANT_ID`.
4. **If you seed a lab tenant,** use `scripts/seed-lab-tenant.ps1` (renamed from the v1.0 seed script). `-UserDomain` and `-AdminDomain` are required, `-Roster` takes an optional JSON roster, and the script prompts for each account's password separately instead of setting one shared password.
5. **If you import Rejewski modules in your own code,** update these names:

| v1.0 | v1.0.1 |
|---|---|
| `roe_gate.is_sandbox` | `roe_gate.is_lab_tenant` |
| `roe_gate.require_sandbox` | `roe_gate.require_lab_tenant` |
| built-in GUID scrubber in `replay_log` | `replay_log.scrub_lab_tenant_guid` |

`scripts/reasoning_loop.py` and `scripts/demo_b007_device_compliance.py` now take the tenant and account from arguments or `.env`, and the reasoning loop refuses to write replay-log entries without them.

## Changes in this release

### Security

- No built-in tenant, domain, account, or operator values outside committed evidence.
- The lab tenant comes from configuration (`REJEWSKI_LAB_TENANT_ID`, ADR 0008 v1.1).
- The seed script prompts for a separate password per account.
- Secret scanning and push protection are enabled on the repository.

### Added

- `.env.example`, listing every variable the scripts read.
- A feature-request issue template that asks for the attack stage, ATT&CK technique, use case, proposed approach, and expected control.
- ADR 0009 (Proposed): Stage 2 Rules of Engagement, Persistence by a standard account. It sets the rules for v1.1's stage and changes no code yet.
- Run R019 (Sat Oct 31): all 15 tool surfaces, the same 10 findings as R017 and R018 (5 high, 5 medium), with its replay log, triage records, and HTML report.
- Six tests (241 passing).

### Changed

- CONTRIBUTING.md states the repo is public and open to external contributions, and points idea discussions to GitHub Discussions.
- The bug report template asks for the release tag or commit SHA.

### Removed

- `scripts/write_consent_r011.py`, a one-off helper with built-in tenant and operator IDs. Use `scripts/write_consent_record.py`.

## Evidence in this release

- Replay logs for runs R002 to R019 in `samples/replay-log/`, with finding-triage records in `samples/finding-triage/`.
- HTML reports for R012 to R019 in `docs/reports/`.
- The canonical run stays R017.

Evidence comes from the maintainers' lab tenant with seeded accounts. It names that tenant and its test accounts by design (G-6).

## Known limitations

Unchanged from v1.0. See [Known limitations in the v1.0 release notes](release-notes-v1.0.md#known-limitations). The technique-scope check (C015) and a replacement for ROPC sign-in (C014) are v1.1 prerequisites in ADR 0009.

## Changes

[CHANGELOG.md](https://github.com/Cloud-Harbor-Consulting-LLC/rejewski/blob/main/CHANGELOG.md) lists every change in this release.

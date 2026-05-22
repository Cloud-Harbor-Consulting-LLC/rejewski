# Project Harbor Sonar — Rejewski ROE Consent Flow

- Version: v0.1
- Last updated: 2026-05-22
- Status: Baseline (Sprint 1 W3 deliverable)
- Authors: Derek Morgan
- Related: ADR 0001 (Rules of Engagement) §2 Consent floor, §5 Replay-log immutability, §7 Credential handling, §8 Operator identity; docs/threat-model.md v0.3; docs/guardrails.md G-1, G-3, G-5, G-8

## Change log

- v0.1 (2026-05-22) — Initial baseline. Codifies the per-run consent prompt, operator confirmation mechanic, consent-record schema, replay-log binding, refusal behaviors, and Sprint 1 exit floor of 5 consented runs.

---

## 1. Purpose and scope

ADR 0001 §2 requires that every Rejewski run be gated by an explicit per-run operator consent confirmation. This document specifies the **shape** of that confirmation, the **record** it produces, and the **binding** between the consent record and the downstream replay log. It does not modify the rules in ADR 0001; it operationalizes them.

The consent flow is the first runtime contract Rejewski enforces. It runs after config load and before any token acquisition (T1078.004) or Graph call. A failed or declined consent terminates the run before any network egress.

Scope:

- All Sprint 1 technique runs against the cloudharbordemo sandbox tenant (76b87c33-6178-4ff9-94a7-164792c8e4c6).
- Single-operator runs only. Multi-operator handoffs are out of scope for v0.1.
- Interactive operator at a terminal session. Headless/CI-driven runs are out of scope until ADR-amended (Sprint 3+ candidate).

## 2. Pre-run consent prompt

After config load passes the G-1 tenant lock check and the §3 technique-allowlist check from ADR 0001, the runtime emits a consent prompt to stdout and blocks on operator input. The prompt summarizes the proposed run in four required fields and one runtime-generated identifier.

| Field | Source | Example value |
|-------|--------|---------------|
| Target tenant | rejewski.config.json (tenant_id) | cloudharbordemo (76b87c33-6178-4ff9-94a7-164792c8e4c6) |
| Techniques | invocation arguments | T1078.004, T1087.004 |
| Expected duration | per-technique manifest sum + 20% slack | ≤ 6 minutes |
| Operator identity | resolved Entra ID object ID for signed-in account | b0a5e9c4-... (ADR 0001 §8) |
| Run ID | runtime-generated UUIDv4 at prompt emission | 7d3c1a2e-... |

The operator confirms by typing the run ID back verbatim and pressing Enter. Any other input (including a bare `y`, `yes`, or empty line) is treated as decline. Verbatim run-ID echo is deliberate: it forces the operator to read the prompt, prevents reflex confirmation, and produces a confirmation token that proves the operator saw the specific run ID — not a generic approval.

A SIGINT (Ctrl-C) at the prompt is recorded as a decline, not an error.

## 3. Consent record

On confirmation, the runtime writes a consent record to the replay log as its first entry. The record schema:

| Field | Type | Notes |
|-------|------|-------|
| event | string | Literal `consent.granted` or `consent.declined` |
| run_id | UUIDv4 | Matches the run ID echoed by the operator |
| tenant_id | UUIDv4 | Must equal the G-1 locked value |
| operator_object_id | UUIDv4 | Entra ID object ID; never UPN or display name (ADR 0001 §8) |
| techniques | list[string] | ATT&CK technique IDs as confirmed |
| expected_duration_seconds | integer | Upper bound; the run is aborted if it exceeds 2× this value (G-8 alignment) |
| prompt_emitted_at | RFC 3339 timestamp | UTC, millisecond precision |
| confirmed_at | RFC 3339 timestamp | UTC, millisecond precision |
| confirmation_latency_seconds | integer | confirmed_at − prompt_emitted_at, rounded down |

The consent record is the **only** entry in the replay log that may precede the run's first Graph call. Any replay log whose first entry is not a `consent.granted` event is invalid by inspection and fails post-run validation.

Consent records carry no token material, no credential value, and no operator UPN. ADR 0001 §7 (credential handling) and §8 (operator identity) both apply.

## 4. Replay-log binding

The consent record's `run_id` is propagated as the binding key for every subsequent replay-log entry in the run (Graph request, Graph response, technique start, technique end, run end). The post-run hash (ADR 0001 §5) seals the consent record together with all bound entries; tampering with either side invalidates the hash.

Binding properties:

- One consent record per run. Mid-run re-prompts are not supported in v0.1.
- The `run_id` is a non-reusable nonce. Re-using a prior run's ID in a new prompt is a runtime error.
- A run with a `consent.declined` first entry produces a log file of exactly that one entry and exits 0. The declined record is preserved as evidence of the refusal.

## 5. Sprint 1 consent floor

ADR 0001 §2 sets the Sprint 1 exit floor at **5 consented runs logged end-to-end**. "End-to-end" means each of the 5 runs must satisfy all of:

- `consent.granted` record present as first replay-log entry.
- At least one Graph request entry bound to the same `run_id`.
- A `run.end` entry bound to the same `run_id`.
- A sealed post-run hash recorded in logs/rejewski-audit.jsonl (G-5 alignment).

Declined runs (`consent.declined` first entry) and aborted runs (no `run.end` entry) do **not** count toward the floor. The 5-run floor is a quality gate on the consent → replay-log → audit chain, not a volume target.

The current count toward the Sprint 1 floor is tracked in the audit ledger and reported in the Sprint 1 review (output/sprint-1-review.md).

## 6. Refusal and abort behaviors

The runtime refuses to proceed and exits non-zero before any Graph call when any of the following occur:

- The operator types anything other than the exact run ID at the prompt.
- The operator sends SIGINT or closes the terminal before confirmation.
- The resolved operator object ID does not match the principal that will sign in for token acquisition (ADR 0001 §8 deferred check: the runtime re-asserts this match at first Graph call and aborts on mismatch).
- The tenant ID resolved from runtime config does not equal 76b87c33-6178-4ff9-94a7-164792c8e4c6 (G-1).
- The technique list contains any ID not in the current threat-model §5 allowlist (ADR 0001 §3).

In every refusal case, the runtime writes either a `consent.declined` record or a pre-consent abort marker to the replay log before exiting. No refusal is silent.

## 7. Out of scope (v0.1)

The following are deliberately deferred:

- Headless / CI-driven consent flows (would require a signed pre-issued consent artifact; Sprint 3+ ADR candidate).
- Multi-operator handoff within a run.
- Consent revocation mid-run (current model: abort and re-prompt in a new run).
- Operator-side consent storage (e.g., 24-hour bypass tokens). v0.1 requires fresh per-run consent unconditionally.

## 8. References

- ADR 0001 — Rules of Engagement, §2 Consent floor, §5 Replay-log immutability, §7 Credential handling, §8 Operator identity
- docs/threat-model.md v0.3 — §3 Adversary model, §5 Sprint 1 technique scope
- docs/guardrails.md — G-1 (Sandbox Tenant Lock), G-3 (Scope Allowlist), G-5 (Audit Capture), G-8 (Session Keep-Warm Bound)
- MITRE ATT&CK Enterprise — <https://attack.mitre.org/matrices/enterprise/>

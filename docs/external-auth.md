# Project Harbor Sonar — Rejewski External Authorization Flow

- Version: v0.2
- Last updated: 2026-10-15
- Status: Baseline (Sprint 5 W18 deliverable) — process/authorization document
- Authors: Derek Morgan
- Related: docs/roe-consent-flow.md v0.2 (self-test consent mechanic), ADR 0001 (Rules of
  Engagement) §1 no-tenant-app-reg, §2 consent floor, §7 credential handling, §8 operator
  identity; docs/guardrails.md G-1 (Consent-bound tenant lock), G-6 (Data Redaction); ADR 0008;
  schemas/roe-consent/v2.json; samples/roe-consent/

---

## 1. Purpose and scope

`docs/roe-consent-flow.md` specifies the per-run consent mechanic for the **self-test**
scenario only — Rejewski running against the CHC-owned lab tenant
(`<lab-tenant-id>`). Its §7 "Out of scope (v0.1)" does not address a
third-party engagement at all. This document adds that missing scenario: the **authorization
flow for a third-party tenant assessment** — a run against a tenant that is neither
the lab tenant nor an operator-owned tenant, performed for and authorized by an external
counterparty.

It reuses the roe-consent-flow.md §2 consent-prompt mechanic as its runtime base, but the
**trust and authorization chain** for a third party — who signs, what evidence proves
authorization, and how scope is bounded to only the agreed surfaces — is new and is treated
here.

> **Update 2026-10-15 (v0.2): third-party runs can now execute.** [ADR 0008](adr/0008-consent-bound-tenant-lock.md) replaced the sandbox-only G-1 lock with a consent-bound tenant lock. A run may now target the counterparty's tenant when the run's replay-log directory holds a v2 record (`schemas/roe-consent/v2.json`) for that run ID and tenant, with `engagement.type` `third_party_assessment`, `engagement.status` `active`, today inside the authorization window, `counterparty.is_self_test` false, and a signature method other than `self_test_attestation`. `scripts/roe_gate.py` checks these fields before the first token request. It does not verify the signed letter itself, so the authorization chain in §2 stays a precondition the operator must meet before writing the record. `samples/roe-consent/thirdparty-example.json` remains illustrative.

---

## 2. Authorization chain (third-party assessment)

Before any third-party run may be *authorized* (a separate question from whether G-1 permits it
to *execute* — see §1), all of the following must exist and be retained:

1. **A signed engagement letter (or equivalent).** The counterparty's authorized signatory and
   the CHC signatory both sign a document that names the target tenant, the agreed scope surface,
   and the effective/expiry dates. This is the third-party analogue of the self-test's standing
   ROE — a self-test is *self-authorized*; a third-party run is *counter-signed*. The signature
   method is recorded (see the ROE Consent Archive workbook's **Signature Method** column for the
   vocabulary already in use — e.g. wet signature, e-signature, email authorization). A
   third-party engagement MUST NOT use the `self_test_attestation` method.
2. **A recorded counterparty identity.** Organization, authorized contact name, and contact
   email — the parties who can grant and revoke authorization.
3. **An explicit, enumerated scope surface.** The agreed tenants, Graph surfaces, and technique
   classes. Anything not enumerated is out of scope by default (§3).
4. **An authorization window.** `effective_date … expiry_date`. Authorization is time-boxed; a
   run confirmed outside the window is unauthorized regardless of the signed letter.
5. **A durable consent record.** A `schemas/roe-consent/v2.json` record capturing all of the
   above, archived independently of any single run's replay log (§5).

The `evidence_ref` field of the v2 record points at the retained signed letter; the record
itself is the machine-readable index into that evidence.

---

## 3. Scope-boundary enforcement

A third-party run is bounded to its agreed **Scope Surface** by three independent checks, each
of which can only *deny*, never widen:

- **Tenant lock.** The run's `tenant_id` must equal the tenant named in the run's consent record.
  Enforced in code by `scripts/roe_gate.py` before the first token request (G-1, ADR 0008).
- **Technique subset.** The run's confirmed `techniques` MUST be a subset of the technique
  classes enumerated in `scope.surface`. A technique not in the agreed surface is refused at the
  consent prompt, exactly as an out-of-allowlist technique is refused for a self-test
  (roe-consent-flow.md §6, ADR 0001 §3).
- **Authorization window.** The run's `confirmed_at` must fall within
  `[authorization.effective_date, authorization.expiry_date]`. Outside the window the run is
  unauthorized even if every other check passes.

The read-only posture is unchanged: a third-party assessment is still **G-1 read-only Graph
GET** enumeration. External authorization never grants write, credential-modification, or
tenant-app-registration capability — those remain barred by ADR 0001 §1 and G-2/G-3 for every
scenario, self-test or third-party.

---

## 4. How this differs from the self-test flow

| Dimension | Self-test (roe-consent-flow.md) | Third-party (this doc) |
|---|---|---|
| Target tenant | the lab tenant, or a tenant the operator owns | The counterparty's named tenant (G-1 consent-bound lock, ADR 0008) |
| Who authorizes | CHC, self-authorized under the standing ROE | Counterparty's signatory **and** CHC, counter-signed |
| Evidence of authorization | The standing ROE / `docs/roe-consent-flow.md` | A signed engagement letter, retained and referenced by `evidence_ref` |
| Signature method | `self_test_attestation` | Counter-signed method (wet/e-signature/email), never `self_test_attestation` |
| Counterparty block | `is_self_test = true`, explicit self-test marker | `is_self_test = false`, full counterparty org/contact/email |
| Scope | All implemented techniques against the sandbox | Only the enumerated agreed surfaces; techniques ⊆ scope.surface |
| Authorization window | Standing | Time-boxed `effective_date … expiry_date` |
| Consent record | v1 core, embedded in the replay log | v2 durable-archive record (superset of the v1 core), archived standalone |

The runtime **consent prompt itself is identical** — same four required fields plus the
verbatim run-ID echo (roe-consent-flow.md §2). What changes is the authorization chain that must
exist *before* the prompt is allowed to run, and the durability of the record produced *after*.

---

## 5. Consent record v2 and the ROE Consent Archive workbook

The durable consent record (`schemas/roe-consent/v2.json`) is a strict **superset of the v1
replay-log-embedded shape** (`schemas/roe-consent/v1.json`): it keeps the nine v1 fields
unchanged — so `scripts/write_consent_record.py`'s `v1_core()` can still seed a run's replay log
with a byte-compatible v1 entry, and the committed R010–R013 evidence stays valid as v1 — and
adds the durable-archive block. A v2 record therefore serves as a **standalone artifact** with
its own `record_id`, not merely embedded evidence in one run's log.

The archive fields are designed to reconcile **field-by-field** against the SharePoint **ROE
Consent Archive workbook** (which Derek maintains manually). A human can transcribe a v2 record
into a workbook row, or vice-versa, with no ambiguity:

| SharePoint workbook column | v2 record field |
|---|---|
| Engagement Name | `engagement.name` |
| Counterparty Org | `counterparty.org` |
| Counterparty Contact | `counterparty.contact_name` |
| Counterparty Email | `counterparty.contact_email` |
| Engagement Type | `engagement.type` (`self_test` \| `third_party_assessment`) |
| Scope Surface | `scope.surface` (enumerated list) |
| Scope Summary | `scope.summary` |
| MVP Pillar | `engagement.mvp_pillar` |
| Signed By (provider) | `authorization.signed_by_provider` |
| Signed By (counterparty) | `authorization.signed_by_counterparty` |
| Signature Method | `authorization.signature_method` |
| Signed date | `authorization.signed_date` |
| Effective date | `authorization.effective_date` |
| (authorization expiry) | `authorization.expiry_date` |
| Status | `engagement.status` (`draft`\|`active`\|`completed`\|`expired`\|`revoked`) |
| Storage Location | `archive.storage_location` |

Two fields have no workbook column of their own and exist to bind the record to run evidence:
`authorization.expiry_date` (the workbook records a single Signed/Effective pairing; the schema
adds an explicit expiry so the §3 window check is machine-checkable) and `archive.record_id` /
`archive.created_utc` (the durable record's own identity and authoring time). The v1 core fields
(`run_id`, `tenant_id`, `techniques`, timestamps, `confirmation_latency_seconds`, …) carry the
run-linkage that the workbook does not track.

**Self-test records populate the counterparty block explicitly, never blank** (AC4): `is_self_test
= true`, `org = "Cloud Harbor Consulting (self-test)"`, and the CHC contact — see
`samples/roe-consent/selftest-example.json`. The third-party shape is illustrated by
`samples/roe-consent/thirdparty-example.json` (fictional counterparty; see the §1 banner).

---

## 6. Evidence retained

For every authorized engagement, the retained evidence set is:

- the signed engagement letter (or the standing ROE, for a self-test) at `authorization.evidence_ref`;
- the v2 durable consent record itself, at `archive.storage_location`;
- the run's replay log (which embeds the v1 core of the same consent as its first entry), sealed
  per ADR 0001 §5;
- the corresponding ROE Consent Archive workbook row.

`record_id` is the stable join key across all four. G-6 applies to the record as to any committed
artifact: no operator paths, tokens, or tenant secrets beyond the identifiers already carried by
the v1 consent shape; the sandbox tenant GUID is treated as it is in the committed R010/R011
records.

---

## 7. Out of scope / posture (v0.1)

Deliberately **not** enabled by this document:

- **Technique-scope enforcement in code.** §3's technique-subset check is a review step today;
  `scripts/roe_gate.py` enforces the tenant and the authorization window, not the technique list.
- **Writing to SharePoint directly.** The workbook remains Derek's manual system of record; the
  v2 record is a JSON artifact a human transcribes from (or into) it.
- **Any write, credential-modification, or tenant-app-registration capability.** Barred for all
  scenarios by ADR 0001 §1 and G-2/G-3.
- **Multi-operator handoff and headless/CI consent** — inherited out-of-scope items from
  roe-consent-flow.md §7.

---

## 8. Cross-references

- docs/roe-consent-flow.md — self-test per-run consent mechanic (§2 prompt reused here)
- schemas/roe-consent/v1.json — the frozen replay-log-embedded consent shape
- schemas/roe-consent/v2.json — the durable long-term-archive superset
- scripts/write_consent_record.py — v2 record emitter (`build_consent_record`, `v1_core`)
- samples/roe-consent/ — self-test and third-party illustrative records
- ADR 0001 — Rules of Engagement (§1 no tenant app reg, §2 consent floor, §3 technique allowlist,
  §7 credential handling, §8 operator identity)
- docs/guardrails.md — G-1 (Consent-bound tenant lock), G-6 (Data Redaction)
- docs/adr/0008-consent-bound-tenant-lock.md — the decision that lets a consented run execute against a third-party tenant

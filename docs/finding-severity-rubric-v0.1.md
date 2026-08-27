# Rejewski Finding Severity Scoring Rubric

- Version: v0.1
- Last updated: 2026-08-27
- Status: Living document — calibrated against the current finding-triage corpus
- Authors: Derek Morgan
- Related: schemas/finding-triage/v0.1.json, docs/threat-model.md, docs/attck-coverage.md, samples/finding-triage/

---

## 1. Purpose and scope

`schemas/finding-triage/v0.1.json` defines a `severity` enum —
`informational | low | medium | high | critical` — but no criteria for which level
applies when. This rubric closes that gap: it gives each level an **objective test a
human can apply**, three scored dimensions that feed a decision table, and a
confidence/evidence gate that keeps severity tied to *demonstrated* risk.

Scope note: Rejewski is a read-only adversary-emulation toolkit (G-1 read-only Graph
GET, G-2 no credential/write actions). Every current finding is a **reconnaissance**
result, so the corpus clusters in the informational–high band; `critical` is defined
but reserved (see §2). Severity here rates the *finding's demonstrated adversary value*,
not the ATT&CK technique's worst-case potential in a real breach.

---

## 2. Severity levels — objective tests

Apply the concrete test in the right-hand column. Each test is a yes/no a reviewer can
answer from the finding's replay-log evidence, not an adjective.

| Level | One-line meaning | Concrete test (answerable from the evidence) |
|---|---|---|
| **informational** | No adversary-usable capability on its own | Blast radius is **self-only** (operator's own objects), **OR** the cited evidence does not show the technique succeeding (see the gate, §4). |
| **low** | Generic recon; no path to accounts, credentials, or data | The technique **succeeded**, but its output is **infrastructure/classification metadata only** — no user/group/role list, no credential or token, no data content. |
| **medium** | Hands the adversary a tenant-wide target or evasion map | The technique **succeeded** and returned a **tenant-wide directory/identity list** (users, groups, roles, service principals) **or a defensive-posture map** (CA policy, detection-sensor health, sign-in/alert telemetry) — but **no** credential/token or data content. |
| **high** | Captured credential/token material, sensitive data, or bypassed a control | The finding demonstrates **possession or reuse of a token/credential**, **OR** read of **Confidential-or-higher data content**, **OR** a technique that operated **through a correctly-deployed preventive control** (e.g., a token reused with no fresh MFA challenge). |
| **critical** | Demonstrated tenant-wide compromise | The finding demonstrates an **admin/global-privilege capability, a persistence mechanism, or capture/exfiltration at tenant scale**. *Reserved:* out of Rejewski's read-only scope (G-1/G-2); no current finding can reach it. |

---

## 3. Scoring dimensions

Score each finding on three dimensions. Each level has a concrete anchor so two
reviewers score the same finding the same way.

| Dimension | 0 | 1 | 2 | 3 |
|---|---|---|---|---|
| **P — Privilege observed/required** | No directory role (any authenticated user; self-scope, e.g. `GET /me`) | Basic tenant read (Directory Readers / Global Reader) | Privileged read role (Security Reader, Reports Reader, Intune/role-scoped admin read) | Admin write / privilege escalation *(out of current scope)* |
| **B — Blast radius** | Self only (operator's own objects) | A single other principal/object | Tenant-wide **read** (all of a class: all users, all sites, all policies) | Tenant-wide **control** (write/persistence, or a token that unlocks tenant-wide action) |
| **D — Data sensitivity / attacker value** | Negligible (generic health/config) | Recon metadata (classification taxonomy, infra config) | Directory/identity **or** defensive-map value (users, groups, roles, CA policy, detection state, audit telemetry) | Credential/token material, **or** Confidential-or-higher data content |

Scoring is about what the finding **demonstrated**, not what the technique could do in
the worst case. A read that *could* have returned tenant secrets but returned an empty
set scores on what it actually surfaced.

---

## 4. Combining dimensions → severity

Evaluate the decision table **top-down; the first row whose condition holds sets the
base severity.** Then apply the gate.

| # | Condition | Base severity |
|---|---|---|
| 1 | `P = 3` **OR** `B = 3` **OR** (`D = 3` and the credential/data was captured at tenant scale) | **critical** |
| 2 | `D = 3` (token/credential material or sensitive-data content demonstrated) **OR** the technique operated through a correctly-deployed preventive control | **high** |
| 3 | `B = 2` **AND** `D = 2` (tenant-wide read of a directory/identity or defensive map) | **medium** |
| 4 | technique **succeeded** **AND** `D ≤ 1` **AND** `B ≤ 2` **AND** `P ≤ 2` | **low** |
| 5 | otherwise | fall through to the gate |

### Confidence / evidence gate (applied *after* the table)

Severity must reflect **demonstrated** risk. After computing the base severity:

- **Unconfirmed → informational.** If `confidence = low` **and** the cited evidence does
  not show the technique succeeding, floor the finding to **informational**, whatever the
  base severity. Record *why* in `notes`.
- **Self-only cap.** If `B = 0` (self-scope only), cap at **informational** unless `D = 3`.
- The gate can only lower severity, never raise it.

`confidence` (the schema's `low | medium | high`) rates *whether the finding is real and
correctly attributed*; `severity` rates *how much it matters if real*. The gate is the
one place the two interact: a finding that is not yet demonstrated cannot carry a
material severity on evidence that does not back it.

---

## 5. Worked examples (retroactive application)

The rubric applied to five existing records in `samples/finding-triage/`. The last two
columns compare the rubric's output to the severity already on the record. **Where they
differ, it is called out — not reconciled by fudging the scores.**

| Finding (record) | P | B | D | Table → base | Gate | **Rubric** | **Assigned** | Match |
|---|---|---|---|---|---|---|---|---|
| T1078.004 valid-accounts (R011) | 0 | 0 | — | — | unconfirmed | **informational** | informational | ✓ *(via gate — see 5.1)* |
| T1580 purview-labels (R011) | 1 | 2 | 2 | medium | — | **medium** | medium | ✓ *(re-triaged low→medium — see 5.2)* |
| T1087.004 account-discovery (R011) | 1 | 2 | 2 | medium | — | **medium** | medium | ✓ |
| T1526 ca-policy-discovery (R011) | 2 | 2 | 2 | medium | — | **medium** | medium | ✓ *(boundary — see 5.4)* |
| T1550.001 token-reuse (R011) | 1 | 2 | 3 | high (row 2) | — | **high** | high | ✓ |

### 5.1 T1078.004 — informational (agrees, but only through the gate)

The record is `informational` with `confidence = low`; its own `notes` read: *"Technique
T1078.004 not present in R011.json; verify script execution and replay log."* On the
dimensions alone, a **confirmed** valid-account / initial-access foothold is the
credential the whole chain rests on and would score **low at minimum** (higher if it
represented a live unauthorized session). The rubric agrees with `informational` **only
because the evidence gate fires** — the technique was not observed in the cited replay
log. **This is the corpus's clearest case where the technique's inherent risk and the
assigned label diverge, reconciled solely by the confidence gate.** Action: if the
evidence gap is closed on a later run, this finding must be re-scored upward (≥ low).

### 5.2 T1580 — rubric said **medium**, record said **low** → re-triaged to **medium** (resolved)

Purview sensitivity-label enumeration returned the tenant's **data-classification
taxonomy** (label names, enabled state, scope). The record originally rated this `low`
(treating the taxonomy as infrastructure metadata, `D = 1`). The rubric scores it `D = 2`:
the label scheme is a **Collection-targeting map** — it tells an adversary which data
classes exist (e.g. *Confidential*, *Highly Confidential – Legal*) so they can steer later
exfiltration toward the highest-value labels and around label-gapped channels. With
`B = 2` (tenant-wide) and `D = 2`, decision row 3 yields **medium**.

**Resolution.** This divergence was surfaced rather than forced, and then acted on:
`samples/finding-triage/t1580-r011-purview-labels.json` has been **re-triaged from `low`
to `medium`** (triage_status `open` → `reviewed`), so the rubric and the record now agree.
The `D = 1` vs `D = 2` call remains the **softest boundary in the rubric** (§6); v0.2 should
add an explicit `D` anchor for "classification taxonomy" so this decision is codified rather
than case-by-case.

> Downstream note: `docs/findings-report-r011.md` and `docs/phs-security-roi-model-v0.1.md`
> are versioned point-in-time artifacts that still cite T1580 as `low`; they are left as
> authored unless separately revised, since they record the assessment as of their own dates.

### 5.3 T1087.004 — medium (agrees)

Account discovery enumerated **8 users tenant-wide** (`B = 2`) via `GET /users`, requiring
only basic read (`P = 1`); the output is the directory/identity target list (`D = 2`). Row
3 → **medium**, matching the record. This is the canonical "tenant-wide directory read,
no credentials captured" shape that anchors the medium band.

### 5.4 T1526 — medium (agrees; flagged medium/high boundary)

CA-policy discovery reads the tenant's **conditional-access posture** — where MFA and
device controls are and are not enforced. It requires a privileged read (`P = 2`, Security
Reader), is tenant-wide (`B = 2`), and its output is a **defensive-evasion map** (`D = 2`).
Row 3 → **medium**, matching the record. It is called out because it — with T1518.001
(detection-sensor health) and T1654 (sign-in/alert telemetry) — sits at the **medium/high
boundary**: all three expose the *defender's own map*, which has outsized evasion value. A
future rubric version may add a "defensive-evasion escalator" that would move this class to
`high`. Left at `medium` for v0.1, but flagged so the calibration choice is explicit.

### 5.5 T1550.001 — high (agrees)

Token reuse: the delegated bearer token was **silently reused for all 9 technique runs**
via the MSAL encrypted cache. This is token material (`D = 3`) and a technique that
operated **through the authentication control** (a cached token needs no fresh MFA
challenge) — decision row 2 → **high**, matching the record. This is the corpus's only
finding that touches credential/token material, and the only current `high`.

---

## 6. Notes, limitations, and calibration

- **v0.1 is calibrated against the current 10-record corpus.** The one worked-example
  divergence (T1580, §5.2) has since been resolved by re-triaging that record from `low`
  to `medium`, so the rubric's **final label now matches all five** worked examples;
  T1078.004 (§5.1) matches only through the confidence gate. Calibrating to the corpus
  means the rubric will need re-checking as new, higher-severity findings (post-B030
  role-assignment reads, future write-scope emulation) enter the set.
- **The `D` (data value) dimension is the softest to score** — the `D = 1` vs `D = 2`
  boundary (infra/taxonomy metadata vs directory/defensive-map value) is where reviewers
  will most often disagree, as T1580 shows. v0.2 should add worked anchors for each `D`
  level drawn from real findings.
- **`critical` is reserved.** Rejewski's read-only posture (G-1) and no-write posture (G-2)
  mean no finding demonstrates admin escalation, persistence, or tenant-scale capture. The
  level exists so the rubric is complete and so a future write-scope emulation (if ever
  authorized under a superseding ADR) has a home for it.
- **A "defensive-evasion escalator" is deferred to v0.2** (see §5.4): findings that expose
  the tenant's control/detection map (T1526, T1518.001, T1654) are arguably worth more than
  plain directory recon. v0.1 keeps them at `medium` to avoid re-rating half the corpus on
  a single unvalidated heuristic.
- **Severity is not confidence.** Keep them independent in the record; the gate (§4) is the
  only coupling. Do not lower `severity` to express doubt — lower `confidence` and let the
  gate act.

---

## 7. Change log

| Version | Date | Change |
|---|---|---|
| v0.1 | 2026-08-27 | Initial rubric. Five severity levels with objective tests; P/B/D scoring dimensions; decision table + confidence/evidence gate; five retroactive worked examples against `samples/finding-triage/` (one genuine divergence flagged: T1580 low → rubric medium). Calibrated against the S4 W16 finding corpus. |
| v0.1 | 2026-08-27 | Acted on the §5.2 divergence: re-triaged `t1580-r011-purview-labels` from `low` to `medium` (triage_status `open` → `reviewed`). Worked-example agreement now 5/5; §5.2/§6 and the worked-example table updated to reflect the resolution. |

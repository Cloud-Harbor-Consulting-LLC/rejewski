# Rejewski Finding Severity Scoring Rubric

- Version: v1.0
- Last updated: 2026-09-10
- Status: **Locked (v1.0).** Calibrated against the current finding-triage corpus and tied to
  CIS Controls v8 (§2, framework cross-reference). Filename slug kept at `-v0.1` for link
  stability across the records and docs that cite it.
- Authors: Derek Morgan
- Related: schemas/finding-triage/v0.1.json, docs/threat-model.md, docs/attck-coverage.md, samples/finding-triage/, CIS Controls v8 (<https://www.cisecurity.org/controls/v8>)

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
| **medium** | Hands the adversary a tenant-wide target list | The technique **succeeded** and returned a **tenant-wide directory/identity list** (users, groups, roles, service principals) **or a data-classification taxonomy that steers Collection** — but **no** credential/token, data content, or defensive-evasion map. |
| **high** | Captured credential/token material or sensitive data, bypassed a control, or mapped the defender's own detection posture | The finding demonstrates **possession or reuse of a token/credential**, **OR** read of **Confidential-or-higher data content**, **OR** a technique that operated **through a correctly-deployed preventive control** (e.g., a token reused with no fresh MFA challenge), **OR** enumeration of the **tenant's own defensive-evasion map** — CA-policy posture, security-sensor health, or sign-in/alert telemetry (the *defensive-evasion escalator*, adopted in v1.0 — see §5.4 and §6). |
| **critical** | Demonstrated tenant-wide compromise | The finding demonstrates an **admin/global-privilege capability, a persistence mechanism, or capture/exfiltration at tenant scale**. *Reserved:* out of Rejewski's read-only scope (G-1/G-2); no current finding can reach it. |

### Framework cross-reference — CIS Controls v8 (added v1.0)

The Master Plan S5 W18 acceptance ties the rubric to an external control framework. This
rubric anchors to **CIS Controls v8**, not Microsoft Secure Score. Reasoning:

- A severity rubric is a **stable reference** and must cite an equally stable anchor. CIS
  Controls v8 is framework-stable, vendor-neutral, and citable by Control/Safeguard number.
  Microsoft Secure Score is a **per-tenant posture metric** whose points and improvement-action
  catalog change over time and per tenant — it describes *one tenant's configuration today*,
  not *the severity class of an adversary capability*, so it cannot anchor a fixed rubric.
- CIS Controls v8 **Implementation Groups (IG1 → IG3)** give a maturity axis that parallels the
  rubric's severity escalation, and each level maps cleanly to the CIS Safeguard *class* that
  should have prevented or detected the demonstrated capability.
- Rejewski findings already carry a defensive control mapping (CA / RBAC); those map onto CIS
  Safeguards, so the cross-reference **reinforces the existing finding-to-control mapping**
  rather than adding a second, tenant-specific axis. (Secure Score remains the right lens for
  the *tenant-side remediation* view — its improvement actions correspond to these same CIS
  Safeguards — so the two are complementary; the rubric anchors to CIS, remediation tracking
  can still cite Secure Score.)

The cross-reference is tied to the P/B/D dimensions (§3): **P** (privilege) ↔ CIS Controls 5
(Account Management) & 6 (Access Control Management); **B** (blast radius) ↔ CIS 6.8 (RBAC) &
3.3 (data access control lists); **D** (data / attacker value) ↔ CIS 3 (Data Protection) & 8
(Audit Log Management, for the defensive-evasion / telemetry case).

| Severity | Rubric driver (P/B/D) | CIS Controls v8 anchor — the Safeguard class that should have prevented or detected the demonstrated capability |
|---|---|---|
| **informational** | `B = 0` self-scope, or unconfirmed via the gate (§4) | No tenant Safeguard implicated by the finding alone — baseline CIS Control 4 (Secure Configuration) hygiene only. |
| **low** | `D ≤ 1` — environmental/infra recon only | CIS Control 1 (Enterprise Asset Inventory) / Control 2 (Software Inventory): the finding reflects the environment's *shape*; lowest remediation urgency. |
| **medium** | `B = 2` tenant-wide read; `D = 2` as a directory/identity **target list** or a data-classification **taxonomy** | Target list → CIS Control 5 (Account Management) + Control 6 (Access Control Management, esp. **6.8** RBAC / least-privilege). Data-classification taxonomy → CIS Control 3 (Data Protection). The finding maps the targets; least-privilege and data-protection Safeguards shrink them. |
| **high** | `D = 3` token/credential or Confidential+ data; operated **through a preventive control**; **or** exposed the **defensive-evasion map** (escalator, v1.0) | Credential/token & control-bypass → CIS Control 6 (**6.5** MFA for administrative access, **6.8** RBAC). Data content → CIS Control 3 (**3.3** data access control lists). **Defensive-evasion map → CIS Control 8 (Audit Log Management, incl. 8.5 / 8.11) and detection Safeguards** — exposing the tenant's audit/detection posture directly degrades the defender's ability to detect, which is precisely why v1.0 escalates this class to high. |
| **critical** | `P = 3` / `B = 3` — admin or tenant-scale compromise/persistence | CIS Control **5.4** (dedicated administrator accounts) + Control 6 at IG3 (privileged access) + Control **3.3** (data access control). *Reserved* — out of Rejewski's read-only scope. |

---

## 3. Scoring dimensions

Score each finding on three dimensions. Each level has a concrete anchor so two
reviewers score the same finding the same way.

| Dimension | 0 | 1 | 2 | 3 |
|---|---|---|---|---|
| **P — Privilege observed/required** | No directory role (any authenticated user; self-scope, e.g. `GET /me`) | Basic tenant read (Directory Readers / Global Reader) | Privileged read role (Security Reader, Reports Reader, Intune/role-scoped admin read) | Admin write / privilege escalation *(out of current scope)* |
| **B — Blast radius** | Self only (operator's own objects) | A single other principal/object | Tenant-wide **read** (all of a class: all users, all sites, all policies) | Tenant-wide **control** (write/persistence, or a token that unlocks tenant-wide action) |
| **D — Data sensitivity / attacker value** | Negligible (generic health/config) | Recon metadata — environmental/infrastructure config only (service health, verified domains, SKU counts, topology) | Directory/identity, defensive-map, **or data-targeting** value (users, groups, roles, CA policy, detection state, audit telemetry, **or a data-classification taxonomy that steers Collection**) | Credential/token material, **or** Confidential-or-higher data content |

Scoring is about what the finding **demonstrated**, not what the technique could do in
the worst case. A read that *could* have returned tenant secrets but returned an empty
set scores on what it actually surfaced.

### D = 1 vs D = 2 — the boundary anchor (added in v0.2)

The `D = 1` / `D = 2` line is the rubric's most-contested call — it drove the T1580
re-triage. Apply this concrete test:

- **D = 1** — the output only describes the environment's *shape* and names no principal,
  role, policy, detection component, data class, or credential. Examples: service-health /
  announcement status, verified domains, subscribed-SKU counts, tenant topology.
- **D = 2** — the output gives the adversary at least one of:
  - **(a) a target list** — specific accounts, groups, roles, or service principals;
  - **(b) a defensive-evasion map** — CA policy posture, detection-sensor health, or
    sign-in/alert telemetry;
  - **(c) a data-targeting taxonomy** — a data-classification scheme (sensitivity-label
    names/scope) that steers later Collection toward specific data classes.

  All three score `D = 2`. **Routing differs at the decision table (§4):** sub-cases (a) and
  (c) resolve to **medium**, but sub-case **(b) — the defensive-evasion map — escalates to
  high** under the defensive-evasion escalator adopted in v1.0. The escalator is a routing
  rule, not a re-score: the defender's-own-detection map stays `D = 2` (it is neither
  credential/token nor data content, so it is not `D = 3`), but its evasion value is treated
  as high because it tells the adversary *what to evade*, not merely *who or what exists*.

Worked anchor: **T1580** sensitivity-label enumeration is **D = 2 under (c)** — the label
scheme tells an adversary which data classes to target — which is why it was re-triaged from
`low` to `medium` (§5.2). A pure `GET /organization` domain/SKU read, by contrast, is **D = 1**.

---

## 4. Combining dimensions → severity

Evaluate the decision table **top-down; the first row whose condition holds sets the
base severity.** Then apply the gate.

| # | Condition | Base severity |
|---|---|---|
| 1 | `P = 3` **OR** `B = 3` **OR** (`D = 3` and the credential/data was captured at tenant scale) | **critical** |
| 2 | `D = 3` (token/credential material or sensitive-data content demonstrated) **OR** the technique operated through a correctly-deployed preventive control | **high** |
| 3 | `D = 2` via a **defensive-evasion map** — sub-case (b) in §3: CA-policy posture, security-sensor health, or sign-in/alert telemetry (*defensive-evasion escalator, adopted v1.0*) | **high** |
| 4 | `B = 2` **AND** `D = 2` (tenant-wide read of a directory/identity target list or a data-classification taxonomy — §3 sub-cases (a)/(c)) | **medium** |
| 5 | technique **succeeded** **AND** `D ≤ 1` **AND** `B ≤ 2` **AND** `P ≤ 2` | **low** |
| 6 | otherwise | fall through to the gate |

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
| T1526 ca-policy-discovery (R011) | 2 | 2 | 2 | high (row 3, escalator) | — | **high** | high | ✓ *(escalated medium→high — see 5.4)* |
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

> Downstream note (updated 2026-08-29): the two versioned artifacts that embedded T1580's
> severity — `docs/findings-report-r011.md` and `docs/phs-security-roi-model-v0.1.md` — plus
> the `t1580-conditional-access-purview-require-compliant-app` finding-to-control mapping have
> since been reconciled to `medium`, each carrying a dated footnote that records the re-triage
> while preserving the original assessment context.

### 5.3 T1087.004 — medium (agrees)

Account discovery enumerated **8 users tenant-wide** (`B = 2`) via `GET /users`, requiring
only basic read (`P = 1`); the output is the directory/identity target list (`D = 2`). Row
3 → **medium**, matching the record. This is the canonical "tenant-wide directory read,
no credentials captured" shape that anchors the medium band.

### 5.4 T1526 — high (defensive-evasion escalator, adopted v1.0)

CA-policy discovery reads the tenant's **conditional-access posture** — where MFA and
device controls are and are not enforced. It requires a privileged read (`P = 2`, Security
Reader), is tenant-wide (`B = 2`), and its output is a **defensive-evasion map** (`D = 2`,
§3 sub-case (b)). This — with T1518.001 (detection-sensor health) and T1654 (sign-in/alert
telemetry) — exposes the *defender's own map*, which tells an adversary **what to evade**, not
merely who or what exists. v0.2 flagged these three at the medium/high boundary and deferred
the escalator to a PM decision; **v1.0 adopts the defensive-evasion escalator**: decision-table
row 3 routes the `D = 2` defensive-evasion sub-case to **high**. T1526, T1518.001, and T1654 are
therefore **re-triaged `medium` → `high`** (§6), each finding record, its finding-to-control
mapping, `docs/findings-report-r011.md`, and the `docs/phs-security-roi-model-v0.1.md` §6 bridge
updated with a dated footnote preserving the original medium assessment — the same reconciliation
pattern used for the T1580 `low` → `medium` fix (§5.2). The directory/identity target-list
findings (T1087.004, T1069.003) and the data-classification taxonomy (T1580) are **not** escalated
— they remain `medium`; the escalator is scoped precisely to the defender's-own-detection map.

### 5.5 T1550.001 — high (agrees)

Token reuse: the delegated bearer token was **silently reused for all 9 technique runs**
via the MSAL encrypted cache. This is token material (`D = 3`) and a technique that
operated **through the authentication control** (a cached token needs no fresh MFA
challenge) — decision row 2 → **high**, matching the record. This is the corpus's only
finding that touches credential/token material, and the only current `high`.

---

## 6. Notes, limitations, and calibration

- **The rubric is calibrated against the current 10-record corpus.** The one worked-example
  divergence (T1580, §5.2) has since been resolved by re-triaging that record from `low`
  to `medium`, so the rubric's **final label now matches all five** worked examples;
  T1078.004 (§5.1) matches only through the confidence gate. Calibrating to the corpus
  means the rubric will need re-checking as new, higher-severity findings (post-B030
  role-assignment reads, future write-scope emulation) enter the set.
- **The `D` (data value) dimension is the softest to score** — the `D = 1` vs `D = 2`
  boundary is where reviewers most often disagree, as T1580 showed. **v0.2 codifies this
  boundary** with an explicit test and worked anchors (§3, "D = 1 vs D = 2 — the boundary
  anchor"): a data-classification taxonomy that steers Collection is now unambiguously `D = 2`,
  while pure environmental/infra config is `D = 1`.
- **`critical` is reserved.** Rejewski's read-only posture (G-1) and no-write posture (G-2)
  mean no finding demonstrates admin escalation, persistence, or tenant-scale capture. The
  level exists so the rubric is complete and so a future write-scope emulation (if ever
  authorized under a superseding ADR) has a home for it.
- **The "defensive-evasion escalator" is ADOPTED as of v1.0** (PM decision, S5 W18; see §5.4).
  Findings that expose the tenant's own control/detection map (T1526 CA-policy posture, T1518.001
  security-sensor health, T1654 sign-in/alert telemetry) are escalated `medium` → `high`: the
  defender's-own-detection map has outsized evasion value — it tells an adversary *what to evade*,
  not just who or what exists — so it belongs in the high band alongside credential/token material
  and control bypass (§2 high test, §4 decision-table row 3). This is **no longer deferred**. The
  escalator is scoped **precisely to the defensive-evasion map** (§3 D=2 sub-case (b)); directory/
  identity target lists (§3 sub-case (a): T1087.004, T1069.003, T1082, T1213.002, T1033) and the
  data-classification taxonomy (§3 sub-case (c): T1580) are **not** escalated and remain `medium`.
  Adopting it cascaded, as anticipated, across the three finding records (both their R011 and R013
  triage records — six in total), their finding-to-control mappings, `docs/findings-report-r011.md`,
  and the `docs/phs-security-roi-model-v0.1.md` §6 bridge, each with a dated footnote per the T1580
  reconciliation precedent (§5.2).
- **Severity is not confidence.** Keep them independent in the record; the gate (§4) is the
  only coupling. Do not lower `severity` to express doubt — lower `confidence` and let the
  gate act.

---

## 7. Change log

| Version | Date | Change |
|---|---|---|
| v0.1 | 2026-08-27 | Initial rubric. Five severity levels with objective tests; P/B/D scoring dimensions; decision table + confidence/evidence gate; five retroactive worked examples against `samples/finding-triage/` (one genuine divergence flagged: T1580 low → rubric medium). Calibrated against the S4 W16 finding corpus. |
| v0.1 | 2026-08-27 | Acted on the §5.2 divergence: re-triaged `t1580-r011-purview-labels` from `low` to `medium` (triage_status `open` → `reviewed`). Worked-example agreement now 5/5; §5.2/§6 and the worked-example table updated to reflect the resolution. |
| v0.2 | 2026-08-29 | Codified the `D = 1` vs `D = 2` boundary (§3 anchor: a Collection-steering data-classification taxonomy is `D = 2`; pure environmental/infra config is `D = 1`), resolving the ambiguity that produced the T1580 case and moving "classification taxonomy" out of the `D = 1` cell. Evaluated the defensive-evasion escalator (T1526/T1518.001/T1654 → high) and **did not adopt it** — deferred to a PM decision because it cascades into a multi-finding re-triage (§6). Filename slug kept at `-v0.1` for link stability. |
| **v1.0** | 2026-09-10 | **Rubric locked.** (1) Tied to **CIS Controls v8** (§2 framework cross-reference) — one CIS anchor per severity level, tied to the P/B/D dimensions; reasoning stated for CIS over Microsoft Secure Score. (2) **Adopted the defensive-evasion escalator** (PM decision, S5 W18): the `D = 2` defensive-evasion map (§3 sub-case (b)) now routes to **high** via new decision-table row 3; §2 high/medium tests and §5.4 updated. T1526, T1518.001, and T1654 re-triaged `medium` → `high` across their R011 **and** R013 finding-triage records (six total), their finding-to-control mappings, `docs/findings-report-r011.md`, and the `docs/phs-security-roi-model-v0.1.md` §6 bridge, each with a dated footnote per the T1580 precedent. Scoped precisely to those three techniques; no other severity changed. Filename slug kept at `-v0.1` for link stability. |

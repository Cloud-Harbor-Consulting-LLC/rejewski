# Security ROI Business Case Model (v0.1)

- **Status:** v0.1
- **Pillar:** 2 — Security ROI and Business Case
- **Backlog item:** B011 Pillar 2 Security ROI Sprint Build — Business Case Model
- **Owner:** Derek Morgan (Cloud Harbor Consulting)
- **Grounded in:** docs/phs-security-roi-baseline-v0.1.md (all figures sourced there)

---

## 1. Purpose and scope

This is the Pillar 2 business case model — the document that turns the Security ROI
baseline into a worked example a practitioner can bring to a CISO conversation. Every
figure it uses is drawn from `docs/phs-security-roi-baseline-v0.1.md` §4 (the assumption
table) with its confidence band and vendor-bias flags carried through; this document adds
no new benchmarks, it *applies* them. It is written for reuse in sprint-review readouts,
blog posts, and future speaking content. The reference population is US mid-market —
500–1,000 employees on Microsoft 365 E5 — which is Rejewski's commercial TAM. This is a
narrative-plus-structured-data model, not a CFO spreadsheet: it shows the shape of the
value and the provenance of every number, not a precise per-engagement dollar return.

---

## 2. Scenario definition

A single representative scenario is used throughout the model. Every figure cites its
source and confidence band from `phs-security-roi-baseline-v0.1.md` §4.

| Parameter | Value | Confidence | Source (baseline §4 row) |
|---|---|---|---|
| Organization size | 750 employees | — | Representative US mid-market (500–1,000) |
| M365 license | E5 | — | Assumed; required for full Defender XDR + Entra ID P2 stack |
| Breach cost reference | $3.31M (median) | **MODERATE** | IBM CODB 2024 — US mid-market (500–1,000 employees) |
| Credential-driven breach share | 22% | **HIGH** | Verizon DBIR 2025 — credential-driven breach share (initial action) |
| Mean time to identify (broad population) | 194 days | **HIGH** | IBM CODB 2024 — MTTI |
| Mandiant dwell time (IR-engaged) | 11 days | **HIGH** (Mandiant population) | M-Trends 2025 — median dwell |
| AI + automation savings (extensive) | $1.9M | **HIGH** | IBM CODB 2025 — AI + automation extensive-deployment savings |

Note on the breach-cost anchor: the mid-market $3.31M row is **MODERATE** confidence
(single-vintage, IBM CODB 2024), not HIGH — the model uses it as the mid-market anchor
but does not treat it as a replicated figure. Per baseline §6, the $1.9M AI-savings figure
is the current 2025 baseline (the 2024 report published $1.88M / $2.20M / $2.22M under
different framings).

---

## 3. Credential attack exposure

**What does a credential-driven breach cost this scenario tenant?**

- Expected credential breach cost = breach cost × credential-driven share
- **$3.31M × 22% = ~$728K** expected credential-breach exposure for a 750-employee
  mid-market E5 tenant.
  - $3.31M — IBM CODB 2024, US mid-market median (**MODERATE**, baseline §4).
  - 22% — Verizon DBIR 2025, credential-driven breach share (**HIGH**, baseline §4).

**The exposure window.** The stolen-credential breach lifecycle is **292 days** (IBM CODB
2024, a **MODERATE** single-source figure used as a *proxy* for credential-theft MTTR —
no source reports credential-theft MTTR as its own metric; baseline §4 and gap #4).
Against that, Mandiant's IR-engaged median dwell time is **11 days** (M-Trends 2025,
**HIGH** within the Mandiant population). The **281-day delta (292 − 11)** is the surface
area where a competent adversary operates undetected in most organizations but a
top-tier IR capability does not — and it is exactly the window Rejewski's deterministic
adversary emulation maps.

**Why 292/194 days and 11 days are not contradictory** (baseline §5 reconciliation): the
IBM figures are computed across a broad population (misconfigurations, insider events,
self-discovered compromises); the Mandiant 11-day figure is computed across IR
engagements that skew toward larger, externally-notified intrusions where a top-tier IR
firm was engaged. Mandiant 11 days is the *"what a competent adversary actually
achieves"* baseline; IBM 194/292 days is the *"what most organizations actually detect
at"* baseline. Averaging them would hide the business case; the baseline keeps them
separate by design, and so does this model.

---

## 4. Control effectiveness

MFA is the primary lever against the credential-driven share.

- **99.2% MFA block rate against automated attacks** (**HIGH** confidence, baseline §4).
  - **Vendor-bias disclosure:** the 99.2% figure is **Microsoft-published** (Microsoft
    Entra). It is rated HIGH because it has *independent corroboration*: Google's 2019
    account-takeover research reported a **>99% block rate for device-based 2FA**
    (baseline §7). The direction of the two vendors' incentives differs, which is why
    the figure survives triangulation.
- Applied to the 22% credential-driven share: MFA blocks ~99.2% of those automated
  credential attacks at the authentication boundary.
- **Residual risk: ~0.8% of credential-driven attacks** get past MFA to reach the
  post-authentication discovery phase.
- **Rejewski emulates that residual 0.8%** — the attack surface that survives a correctly
  deployed MFA control and is therefore invisible to a "we deployed MFA" posture.

The point of §4 is not that MFA is weak — it is that MFA is ~99.2% effective and the
business question is *what happens in the 0.8%*. That residual is where §5 and §6 live.

---

## 5. Rejewski positioning — where adversary emulation fits

What Rejewski adds beyond "deploy MFA":

- **MFA licensing cost:** $3–$6 per user per month (**LOW** confidence — vendor pricing
  only, no primary research; baseline §4 and gap #5). At 750 users that is
  **~$27K–$54K/year** (750 × $3–$6 × 12).
- **Defender XDR ROI:** Forrester Total Economic Impact study **commissioned by
  Microsoft** reports **242% 3-year ROI** (**MODERATE**, vendor-commissioned; baseline §4).
  *Disclosure required and made:* this is a Microsoft-commissioned Forrester TEI —
  small selected-customer sample, composite-organization method, optimistic benefit
  realization (baseline §7).
- **The residual-surface problem:** MFA licensing and Defender XDR both address the ~99.2%.
  They do not tell you what survives. Rejewski enumerates the residual 0.8% — specifically
  the techniques that get through a valid MFA posture: **T1550.001** (application-access-token
  reuse — a replayed token needs no fresh MFA challenge) and **T1078.004** ROPC against
  legacy-auth endpoints (a flow that can bypass interactive MFA where CA does not enforce it).
- **The business case in one line:** without adversary emulation, the residual post-MFA
  attack surface is *unknown*. With Rejewski, it is *enumerated, evidenced (replay-log),
  and mapped to specific controls* — the difference between "we deployed MFA" and "here is
  what still gets through, and here is the control that closes it."

---

## 6. Findings-to-ROI bridge

Each R011 finding (docs/findings-report-r011.md) mapped to its control and its risk
category. **"Potential cost avoided" assigns no dollar figure** — it maps the finding to
the relevant baseline risk category and states the direction of the risk. Assigning a
specific dollar avoided per finding would fabricate precision the data does not support
(writing rules; baseline confidence bands).

| Technique | Severity | Control mapped | Risk category | Potential cost avoided (direction) |
|---|---|---|---|---|
| T1078.004 | informational | CA-SIG003-Guests-RequireMFA | Initial access / valid accounts | Reduces the entry path that precedes the $728K credential-breach exposure (§3); guest-MFA closes the ROPC/legacy-auth gap (§5) |
| T1087.004 | medium | CA-COV008-BlockByLocation | Account enumeration | Shrinks the phishing/targeting surface an adversary builds from a user directory |
| T1069.003 | medium | CA-SIF001-SignInFrequency-8h | Group / privilege enumeration | Caps stolen-token lifetime, narrowing the 281-day exposure window (§3) |
| T1550.001 | **high** | Directory Readers (RBAC) | Credential / token theft | Fraction of the $728K credential-breach exposure (§3); token reuse is the residual-0.8% path that survives MFA (§4–§5) |
| T1526 | medium | Reports Reader (RBAC) | CA-policy exposure | Least-privilege on policy reads limits an adversary's map of where MFA/CA coverage is thin |
| T1518.001 | medium | Security Reader (RBAC) | Detection-coverage gap | Restricts who can read DfI sensor health — the map of where detection is degraded |
| T1082 | medium | Intune Service Administrator (RBAC) | Endpoint targeting | Limits enumeration of non-compliant/unencrypted devices — the soft lateral-movement targets |
| T1580 | low | CA-PUR-001-RequireCompliantApp | Data-classification exposure | Restricts label-inventory reads that would steer later Collection toward Confidential data |
| T1654 | medium | Reports Reader (RBAC) | Security-log exposure | Least-privilege on sign-in/alert logs denies the adversary the defender's own detection baseline |

Reading the bridge: the **T1550.001 (High)** finding is the one that ties most directly to
the §3 dollar figure — token reuse is precisely the residual-0.8% credential-theft path
that survives MFA — and its control (least-privilege on Directory Readers) reduces the
blast radius of a replayed token. The rest map to *direction of risk*, not dollars.

---

## 7. Limitations and honest gaps

Carried over from `phs-security-roi-baseline-v0.1.md` §8 where they affect this model:

- **IBM 2025 PDF body not retrieved** (gap #1). The US mid-market anchor here is the 2024
  figure ($3.31M); the 2025 mid-market segment split may differ. The $3.31M row is
  MODERATE confidence for that reason.
- **Gartner SOC alert-volume figures are paywalled** (gap #3). Any SOC alert-load framing
  in downstream versions of this model rests on the 30–40 alerts/analyst/shift *planning
  assumption* (LOW confidence, vendor consensus, not research).
- **MFA deployment cost has no primary research source** (gap #5). The $27K–$54K/year in §5
  is built from vendor list pricing only (LOW confidence); it is an order-of-magnitude
  figure, not a defensible TCO.
- **Tines Voice of the SOC 2023 data is approaching 3 years old** (gap #6). Not used
  numerically in this v0.1 model, but flagged for any future SOC-efficiency extension.

Additionally: the **292-day stolen-credential lifecycle is a proxy** for credential-theft
MTTR, not a direct measurement (baseline gap #4), and the **242% Forrester TEI is
vendor-commissioned** (baseline §7). Both are used above with those flags attached.

---

## 8. Cross-references

- docs/phs-security-roi-baseline-v0.1.md — all figures sourced here (§4 assumption table,
  §5 dwell-time reconciliation, §6 AI-savings reconciliation, §7 bias flags, §8 gaps).
- docs/phs-zt-scenarios-v0.1.md — Zero Trust scenario complements (Pillar 1); the $1.76M
  ZT-savings anchor and the device-compliance / identity-verification scenarios.
- docs/findings-report-r011.md — the nine R011 findings with control mappings; the
  empirical inputs to §6.
- docs/attck-coverage.md — technique coverage (what Rejewski has actually emulated).

---

## 9. Change log

| Version | Date | Change |
|---|---|---|
| v0.1 | 2026-08-15 | Initial model. Scenario: 750-employee mid-market M365 E5. Sources: IBM CODB 2024/2025, Verizon DBIR 2025, M-Trends 2025, Microsoft MFA research. |

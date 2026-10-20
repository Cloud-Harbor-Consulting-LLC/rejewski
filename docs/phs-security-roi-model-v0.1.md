# Security ROI Business Case Model (v0.1)

- **Status:** v0.2 (2026-10-12; file path kept at `-v0.1.md` because `scripts/generate_html_report.py` reads it by path)
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
| Breach cost reference (context only) | $4.99M (global average) | **HIGH** | IBM CODB 2026 — global average, up 12%, a record |
| Leading initial access vector | Exploitation of vulnerabilities, 31% of breaches, ahead of credential abuse | **HIGH** | Verizon DBIR 2026 |
| Mandiant dwell time (IR-engaged) | 14 days (up from 11) | **HIGH** (Mandiant population) | M-Trends 2026 — global median dwell |
| Exploits as initial infection vector (IR-engaged) | 32% of intrusions | **HIGH** (Mandiant population) | M-Trends 2026 |
| MFA block rate | >99.2% of account compromise attacks | **HIGH** (vendor-published, corroborated) | Microsoft Learn, mandatory MFA page (updated 2026-10-06) |
| AI + automation savings (extensive) | $1.9M | **HIGH** (2025 vintage, not refreshed) | IBM CODB 2025 — AI + automation extensive-deployment savings |

Note on the v0.2 refresh: every row above except the AI-savings row was re-verified against
its primary source on 2026-10-12 (baseline §4a). v0.1 used a US mid-market breach cost
($3.31M, IBM CODB 2024), a 22% credential-driven breach share (Verizon DBIR 2025), and IBM
2024 time-to-identify and stolen-credential lifecycle figures. Those rows are retired from the
scenario: the 2026 DBIR reversed the credential and vulnerability ranking, and the 2026
equivalents of the other figures were found only in secondary sources. The $1.9M AI-savings
figure is the 2025 baseline (baseline §6) and is not used in any finding's ROI line.

---

## 3. Breach exposure

**What does a breach cost, and why does this model not compute a credential-specific dollar
figure?**

- IBM CODB 2026 puts the global average breach at **$4.99M** (**HIGH**, baseline §4a). The
  model cites it as context for the size of the problem. It does not multiply it by any share.
- v0.1 computed **$3.31M × 22% = ~$728K** as an expected credential-breach exposure. v0.2
  retires that figure. Both inputs are superseded: the 2026 DBIR puts exploitation of
  vulnerabilities (31%) ahead of credential abuse as the leading initial access vector, and a
  2026 credential share and a 2026 US mid-market cost were found only in secondary sources.
  A product of an unconfirmed share and an unconfirmed segment cost would be false precision.
- Consequence for §6: no finding's ROI line carries a dollar figure, including T1550.001,
  which v0.1 expressed as a fraction of the $728K.

**The exposure window.** Mandiant's IR-engaged global median dwell time is **14 days**,
up from 11 (M-Trends 2026, **HIGH** within the Mandiant population). That is the time a
foothold account has to read the tenant before containment, and it is the phase Rejewski
emulates. v0.1 set this against IBM's 292-day stolen-credential lifecycle (2024) to derive a
281-day window. v0.2 retires that delta because the 2026 IBM lifecycle figure was confirmed
only in secondary sources.

**Population note** (baseline §5 reconciliation, still valid): Mandiant figures come from
IR engagements, which skew toward larger, externally notified intrusions. IBM lifecycle
figures cover a broader population. The two measure different things and are not averaged.

---

## 4. Control effectiveness

MFA is the primary lever against the credential-driven share.

- **MFA blocks more than 99.2% of account compromise attacks** (Microsoft Learn, mandatory
  MFA page, updated 2026-10-06; **HIGH** confidence, baseline §4a).
  - **Vendor-bias disclosure:** the 99.2% figure is **Microsoft-published** (Microsoft
    Entra). It is rated HIGH because it has *independent corroboration*: Google's 2019
    account-takeover research reported a **>99% block rate for device-based 2FA**
    (baseline §7). The direction of the two vendors' incentives differs, which is why
    the figure survives triangulation.
- Applied to credential-based entry: MFA stops more than 99.2% of those attacks at the
  authentication boundary.
- **Residual risk: under 0.8% of credential-based attacks** get past MFA to reach the
  post-authentication discovery phase.
- **A second path MFA does not address:** the 2026 DBIR puts exploitation of
  vulnerabilities (31%) ahead of credential abuse as the leading initial access vector, and
  M-Trends 2026 puts exploits at 32% of intrusions. Either path ends with a foothold account
  inside the tenant.
- **Rejewski emulates what that foothold account can read**, whichever path produced it.
  That surface is invisible to a "we deployed MFA" posture.

The point of §4 is not that MFA is weak — it is that MFA is ~99.2% effective and the
business question is *what a foothold account can read once it is inside*. That is where
§5 and §6 live.

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

Each finding mapped to its control and its risk category. The original nine rows are the
R011 sweep (docs/findings-report-r011.md); the last two — **T1213.002** and **T1033** —
are later-evidenced techniques (R013 and R012 respectively) folded into the same bridge so
every implemented, triaged technique has an ROI line. **"Potential cost avoided" assigns no
dollar figure** — it maps the finding to the relevant baseline risk category and states the
direction of the risk. Assigning a specific dollar avoided per finding would fabricate
precision the data does not support (writing rules; baseline confidence bands). v0.2 has no
exceptions. v0.1 expressed **T1550.001** as a fraction of the §3 $728K figure; that figure is
retired (§3), and T1550.001 now states a direction of risk like every other row.

| Technique | Severity | Control mapped | Risk category | Potential cost avoided (direction) |
|---|---|---|---|---|
| T1078.004 | high [§] | CA-RequireMFA-AllUsers | Initial access / valid accounts | Reduces the credential entry path into the tenant; MFA for all users closes the ROPC gap, since ROPC cannot satisfy MFA (§5) |
| T1087.004 | medium | CA-COV008-BlockByLocation | Account enumeration | Shrinks the phishing/targeting surface an adversary builds from a user directory |
| T1069.003 | medium | CA-SIF001-SignInFrequency-8h | Group / privilege enumeration | Caps stolen-token lifetime, shortening the time a foothold account has to read the tenant (§3: 14-day median dwell) |
| T1550.001 | **high** | Directory Readers (RBAC) | Credential / token theft | Token reuse is the residual path that survives MFA (§4–§5); least-privilege on directory reads limits what a replayed token can see |
| T1526 | high [‡] | CA policy read roles (RBAC) | CA-policy exposure | Least-privilege on policy reads limits an adversary's map of where MFA/CA coverage is thin |
| T1518.001 | high [‡] | Security Reader (RBAC) | Detection-coverage gap | Restricts who can read DfI sensor health — the map of where detection is degraded |
| T1082 | medium | Intune Service Administrator (RBAC) | Endpoint targeting | Limits enumeration of non-compliant/unencrypted devices — the soft lateral-movement targets |
| T1580 | medium [†] | CA-PUR-001-RequireCompliantApp | Data-classification exposure | Restricts label-inventory reads that would steer later Collection toward Confidential data |
| T1654 | high [‡] | Reports Reader (RBAC) | Security-log exposure | Least-privilege on sign-in/alert logs denies the adversary the defender's own detection baseline |
| T1213.002 | medium | CA-SPO-001-RequireCompliantApp | Information-repository exposure | Restricts the SharePoint site inventory that steers later Collection toward business-sensitive repositories (HR, Legal, Finance); a compliant-app CA policy blocks the unmanaged-host token path at the authorization boundary |
| T1033 | medium | PIM-EligibleRoleAssignments | Privileged-account enumeration | Shrinks the standing set of Global Admin / Privileged Role Administrator holders an adversary can discover as always-on escalation targets; JIT eligibility makes each activation an auditable, time-bound event |

Reading the bridge: the **T1550.001 (High)** finding ties most directly to §4. Token reuse
is the residual credential path that survives MFA, and its control (least-privilege on
Directory Readers) reduces the blast radius of a replayed token. Every row maps to
*direction of risk*; none carries a dollar figure.

> **[†] Note (2026-08-29):** T1580 severity updated `low` → `medium` per
> `docs/finding-severity-rubric-v0.1.md` (the label taxonomy is a Collection-targeting map,
> D=2). The bridge's *direction of risk* for T1580 is unchanged; only the severity level is
> refined. See §9.
>
> **[§] Note (2026-10-20):** T1078.004 severity `informational` → `high` and control `CA-SIG003-Guests-RequireMFA` →
> `CA-RequireMFA-AllUsers`. R017 is the first run to evidence the technique (a member account's password alone got a
> token through ROPC), which rubric v1.0 rates high (D=3); the guest-only policy does not cover member accounts.
> Direction of risk unchanged in substance.
>
> **[‡] Note (2026-09-10):** T1526, T1518.001, and T1654 severity updated `medium` → `high`
> per `docs/finding-severity-rubric-v0.1.md` **v1.0**, which adopted the defensive-evasion
> escalator (PM decision, S5 W18): a finding that maps the tenant's own detection posture
> (CA-policy coverage, security-sensor health, or sign-in/alert telemetry) routes to `high`.
> The bridge's *direction of risk* for all three is unchanged; only the severity level is
> refined. See §9.

---

## 7. Limitations and honest gaps

Carried over from `phs-security-roi-baseline-v0.1.md` §8 where they affect this model:

- **IBM 2026 segment splits and lifecycle figures not confirmed from a primary source**
  (baseline gap #10). v0.2 therefore uses only the 2026 global average, as context, and
  computes no segment-specific or credential-specific dollar exposure.
- **2026 credential-abuse share not confirmed from a primary source** (baseline gap #11).
  The 2026 DBIR ranking (vulnerability exploitation ahead of credential abuse) is primary;
  the credential percentage is not used.
- **Gartner SOC alert-volume figures are paywalled** (gap #3). Any SOC alert-load framing
  in downstream versions of this model rests on the 30–40 alerts/analyst/shift *planning
  assumption* (LOW confidence, vendor consensus, not research).
- **MFA deployment cost has no primary research source** (gap #5). The $27K–$54K/year in §5
  is built from vendor list pricing only (LOW confidence); it is an order-of-magnitude
  figure, not a defensible TCO.
- **Tines Voice of the SOC 2023 data is approaching 3 years old** (gap #6). Not used
  numerically in this v0.1 model, but flagged for any future SOC-efficiency extension.

Additionally: the **242% Forrester TEI is vendor-commissioned** (baseline §7) and is used
above with that flag attached. The 292-day stolen-credential lifecycle (baseline gap #4) is
no longer used.

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
| v0.1 | 2026-08-29 | §6 findings-to-ROI bridge: T1580 severity `low` → `medium` per `docs/finding-severity-rubric-v0.1.md` (re-triage). Direction of risk unchanged; no figures affected. |
| v0.1 | 2026-09-08 | §6 bridge extended with two later-evidenced techniques — **T1213.002** (CA-SPO-001-RequireCompliantApp, evidenced R013) and **T1033** (PIM-EligibleRoleAssignments, evidenced R012) — same style/rigor as the original nine, direction-of-risk only, no dollar figure. This is the grounding table consumed by the S5 W18 ROI section in `scripts/generate_html_report.py`. No baseline figures added or changed. |
| v0.2 | 2026-10-12 | Refresh to 2026 primary sources (B032). §2 scenario: IBM CODB 2026 global average ($4.99M, context only), Verizon DBIR 2026 (vulnerability exploitation 31%, ahead of credential abuse), M-Trends 2026 (14-day median dwell, exploits 32%), Microsoft Learn (>99.2% MFA). Retired: the §3 $728K credential-exposure figure (US mid-market $3.31M × DBIR 2025 22%), the 281-day window, and the 194-day MTTI row. §6: T1550.001, T1078.004, and T1069.003 direction cells no longer cite $728K or 281 days; no row carries a dollar figure. T1526 control column corrected in B033 (2026-10-12). |
| v0.1 | 2026-09-10 | §6 bridge: T1526, T1518.001, and T1654 severity `medium` → `high` [‡] per `docs/finding-severity-rubric-v0.1.md` **v1.0** (defensive-evasion escalator adopted; PM decision, S5 W18). Direction of risk unchanged for all three; only the severity column is refined. No figures affected. |

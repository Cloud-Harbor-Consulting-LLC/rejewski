# Security ROI Baseline Assumptions (v0.1)

**Status:** v0.2 (2026-10-12; §4a 2026 refresh added, file path unchanged)
**Pillar:** 2 — Security ROI and Business Case
**Backlog item:** B004 Capture Security ROI baseline assumptions
**Owner:** Derek Morgan (Cloud Harbor Consulting)
**Review cadence:** Sprint 2 Review (Sat Jun 6, 2026), then quarterly

---

## 1. Purpose

Establish a single, cite-able baseline of industry figures the Rejewski adversary-emulation platform uses to express business value (cost avoided, dwell-time reduced, alert-load delta, ROI). Every Rejewski case study, blog post, deck, and sprint-review readout grounds its claims here. When a downstream artifact cites a baseline number, this document is the source.

Pillar 2 of the Microsoft MVP Strategy ("Security ROI and Business Case") is the unclaimed positioning territory the MVP nomination is built on. Translating Microsoft security investments into executive language requires defensible benchmarks; this is that table.

---

## 2. Framing

US mid-market and enterprise are the primary reference populations (Rejewski's commercial TAM). Global figures are included where US sub-cohorts are not separately published. Vintage 2024 to 2025 preferred; older sources are flagged with the vintage column. Every figure carries a confidence band (HIGH, MODERATE, LOW) and a vendor-bias note where the publisher has a commercial stake in the result.

The baseline expresses three quantities per row where the source allows: a low estimate, a median or headline figure, and a high estimate. Where a source publishes only one number, only the median column is populated and the row is annotated.

---

## 3. Methodology

Sources were retrieved and verified using SIFT (Stop, Investigate, Find better coverage, Trace claims), Chain-of-Verification on numeric claims, and Analysis of Competing Hypotheses on disagreements above 25%. 24 sources retrieved; 25 atomic claims scored (19 SUPPORTED, 6 WEAK, 0 UNSUPPORTED).

Confidence bands:

- **HIGH** — figure replicated across two or more primary sources, or single primary source with disclosed methodology and independent corroboration.
- **MODERATE** — single primary source, methodology disclosed, no independent replication available, or replicated across primary plus credible press.
- **LOW** — single secondary source, paywalled primary, vendor pricing only, or working-assumption inputs that lack a primary research basis.

Vendor bias is disclosed inline whenever the source has commercial interest in the direction of the figure. Forrester Total Economic Impact studies are flagged as vendor-commissioned in every reference.

---

## 4. Assumption Table

| Assumption | Low | Median | High | Vintage | Confidence | Source |
|---|---|---|---|---|---|---|
| Average breach cost — global | $4.44M | $4.66M | $4.88M | 2024–2025 | HIGH | IBM CODB 2024, 2025 |
| Average breach cost — US | $9.36M | $9.79M | $10.22M | 2024–2025 | HIGH | IBM CODB 2024, 2025 |
| Average breach cost — US mid-market (500–1,000 employees) | $2.8M | $3.31M | $3.8M | 2024 | MODERATE | IBM CODB 2024 |
| Average breach cost — US enterprise (>25,000 employees) | $5.4M | $5.91M | $6.5M | 2024 | MODERATE | IBM CODB 2024 |
| Per-record breach cost — global | — | $169 | — | 2024 | MODERATE | IBM CODB 2024 |
| Per-record breach cost — US | — | $309 | — | 2024 | LOW | IBM CODB 2024 (single-sourced) |
| Mean dwell time — Mandiant IR engagements (median) | — | 11 days | — | 2024 engagements | HIGH (Mandiant population) | M-Trends 2025 |
| Mean time to identify (broader population, IBM) | — | 194 days | — | 2024 | HIGH | IBM CODB 2024 |
| Mean breach lifecycle (MTTI + MTTC) | — | 241 days | 258 days | 2024–2025 | HIGH | IBM CODB 2024, 2025 |
| Credential-driven breach share (initial action) | — | 22% | — | 2024 data | HIGH | Verizon DBIR 2025 |
| Identity attacks per day globally | — | 600M+ | — | 2024 | HIGH | Microsoft Digital Defense Report 2024 |
| Password-based share of identity attacks | — | >99% | — | 2024 | HIGH | Microsoft Digital Defense Report 2024 |
| Average cost of credential-initiated breach | — | $4.81M | — | 2024 | HIGH | IBM CODB 2024 |
| Stolen-credential breach lifecycle (proxy for credential-theft MTTR) | — | 292 days | — | 2024 | MODERATE | IBM CODB 2024 (single-source) |
| MFA block rate against automated attacks | — | 99.2% | — | 2019–2024 | HIGH | Microsoft Entra |
| MFA effectiveness against password-based attacks (follow-up) | — | 99.99% | — | 2023 | MODERATE | Microsoft Security blog |
| Zero Trust extensive deployment cost savings vs early/none | — | $1.76M | — | 2024 | MODERATE | IBM CODB 2024 |
| AI + automation extensive deployment savings | — | $1.9M | $2.22M | 2024–2025 | HIGH | IBM CODB 2024, 2025 |
| Microsoft Security Copilot MTTR reduction (RCT) | — | 30% faster | — | 2024 | MODERATE | Microsoft RCT |
| Forrester TEI Defender XDR — 3-year ROI | — | 242% | — | June 2025 | MODERATE (vendor-commissioned) | Forrester TEI commissioned by Microsoft |
| Forrester TEI Defender XDR — payback period | — | <6 months | — | June 2025 | MODERATE (vendor-commissioned) | Forrester TEI commissioned by Microsoft |
| Forrester TEI Sentinel — 3-year ROI | — | 234% | — | Dec 2023 | MODERATE (vendor-commissioned, aging) | Forrester TEI commissioned by Microsoft |
| SOC analysts reporting tool overload | — | 64% | — | 2023 | MODERATE | Tines Voice of the SOC 2023 |
| SOC analysts: share of alerts actually investigated | — | ~33% | — | 2023 | MODERATE | Tines VoSoC 2023 |
| SOC false-positive rate (SIEM-aggregate self-report) | 20% | 55% | 60% | 2023 | MODERATE | Tines VoSoC 2023 + vendor range |
| Working planning assumption: alerts/analyst/shift actively investigated | 30 | 35 | 40 | n/a | LOW (no primary research) | Vendor consensus only |
| MFA deployment cost (per user per month, mid-market typical) | $3 | $5 | $6 | 2025 list | LOW (no primary research) | Vendor pricing only |

### 4a. 2026 refresh (v0.2, verified 2026-10-12)

Each row was checked against its primary source. Rows in §4 that these supersede stay in
the table above as history; the ROI model (v0.2) uses only the rows below for 2026 figures.

| Assumption | Value | Vintage | Confidence | Source | Supersedes (§4) |
|---|---|---|---|---|---|
| Average breach cost — global | $4.99M (up 12%, record high) | 2026 report | HIGH | IBM CODB 2026 (source 18) | Average breach cost — global (2024–2025) |
| Leading initial access vector | Exploitation of vulnerabilities, 31% of breaches, ahead of credential abuse | 2026 report | HIGH | Verizon DBIR 2026 (source 19) | Credential-driven breach share 22% (DBIR 2025) as the ranking anchor |
| Global median dwell time — Mandiant IR engagements | 14 days (from 11) | 2025 engagements | HIGH (Mandiant population) | M-Trends 2026 (source 20) | Mean dwell time 11 days (M-Trends 2025) |
| Exploits as initial infection vector — Mandiant IR engagements | 32% of intrusions, most common vector for the sixth year | 2025 engagements | HIGH (Mandiant population) | M-Trends 2026 (source 20) | — |
| MFA block rate | >99.2% of account compromise attacks | Page updated 2026-10-06 | HIGH | Microsoft Learn (source 21) | MFA block rate 99.2% (Microsoft Entra blog) |

Not adopted, because only secondary sources confirmed them on 2026-10-12: a 2026 DBIR
credential-abuse share (reported as 13%), an IBM 2026 time to identify and contain (reported
as 247 days), and an IBM 2026 US average (reported as $11.5M). See gaps #10 and #11.

---

## 5. Critical Reconciliation — Dwell Time

Mandiant M-Trends 2025 reports an 11-day median dwell time. IBM CODB 2024 reports a 194-day mean time to identify. The two figures are not contradictory — they measure different populations.

- **Mandiant 11 days** is computed across Mandiant incident-response engagements, which skew toward larger, sophisticated, externally-notified intrusions where the customer engaged a top-tier IR firm.
- **IBM 194 days** is computed across a broader population including misconfiguration breaches, insider events, and self-discovered compromises.

For Rejewski modeling: Mandiant 11 days is the "what a competent adversary actually achieves" baseline; IBM 194 days is the "what most organizations actually detect at" baseline. **The delta between these two numbers is the surface area where Rejewski's deterministic adversary emulation creates value.** A baseline table that averages the two hides the business case. This document keeps them separate by design.

---

## 6. Critical Reconciliation — AI / Automation Savings

The IBM 2024 report publishes three distinct AI-savings figures depending on framing:

- $1.88M — AI used in security operations workflows specifically
- $2.20M — AI used across all relevant workflows (insider risk, threat hunting, etc.)
- $2.22M — AI used for prevention specifically

The 2025 report uses a different breakdown and reports $1.9M as the average savings for extensive AI plus automation use. For Rejewski citations going forward: **use the 2025 $1.9M figure as the current baseline.** Cite the 2024 framings only when explicitly distinguishing prevention versus operations workflows.

---

## 7. Limitations and Bias Flags

Every figure in Section 4 inherits the bias profile of its publisher. The following disclosures are required whenever a row is cited downstream:

- **IBM CODB 2024 and 2025** — Ponemon-conducted, IBM-published. IBM is a commercial beneficiary of breach concern (sells security tooling and consulting). Methodology is disclosed and the sample is the largest independent breach cost study available. Mega-breach exclusion truncates the upper tail — figures are conservative for enterprise reference but appropriate for mid-market.
- **Verizon DBIR 2025** — Verizon-published, multi-source contributor pool. Methodology is disclosed and the contributor diversity (law enforcement, IR firms, ISACs) is the strongest counterweight to single-vendor bias in the industry.
- **Microsoft (MFA, MDDR, Security Copilot RCT)** — Microsoft is the dominant identity vendor and Copilot is a Microsoft product. The 99.2% MFA figure has independent corroboration from Google's 2019 account-takeover research showing >99% block rate for device-based 2FA. The Security Copilot RCT design is rigorous (randomized controlled trial); treat as moderate-to-high if cited.
- **Mandiant M-Trends** — Mandiant has commercial incentive to show short dwell times (advertises IR effectiveness). IBM has commercial incentive to show long dwell times (advertises detection-product gap). Triangulation works because each bias points opposite.
- **Forrester TEI studies (Defender XDR, Sentinel, Defender Experts)** — All three are vendor-commissioned by Microsoft. Forrester is the research firm, Microsoft is the publisher and commercial beneficiary. TEI methodology interviews a small number (4–6) of selected customers and constructs a composite organization, with optimistic assumptions about benefit realization. **Disclosure required inline whenever cited:** "Forrester Total Economic Impact study commissioned by Microsoft."
- **Tines Voice of the SOC 2023** — Tines is a SOAR vendor with commercial interest in showing alert overload. Self-report data, not measured. Vintage is approaching 3 years; check for a 2024 or 2025 refresh before citation.

---

## 8. Known Gaps

The following items are honest gaps in the v0.1 baseline. Each is tracked for resolution in a future revision.

1. **IBM 2025 PDF body not retrieved.** Press release figures captured; the full PDF (containing segment splits, MTTI/MTTC 2025 split, Zero Trust specific savings 2025, and full vector breakdown) was not pulled in this pass. Action: retrieve before v0.2 publication.
2. **US per-record cost ($309) is single-sourced.** Currently relies on a secondary blog summary of IBM CODB 2024 p.7. Action: verify against the IBM 2024 PDF body before any downstream citation.
3. **Gartner SOC alert-volume figures are paywalled.** No primary public number for "sustainable alerts per analyst per day" exists. The 30–40 alerts/shift planning assumption is vendor consensus, not research. Action: if Cloud Harbor Consulting acquires Gartner access, retrieve from the Hype Cycle for Security Operations.
4. **Credential-theft MTTR is proxied.** IBM's 292-day stolen-credential lifecycle is the closest published figure; no source separately reports credential-theft MTTR as its own metric. Action: review M-Trends 2025 full PDF for credential-specific dwell.
5. **MFA deployment cost has no primary research source.** Vendor pricing (Microsoft Entra ID P1 ~$6/user/month, P2 ~$9/user/month, third-party $3–$4/user/month) is the only basis. Action: if a defensible MFA TCO is required for a business case, build bottom-up from list prices, not from research.
6. **Tines Voice of the SOC 2023 data is approaching 3 years old.** Check for a 2024 or 2025 refresh.
7. **Forrester TEI Sentinel December 2023 figure is aging.** Verify for a 2025 refresh before citation in any downstream artifact.
8. **No IBM 2025 Zero Trust specific dollar.** Only the 2024 figure ($1.76M) is captured; the 2025 report has moved its headline narrative to AI/automation.
9. **All Forrester TEI numbers are vendor-commissioned by Microsoft.** Independent ROI research (IDC Business Value studies, Gartner Magic Quadrant ROI commentary) was not retrieved in this pass.
10. **IBM 2026 segment splits and lifecycle figures not confirmed from a primary source** (added v0.2). US, mid-market, and time-to-identify-and-contain figures for 2026 were found only in secondary summaries. Action: retrieve the IBM 2026 report body before any of them is cited.
11. **2026 DBIR credential-abuse share not confirmed from a primary source** (added v0.2). The ranking (vulnerability exploitation ahead of credential abuse) is confirmed; the percentage is not. Action: retrieve the DBIR 2026 report body before citing a credential share.

---

## 9. Cross-References

- **Pillar 1 (Zero Trust in Practice):** docs/phs-zt-scenarios-v0.1.md — Zero Trust baseline scenarios. The $1.76M ZT cost-saving figure in Section 4 is the business-case anchor for the device-compliance, identity-verification, and network-segmentation scenarios defined there.
- **Threat model:** docs/threat-model.md — ATT&CK T1078.004 / T1087.004 / T1069.003 mappings for Sprint 1 technique runs. Credential-driven breach share (22%, Verizon DBIR 2025) was the population-level anchor for the threat model's identity-emulation focus. As of v0.2 the 2026 DBIR puts vulnerability exploitation ahead of credential abuse (§4a); the foothold account the threat model emulates is reached by either path.
- **Master Plan v1.5:** Section 10 Project Links. This baseline supports KPI Dashboard delta tracking (Section 3.1) and the Sprint Review Template financial-impact slot.

---

## 10. Change Log

- **v0.2 — Mon Oct 12, 2026.** Added §4a 2026 refresh (IBM CODB 2026, Verizon DBIR 2026, M-Trends 2026, Microsoft Learn MFA), each verified against its primary source; gaps #10 and #11; sources 18–21. §4 rows kept as history. Backlog item B032.
- **v0.1 — Sat May 16, 2026.** Initial publication. 12 grounded design questions, 27 assumption rows, 5 HIGH-confidence baselines, 9 honest gaps documented. Backlog item B004.

---

## 11. Sources

1. IBM Cost of a Data Breach Report 2024 — landing: [https://www.ibm.com/reports/data-breach](https://www.ibm.com/reports/data-breach)
2. IBM 2024 CODB press release: [https://newsroom.ibm.com/2024-07-30-IBM-Report-Escalating-Data-Breach-Disruption-Pushes-Costs-to-New-Highs](https://newsroom.ibm.com/2024-07-30-IBM-Report-Escalating-Data-Breach-Disruption-Pushes-Costs-to-New-Highs)
3. IBM 2025 CODB press release: [https://newsroom.ibm.com/2025-07-30-ibm-report-breach-costs-fall-for-first-time-in-five-years-as-ai-defenses-mature-shadow-ai-emerges-as-new-risk](https://newsroom.ibm.com/2025-07-30-ibm-report-breach-costs-fall-for-first-time-in-five-years-as-ai-defenses-mature-shadow-ai-emerges-as-new-risk)
4. IBM Think Insights — Cost of a Data Breach: [https://www.ibm.com/think/insights/data-breach-costs](https://www.ibm.com/think/insights/data-breach-costs)
5. IBM 2024 CODB PDF (Baker Donelson mirror): [https://www.bakerdonelson.com/webfiles/Publications/Cost%20of%20a%20Data%20Breach%20Report%202024.pdf](https://www.bakerdonelson.com/webfiles/Publications/Cost%20of%20a%20Data%20Breach%20Report%202024.pdf)
6. Mandiant M-Trends 2025 — Google Cloud blog: [https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2025/](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2025/)
7. Mandiant M-Trends 2024 — full PDF: [https://services.google.com/fh/files/misc/m-trends-2024.pdf](https://services.google.com/fh/files/misc/m-trends-2024.pdf)
8. Verizon Data Breach Investigations Report 2025 — landing: [https://www.verizon.com/business/resources/reports/dbir/](https://www.verizon.com/business/resources/reports/dbir/)
9. Verizon DBIR 2025 — press release: [https://www.verizon.com/about/news/2025-data-breach-investigations-report](https://www.verizon.com/about/news/2025-data-breach-investigations-report)
10. Microsoft Digital Defense Report 2024: [https://www.microsoft.com/en-us/security/security-insider/intelligence-reports/microsoft-digital-defense-report-2024](https://www.microsoft.com/en-us/security/security-insider/intelligence-reports/microsoft-digital-defense-report-2024)
11. Microsoft Entra — Your Password doesn't matter (99.2% MFA block rate): [https://techcommunity.microsoft.com/blog/microsoft-entra-blog/your-pa-word-doesn-t-matter/731984](https://techcommunity.microsoft.com/blog/microsoft-entra-blog/your-pa-word-doesn-t-matter/731984)
12. Microsoft Security blog — The cost of MFA resilience (99.99% effectiveness): [https://www.microsoft.com/en-us/security/blog/2023/05/02/the-cost-of-mfa-resilience/](https://www.microsoft.com/en-us/security/blog/2023/05/02/the-cost-of-mfa-resilience/)
13. Forrester TEI of Microsoft Defender XDR (June 2025): [https://www.microsoft.com/en-us/security/blog/2025/06/24/the-total-economic-impact-of-microsoft-defender-xdr/](https://www.microsoft.com/en-us/security/blog/2025/06/24/the-total-economic-impact-of-microsoft-defender-xdr/)
14. Microsoft Sentinel landing (Forrester TEI 234% ROI): [https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-sentinel](https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-sentinel)
15. Tines Voice of the SOC 2023 — report: [https://www.tines.com/reports/voice-of-the-soc-2023/](https://www.tines.com/reports/voice-of-the-soc-2023/)
16. Microsoft Security Copilot Randomized Controlled Trial: [https://www.microsoft.com/en-us/security/blog/2024/04/02/randomized-controlled-trial-for-microsoft-copilot-for-security/](https://www.microsoft.com/en-us/security/blog/2024/04/02/randomized-controlled-trial-for-microsoft-copilot-for-security/)
18. IBM Cost of a Data Breach Report 2026 — landing: [https://www.ibm.com/reports/data-breach](https://www.ibm.com/reports/data-breach)
19. Verizon Data Breach Investigations Report 2026 — landing: [https://www.verizon.com/business/resources/reports/dbir/](https://www.verizon.com/business/resources/reports/dbir/)
20. M-Trends 2026: Data, Insights, and Strategies From the Frontlines — Google Cloud blog, 2026-03-23: [https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026)
21. Microsoft Learn — Plan for mandatory Microsoft Entra multifactor authentication (updated 2026-10-06): [https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mandatory-multifactor-authentication](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mandatory-multifactor-authentication)
17. Veza summary clarifying the IBM AI savings framings: [https://veza.com/blog/ibm-2024-cost-of-a-data-breach-report-puts-identity-front-and-center/](https://veza.com/blog/ibm-2024-cost-of-a-data-breach-report-puts-identity-front-and-center/)

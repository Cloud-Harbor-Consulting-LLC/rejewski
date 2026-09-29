# Project Harbor Sonar — Zero Trust Baseline Scenarios

**Version:** v0.1
**Date:** 2026-05-18
**Owner:** Derek Morgan
**Status:** Pillar 1 anchor for Sprint 2 build
**Backlog:** B002

## Purpose

This document defines three baseline Zero Trust scenarios that the Rejewski adversary emulator will replay against the cloudharbordemo sandbox tenant during MVP scope. Each scenario pairs an adversary action with the Microsoft control surface that should detect or block it, the exact telemetry signals a defender will see, and the pass/fail criteria for a replay run.

The scenarios are the foundation for all Pillar 1 work in Sprint 2 and beyond. Subsequent technique modules, replay-log entries, and ROI claims map back to one of the three scenario IDs defined here (ZT-S01, ZT-S02, ZT-S03).

## Framing

Two reference models are in scope:

- **NIST SP 800-207 §2.1.** Seven tenets of a Zero Trust Architecture. Tenets are referenced as T1 through T7 in the order they appear in §2.1. Source: csrc.nist.gov/pubs/sp/800/207/final.
- **Microsoft Zero Trust pillars.** Six pillars: Identities, Endpoints, Applications, Data, Infrastructure, Network. Source: learn.microsoft.com/en-us/security/zero-trust/deploy/overview.

Each scenario below names the NIST tenets it stresses and the Microsoft pillars it maps to.

## Common context

All three scenarios assume the following adversary profile, established in Sprint 1:

- **Adversary identity.** Rejewski operates as an external threat actor with knowledge of a compromised set of credentials for Megan Bowen (<meganb@cloudharbor-demo.com>) in the sandbox tenant cloudharbordemo (76b87c33-6178-4ff9-94a7-164792c8e4c6).
- **Borrowed client.** Microsoft Graph Command Line Tools first-party FOCI client (app ID 14d82eec-204b-4c2f-b7e8-296a70dab67e). No app registration is created in the target tenant. See guardrails.md G-1.
- **Token acquisition.** MSAL Resource Owner Password Credential (ROPC) delegated flow against the v2.0 token endpoint. ROPC carries no device claim and produces no Primary Refresh Token.
- **Telemetry assumption.** Diagnostic settings are enabled to forward SigninLogs, AuditLogs, and MicrosoftGraphActivityLogs to a Log Analytics workspace. Where a signal depends on a non-default diagnostic setting, this is called out in the scenario.

---

## Scenario ZT-S01 — Device Compliance

**ZT principle.** Verify device posture before granting access. The adversary's endpoint is unmanaged, unenrolled, and non-compliant by definition (Rejewski runs from an attacker-controlled host outside the tenant's MDM scope).

**NIST tenets:** T5 (continuous monitoring of asset integrity and posture), T6 (authentication and authorization strictly enforced before access).
**Microsoft pillars:** Endpoints (primary), Identities (evaluator).
**ATT&CK technique:** T1078.004 Valid Accounts: Cloud Accounts.

**Adversary action.**

Rejewski uses the compromised credentials to acquire a Graph token via ROPC, then attempts a Graph API call against a resource protected by a Conditional Access policy that requires a compliant device. Because the ROPC token carries no device claim and the endpoint is not enrolled in Intune, the request must be denied at the Conditional Access evaluation step.

**Defensive control surface.**

Conditional Access grant control set to Require device to be marked as compliant, or the stronger Require Hybrid Microsoft Entra domain joined device.

**Expected alert pattern.**

- **Sign-in log error code.** AADSTS53000 — Microsoft text: "Device is not in required device state: compliant. Conditional Access policy requires a compliant device, and the device is not compliant. The user must enroll their device with an approved MDM provider like Intune."
- **Sign-in log status.** ConditionalAccessStatus = Failure. The failing policy row appears in the ConditionalAccessPolicies array on the Conditional Access tab.
- **Sign-in log device fields.** deviceDetail.isCompliant = false; deviceDetail.isManaged = false; deviceDetail.trustType = empty. ROPC produces no device claim, so all three fields collapse to the unmanaged baseline.
- **Intune surface.** The endpoint does not appear in Intune admin center → Devices → All devices. There is no Compliance column row to inspect; absence is the signal.
- **Hunt query (KQL).**

```kql
SigninLogs
| where ResultType == 53000
| where DeviceDetail.isCompliant == false
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress,
          ConditionalAccessStatus, DeviceDetail
```

**Pass / fail criteria.**

- **Pass (defender wins).** AADSTS53000 row appears in SigninLogs within 60 seconds of the Rejewski token-acquisition attempt, with deviceDetail.isCompliant = false and the expected CA policy named in ConditionalAccessPolicies.
- **Fail (defender loses).** Token issued and Graph call succeeds. Indicates either no Require compliant device CA policy is applied to the resource, or the policy is in report-only mode.

**Cross-refs.** threat-model.md §3 (asset model — endpoint posture); guardrails.md G-1 (tenant lock); ADR 0003 (technique module format) for any technique module that emits this signal.

---

## Scenario ZT-S02 — Identity Verification (ROPC and MFA bypass)

**ZT principle.** Verify explicitly. Every authentication is evaluated on credential strength, sign-in context, and behavioral risk — not just the password.

**NIST tenets:** T4 (access enforced dynamically based on credential and behavioral attributes), T6 (authentication and authorization strictly enforced).
**Microsoft pillars:** Identities (primary), Applications (Graph as the resource).
**ATT&CK technique:** T1078.004 Valid Accounts: Cloud Accounts (credential-based access without interactive challenge).

**Adversary action.**

Rejewski submits the compromised password via MSAL ROPC against the v2.0 token endpoint, borrowing the Microsoft Graph Command Line Tools FOCI client ID. ROPC is a non-interactive password grant: no browser, no MFA prompt, no PRT. If the user is enforced for MFA via Conditional Access and the policy evaluates on this sign-in, the token is denied. If MFA is not enforced for this user-app pairing, the token is issued and the only signal is a risky-sign-in event.

**Defensive control surface.**

Two complementary surfaces. (a) Conditional Access policy enforcing Require MFA on the user, app, or risk level. (b) Microsoft Entra Identity Protection risk detections that fire on credential-misuse patterns.

**Expected alert pattern.**

- **CA MFA denial.** AADSTS50076 fires when CA requires MFA and ROPC cannot satisfy it. Microsoft text: "Due to a configuration change made by your administrator, or because you moved to a new location, you must use multi-factor authentication to access..." Companion code AADSTS50079 indicates MFA proof-up registration is required.
- **Sign-in log row on MFA denial.** Authentication Details tab shows Status: Interrupted, Additional Details: User needs to perform multi-factor authentication, no MFA method attempted.
- **Identity Protection risk detections** (riskEventType in parens). Primary expected fire for Rejewski's first ROPC attempt from an unfamiliar IP and user-agent:
  - Unfamiliar sign-in properties (unfamiliarFeatures) — real-time. Microsoft docs explicitly note this detection runs on non-interactive sign-ins and warrants increased scrutiny due to token-replay risk. This is the highest-confidence fire for ROPC against a previously unseen origin.
  - Atypical travel (unlikelyTravel) — offline.
  - Anonymous IP address (anonymizedIPAddress) — real-time. Fires only if the source IP is on the Tor exit list or known anonymizer.
  - Password spray (passwordSpray) — fires when an attacker successfully validates a user's password after broad attempts.
  - Microsoft Entra threat intelligence (investigationsThreatIntelligence) — real-time.
- **Risk aggregation.** Sign-in risk level (low / medium / high) is recorded on the SigninLogs row; user risk aggregates into riskLevelAggregated. Risk-based CA can MFA-challenge or block when aggregated risk exceeds threshold.
- **clientAppUsed field.** Inferred as Mobile Apps and Desktop clients (modern auth, non-interactive). This is not the legacy Other clients value. Distinguishing ROPC from legitimate Graph Command Line Tools admin usage requires the riskEventType signal — see Gaps §1.
- **Audit signals.** Password resets, MFA registrations, and added authentication methods are recorded in AuditLogs under Authentication methods. Rejewski does not perform these during ROPC, so their absence reinforces the signal of credential-only misuse.
- **Hunt query (KQL).**

```kql
SigninLogs
| where AppId == "14d82eec-204b-4c2f-b7e8-296a70dab67e"
| where ResultType == 0 or ResultType == 50076
| where RiskEventTypes_V2 has_any ("unfamiliarFeatures", "unlikelyTravel",
                                   "anonymizedIPAddress", "passwordSpray")
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          RiskLevelDuringSignIn, RiskEventTypes_V2, ResultType, Status
```

**Pass / fail criteria.**

- **Pass (defender wins).** Either AADSTS50076 denies the token, or a risky-sign-in event with riskEventType = unfamiliarFeatures is logged within five minutes of the Rejewski attempt, and risk-based CA blocks subsequent Graph calls.
- **Fail (defender loses).** Token issued, no risky-sign-in event is recorded, and no CA policy interrupts subsequent Graph activity. This is the gap Rejewski exists to exercise — the ROPC against a FOCI client makes the traffic look like legitimate admin tooling.

**Cross-refs.** threat-model.md §4 (authentication surface); guardrails.md G-3, G-5 (credential discipline and tenant scope); Sprint 2 W1 candidate for risk-based CA hardening recommendations.

---

## Scenario ZT-S03 — Network Segmentation (Lateral discovery via Graph)

**ZT principle.** Never trust the network. Resource access — including the directory itself — is evaluated per request, not per network location. Lateral discovery from a compromised identity must be observable.

**NIST tenets:** T1 (all data sources and computing services are resources, including the directory), T2 (all communication is secured regardless of network location), T7 (signal collection on the current state of assets and infrastructure).
**Microsoft pillars:** Network (primary), Applications (Graph API surface), Identities (actor).
**ATT&CK techniques:** T1087.004 Account Discovery: Cloud Account; T1069.003 Permission Groups Discovery: Cloud Groups.

**Adversary action.**

After acquiring a Graph token (per ZT-S02), Rejewski enumerates the directory: GET /v1.0/users with pagination, GET /v1.0/groups, and group membership expansion. The behavior pattern is volumetric reads from a single identity over a short window — the Sprint 1 enumeration row cap (G-9) is precisely the guardrail that flags this shape.

**Defensive control surface.**

Three complementary surfaces. (a) MicrosoftGraphActivityLogs for volumetric request observability. (b) Defender for Cloud Apps anomaly policies for session-level behavior deviation. (c) Conditional Access location and Tenant Restrictions v2 for network-boundary enforcement.

**Expected alert pattern.**

- **MicrosoftGraphActivityLogs (high-fidelity surface).** Graph GET /users and GET /groups are read operations and do not appear in Entra AuditLogs (which capture directory change events only). They appear in the MicrosoftGraphActivityLogs table in Log Analytics, gated on the corresponding diagnostic setting. Fields: RequestUri, RequestMethod, UserId, AppId, ResponseStatusCode, IPAddress, UserAgent, Roles, ResponseSizeBytes.
- **SigninLogs at token acquisition.** One row per token acquisition with AppId = 14d82eec... and the resource set to Microsoft Graph. Subsequent Graph reads do not produce additional SigninLogs rows — token-level events are not per-request.
- **Defender for Cloud Apps anomaly policies** (post-June 2025 policy roster):
  - Unusual administrative activities — closest documented fit for high-volume directory reads. Session-level deviation from a learned seven-day baseline.
  - Activity from infrequent country — geographic anomaly on the API session.
  - Impossible travel — between Megan's legitimate session and the Rejewski session.
  - Multiple failed login attempts — fires only if ROPC dictionary attempts precede success.
  - Note: Activity from anonymous IP addresses, Suspicious inbox forwarding, Suspicious inbox manipulation rules, Activity from suspicious IP addresses, and Unusual ISP for an OAuth App were migrated to dynamic threat detection in June 2025. Coverage continues under renamed dynamic detections; defender-side runbooks should reference the dynamic detection names, not the deprecated static names.
- **Tenant Restrictions v2.** Does not fire for this scenario because Rejewski operates intra-tenant. TRv2 is the control surface when the same identity is observed signing in to an external tenant from corporate egress.
- **IP-based CA.** A Block by location CA policy against a Named locations allow list produces a denial in the AADSTS53003 family when egress falls outside the allow list. AADSTS53001 (device not joined) and AADSTS53003 (location-blocked) verbatim text was not surfaced in primary Microsoft sources during the grounding pass — see Gaps §3.
- **Hunt query (KQL).**

```kql
MicrosoftGraphActivityLogs
| where RequestUri startswith "/v1.0/users" or RequestUri startswith "/v1.0/groups"
| where RequestMethod == "GET"
| summarize Calls = count(), DistinctTargets = dcount(RequestUri),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
            by UserId, AppId, IPAddress, bin(TimeGenerated, 5m)
| where Calls > 50
| order by Calls desc
```

The 50-call threshold is illustrative; production tuning is tenant-dependent.

**Pass / fail criteria.**

- **Pass (defender wins).** MicrosoftGraphActivityLogs surfaces the enumeration burst within five minutes, and one of (a) Unusual administrative activities MCAS alert fires, (b) risk-based CA blocks the session, or (c) an analytics rule on the hunt query above raises an incident.
- **Fail (defender loses).** Enumeration completes silently. Either MicrosoftGraphActivityLogs diagnostic setting is not enabled, MCAS anomaly baseline is not established for the user, or no analytics rule is tuned to the volumetric Graph read pattern. This is a strong demonstration of why network-layer trust is insufficient: the adversary never crosses a network boundary, and yet exfiltrates the entire directory via API.

**Cross-refs.** threat-model.md §5 (data-tier exposure); guardrails.md G-9 (enumeration row cap); ADR 0003 technique module format; Sprint 1 replay-log writer middleware (replay_log.py) emits the per-request entries that feed the hunt queries above.

---

## Gaps and open items

These are signal-level uncertainties carried forward from the v0.1 grounding pass. Each is a candidate for tenant-side confirmation or follow-up research:

1. **clientAppUsed exact value for ROPC v2 token endpoint.** Inferred as Mobile Apps and Desktop clients. Microsoft Learn does not name OAuth2 password grant explicitly. Confirm against a live SigninLogs event from the sandbox before relying on the field as a deterministic discriminator.
2. **MCAS alert specific to ROPC.** No documented MCAS policy fires on the OAuth2 password grant flow itself. ROPC against a first-party FOCI client looks like legitimate non-interactive admin tooling absent an Identity Protection risk event or the volumetric Graph reads in ZT-S03.
3. **AADSTS53001 versus 53003 disambiguation.** AADSTS53000 (device not compliant) is well-documented. 53001 (device not joined) and 53003 (location-blocked) appear in vendor guidance but verbatim Microsoft text was not surfaced during grounding. Confirm before publishing detection rules that rely on the distinction.
4. **Specific Microsoft Sentinel rule names.** Generic KQL patterns are well known. Specific published rule titles from the Azure-Sentinel GitHub repo for MicrosoftGraphActivityLogs were not enumerated in this pass. Cross-reference before naming a specific rule in a downstream technique module.
5. **Anonymous IP detection coverage.** The MCAS static policy for anonymous IP was migrated June 2025. The Identity Protection riskEventType anonymizedIPAddress remains active. Defender-side documentation should reference the Identity Protection detection, not the deprecated MCAS policy.

## Cross-references

- ADR 0001 Rules of Engagement (0001-rules-of-engagement.md) — tenant scope and authorization boundary.
- ADR 0002 Naming Convention (0002-naming-convention.md) — scenario ID format consistency.
- ADR 0003 Technique Module Format (0003-technique-module-format.md) — technique modules emit signals that map to scenarios.
- guardrails.md — G-1 tenant lock, G-3 credential discipline, G-5 tenant scope, G-9 enumeration row cap.
- threat-model.md — §3 asset model, §4 authentication surface, §5 data-tier exposure.
- schemas/replay-log/v0.5.json — replay-log entries carry the run_id binding field.
- Sprint 2 build will produce technique modules that emit the signals defined here.

## Change log

- **v0.1 (2026-05-18).** Initial draft. Three scenarios defined: ZT-S01 Device Compliance, ZT-S02 Identity Verification, ZT-S03 Network Segmentation. Grounded against NIST SP 800-207, Microsoft Zero Trust deployment guide, Microsoft Learn Conditional Access and Identity Protection references, and Defender for Cloud Apps anomaly policy roster. Five open signal-level items carried forward in Gaps and open items.

## Sources

- NIST SP 800-207 Zero Trust Architecture — csrc.nist.gov/pubs/sp/800/207/final
- Microsoft Learn — Zero Trust deployment pillars — learn.microsoft.com/en-us/security/zero-trust/deploy/overview
- Microsoft Learn — Sign-in log activity details — learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-in-log-activity-details
- Microsoft Learn — Troubleshoot Conditional Access — learn.microsoft.com/en-us/entra/identity/conditional-access/troubleshoot-conditional-access
- Microsoft Learn — Identity Protection risk detections — learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks
- Microsoft Learn — Defender for Cloud Apps anomaly detection policies — learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy
- Microsoft Learn — Tenant Restrictions v2 — learn.microsoft.com/en-us/entra/external-id/tenant-restrictions-v2

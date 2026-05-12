# Rejewski

Agentic Microsoft 365 tenant pen-testing assistant. A friendly threat actor that emulates recon and discovery TTPs against a tenant the operator owns or has written authorization to assess, and produces findings mapped to specific M365 controls.

> **Status:** Private build through Sat Oct 24, 2026. Public launch Mon Oct 26, 2026. See [Project Harbor Sonar Master Plan](https://cloudharborconsulting.sharepoint.com/:t:/s/CHC-Ops/IQBCENuicazZQK8l9Z4XeVFKAQNQEEy11y6ehgv9eb__az0?e=9rw5oh) for build cadence and milestones.

## What it does

Rejewski runs as an agentic loop on top of the Claude Agent SDK. Each run:

1. Prompts the operator for Rules of Engagement consent and records the consent.
2. Executes read-only Microsoft Graph and Defender / Purview queries against the target tenant.
3. Maps each finding to a specific M365 control (Conditional Access policy, Defender setting, Purview label, Intune compliance check, and so on).
4. Emits a structured replay log so every run reproduces.
5. Renders an HTML report with severity scores and business-impact lines per finding.

## Quickstart

To be added in Sprint 6 (README v2). Will cover prerequisites, install, sign-in, and a 5-line run example.

## Rules of Engagement

Every run starts with an ROE consent prompt. The operator confirms tenant ownership or written authorization, scope boundaries, and acknowledges guardrails G1 to G4. The consent record persists alongside the replay log.

Full ROE design lives in docs/adr/0001-roe-consent.md.

## Guardrails

Rejewski operates under 8 guardrails, all enforced in code or process:

- G1 Read-Only
- G2 No Credential Harvesting
- G3 Telemetry-Aware and Replayable
- G4 Threat Actor Emulation (recon and discovery only)
- G5 Rules of Engagement
- G6 Private Build, Public Launch
- G7 M365-Wide Control Inventory Mapping
- G8 Measure at Sprint Boundaries

Full rule text and enforcement notes in docs/guardrails.md.

## Naming

Heritage attribution to Marian Rejewski (1905-1980), the Polish mathematician and cryptologist who reconstructed the inner wiring of the German Enigma machine in 1932 and founded modern cryptanalysis. Full attribution block lands in Sprint 5 (README v1). Rationale and clearance findings in docs/adr/0002-naming-rejewski.md.

## Contributing

See CONTRIBUTING.md. Full v1 lands in Sprint 5.

## License

MIT. See LICENSE.

---

Part of [Cloud Harbor Consulting](https://cloudharborconsulting.cloud) M365 security tooling.

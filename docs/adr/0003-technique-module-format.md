# ADR 0003: Technique Module Format

- Status: Accepted
- Date: 2026-05-14
- Deciders: Derek Morgan
- Related: ADR 0001 (Sprint 1 scope), ADR 0002 (consent floor evidence), docs/threat-model.md, docs/guardrails.md

## Context

Sprint 1 ships three MITRE ATT&CK technique modules (T1078.004, T1087.004, T1069.003) under docs/techniques/. Each module documents Rejewski's emulation of one technique against the cloudharbordemo sandbox tenant. Without a shared format, modules drift on what they record, making cross-technique comparison, guardrail enforcement, and evidence audit harder than necessary.

The no-tenant-app-reg posture means every technique module must explicitly name the borrowed first-party OAuth client. Sprint 1 borrows Microsoft Graph PowerShell (14d82eec-204b-4c2f-b7e8-296a70dab67e). Future sprints may borrow other FOCI clients; gaining a tenant app registration is itself a Sprint 2+ technique. The format must surface this choice unambiguously rather than leaving it in tribal knowledge.

## Decision

Each technique module is a single Markdown file at docs/techniques/<TID>.md where <TID> is the canonical MITRE technique ID (e.g., T1078.004). The dot is preserved; no separators are introduced.

### Required front matter

```yaml
---
technique_id: T1078.004
technique_name: "Valid Accounts: Cloud Accounts"
tactic: Initial Access
sprint: 1
status: implemented
first_party_client: Microsoft Graph PowerShell
first_party_client_id: 14d82eec-204b-4c2f-b7e8-296a70dab67e
sandbox_tenant: cloudharbordemo
sandbox_tenant_id: 76b87c33-6178-4ff9-94a7-164792c8e4c6
---
```

### Required sections, in order

1. **Summary** — one paragraph: what the technique does, why Rejewski emulates it, where it sits in the kill chain.
2. **ATT&CK reference** — direct link to the attack.mitre.org page for the sub-technique.
3. **Borrowed client** — explicit statement of which first-party OAuth client is used and why; reaffirm the no-tenant-app-reg posture.
4. **Procedure** — ordered steps describing the emulation. Each step names the Graph endpoint or CLI command executed.
5. **Guardrails** — bullet list referencing the G-IDs from docs/guardrails.md that constrain this technique.
6. **Detection signals** — what the technique should generate (sign-in logs, audit logs, Graph activity); used downstream to validate detection coverage.
7. **Evidence** — links to B-task evidence under the SharePoint Project Harbor Sonar / Evidence folder. Each entry: run number, date, SharePoint path.
8. **Limitations** — what this module does NOT cover and what is explicitly deferred to later sprints.

### Cross-referencing rules

- Every module links to the ADR(s) authorizing its inclusion. Sprint 1 modules cite ADR 0001.
- Every module links to docs/threat-model.md for adversary-model context.
- Every module names the guardrails (G-IDs) that bound it. Modules with no governing guardrail are not acceptable.

### File naming

- Canonical: docs/techniques/T1078.004.md.
- One file per sub-technique. Parent techniques without sub-techniques use the parent ID alone (e.g., T1526.md).

## Consequences

### Positive

- Predictable structure: reviewers, future contributors, and downstream automation can rely on a fixed shape.
- The borrowed-client field forces every module to make the FOCI choice explicit, keeping the no-tenant-app-reg posture visible in code rather than tribal knowledge.
- Evidence pointers are first-class, not buried in PR descriptions.

### Negative

- Front-matter changes require touching every module — a Sprint 2+ field addition is a multi-file PR.
- Markdown linting must allow YAML front matter (already true in the current toolchain).

### Mitigations

- New required fields enter via an ADR that supersedes 0003; the superseding ADR includes the migration list.

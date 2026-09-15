#!/usr/bin/env python3
"""
Rejewski — write_consent_record (ROE consent record v2, S5 W18)

Reusable successor to the one-off scripts/write_consent_r0NN.py helpers. Emits a durable
long-term-archive consent record conforming to schemas/roe-consent/v2.json, for either a
self-test run (cloudharbordemo) or a third-party assessment.

Backward compatibility (additive, non-breaking):
  - v2 is a strict superset of the v1 replay-log-embedded shape (schemas/roe-consent/v1.json).
  - `v1_core(record)` extracts exactly the 9 v1 fields, so the same consent can still seed a
    run's replay log as its first entry, unchanged. The committed R010-R013 evidence stays v1
    and is never rewritten by this script.

Read-only / offline: builds and writes local JSON. No Microsoft Graph calls. G-1 is unchanged
by this script — a v2 record for a third-party engagement is an authorization artifact only;
all actual Rejewski code execution remains sandbox-locked to cloudharbordemo (docs/external-auth.md).

CLI:
    python scripts/write_consent_record.py --engagement-type self_test \
        --run-id R011 --techniques T1087.004 T1526 --output out/roe-selftest.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
SANDBOX_TENANT_ID = "76b87c33-6178-4ff9-94a7-164792c8e4c6"

# The 9 fields of the v1 replay-log-embedded consent shape (schemas/roe-consent/v1.json).
V1_CORE_FIELDS = (
    "event",
    "run_id",
    "tenant_id",
    "operator_object_id",
    "techniques",
    "expected_duration_seconds",
    "prompt_emitted_at",
    "confirmed_at",
    "confirmation_latency_seconds",
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def v1_core(record: dict) -> dict:
    """Extract the v1 replay-log-embedded core from a v2 record (for seeding a replay log)."""
    return {k: record[k] for k in V1_CORE_FIELDS if k in record}


def build_consent_record(
    *,
    engagement_type: str,
    run_id: str,
    techniques: list[str],
    operator_object_id: str,
    engagement_name: str,
    mvp_pillar: str,
    status: str,
    scope_surface: list[str],
    scope_summary: str,
    signed_by_provider: str,
    signature_method: str,
    signed_date: str,
    effective_date: str,
    expiry_date: str,
    evidence_ref: str,
    storage_location: str,
    record_id: str,
    event: str = "consent.granted",
    expected_duration_seconds: int = 1800,
    confirmation_latency_seconds: int = 3,
    # third-party-only:
    tenant_id: Optional[str] = None,
    counterparty_org: Optional[str] = None,
    counterparty_contact_name: Optional[str] = None,
    counterparty_contact_email: Optional[str] = None,
    signed_by_counterparty: Optional[str] = None,
    prompt_emitted_at: Optional[str] = None,
    confirmed_at: Optional[str] = None,
    created_utc: Optional[str] = None,
) -> dict:
    """Build a v2 consent record.

    For engagement_type == 'self_test' the counterparty block is auto-populated with an explicit
    self-test marker (never blank/null, per AC4) and the tenant defaults to the G-1 sandbox tenant.
    For 'third_party_assessment' the counterparty fields and tenant_id are required.
    """
    is_self_test = engagement_type == "self_test"
    prompt_emitted_at = prompt_emitted_at or _now_iso()
    confirmed_at = confirmed_at or _now_iso()

    if is_self_test:
        tenant_id = tenant_id or SANDBOX_TENANT_ID
        counterparty = {
            "is_self_test": True,
            "org": counterparty_org or "Cloud Harbor Consulting (self-test)",
            "contact_name": counterparty_contact_name or "Derek Morgan",
            "contact_email": counterparty_contact_email or "derek.morgan@cloudharborconsulting.cloud",
        }
        signed_by_counterparty = signed_by_counterparty or f"{signed_by_provider} — self-authorized"
    else:
        missing = [
            n for n, v in {
                "tenant_id": tenant_id,
                "counterparty_org": counterparty_org,
                "counterparty_contact_name": counterparty_contact_name,
                "counterparty_contact_email": counterparty_contact_email,
                "signed_by_counterparty": signed_by_counterparty,
            }.items() if not v
        ]
        if missing:
            raise ValueError(
                "third_party_assessment requires: " + ", ".join(missing)
            )
        counterparty = {
            "is_self_test": False,
            "org": counterparty_org,
            "contact_name": counterparty_contact_name,
            "contact_email": counterparty_contact_email,
        }

    return {
        "schema_version": "2",
        "event": event,
        "run_id": run_id,
        "tenant_id": tenant_id,
        "operator_object_id": operator_object_id,
        "techniques": techniques,
        "expected_duration_seconds": expected_duration_seconds,
        "prompt_emitted_at": prompt_emitted_at,
        "confirmed_at": confirmed_at,
        "confirmation_latency_seconds": confirmation_latency_seconds,
        "engagement": {
            "name": engagement_name,
            "type": engagement_type,
            "mvp_pillar": mvp_pillar,
            "status": status,
        },
        "counterparty": counterparty,
        "scope": {
            "surface": scope_surface,
            "summary": scope_summary,
        },
        "authorization": {
            "signed_by_provider": signed_by_provider,
            "signed_by_counterparty": signed_by_counterparty,
            "signature_method": signature_method,
            "signed_date": signed_date,
            "effective_date": effective_date,
            "expiry_date": expiry_date,
            "evidence_ref": evidence_ref,
        },
        "archive": {
            "record_id": record_id,
            "storage_location": storage_location,
            "created_utc": created_utc or _now_iso(),
        },
    }


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="write_consent_record.py",
        description="Emit a v2 ROE consent record (durable long-term archive).",
    )
    p.add_argument("--engagement-type", required=True, choices=["self_test", "third_party_assessment"])
    p.add_argument("--run-id", required=True)
    p.add_argument("--techniques", nargs="+", required=True, help="ATT&CK technique IDs, e.g. T1087.004 T1526.")
    p.add_argument("--operator-object-id", default="48df3ad2-9110-4c27-9630-f82b1b8eb177",
                   help="Entra object id of the operator (default: sandbox operator).")
    p.add_argument("--engagement-name", required=True)
    p.add_argument("--mvp-pillar", default="Pillar 1 - Zero Trust adversary emulation")
    p.add_argument("--status", default="draft", choices=["draft", "active", "completed", "expired", "revoked"])
    p.add_argument("--scope-surface", nargs="+", required=True)
    p.add_argument("--scope-summary", required=True)
    p.add_argument("--signed-by-provider", default="Derek Morgan (Cloud Harbor Consulting)")
    p.add_argument("--signature-method", default="self_test_attestation")
    p.add_argument("--signed-date", required=True, help="YYYY-MM-DD")
    p.add_argument("--effective-date", required=True, help="YYYY-MM-DD")
    p.add_argument("--expiry-date", required=True, help="YYYY-MM-DD")
    p.add_argument("--evidence-ref", default="docs/roe-consent-flow.md")
    p.add_argument("--storage-location", default="SharePoint > ROE Consent Archive workbook")
    p.add_argument("--record-id", required=True, help="Durable record id, e.g. roe-selftest-r011-001.")
    # third-party
    p.add_argument("--tenant-id")
    p.add_argument("--counterparty-org")
    p.add_argument("--counterparty-contact-name")
    p.add_argument("--counterparty-contact-email")
    p.add_argument("--signed-by-counterparty")
    p.add_argument("--output", required=True, help="Path to write the v2 record JSON.")
    p.add_argument("--emit-v1-core", action="store_true",
                   help="Also write the v1 replay-log-embedded core next to --output (.v1-core.json).")
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    try:
        record = build_consent_record(
            engagement_type=args.engagement_type,
            run_id=args.run_id,
            techniques=args.techniques,
            operator_object_id=args.operator_object_id,
            engagement_name=args.engagement_name,
            mvp_pillar=args.mvp_pillar,
            status=args.status,
            scope_surface=args.scope_surface,
            scope_summary=args.scope_summary,
            signed_by_provider=args.signed_by_provider,
            signature_method=args.signature_method,
            signed_date=args.signed_date,
            effective_date=args.effective_date,
            expiry_date=args.expiry_date,
            evidence_ref=args.evidence_ref,
            storage_location=args.storage_location,
            record_id=args.record_id,
            tenant_id=args.tenant_id,
            counterparty_org=args.counterparty_org,
            counterparty_contact_name=args.counterparty_contact_name,
            counterparty_contact_email=args.counterparty_contact_email,
            signed_by_counterparty=args.signed_by_counterparty,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {output}: v2 consent record {record['archive']['record_id']}", file=sys.stderr)

    if args.emit_v1_core:
        core_path = output.with_suffix(".v1-core.json")
        core_path.write_text(json.dumps(v1_core(record), indent=2) + "\n", encoding="utf-8")
        print(f"wrote {core_path}: v1 replay-log-embedded core", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())

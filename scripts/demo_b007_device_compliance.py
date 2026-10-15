#!/usr/bin/env python3
"""
demo_b007_device_compliance.py

Rejewski B007 — Pillar 1 Zero Trust device compliance demo.

Emulates a threat actor attempting to acquire a Microsoft Graph delegated
token via MSAL ROPC against a non-compliant device. Under a Conditional
Access policy requiring 'device marked as compliant', the token request
fails at the /oauth2/v2.0/token endpoint with AADSTS53000 and no Graph
call is reached.

Maps to ATT&CK T1078.004 (Valid Accounts: Cloud Accounts). Mitigation
M1036 (Account Use Policies / CA require compliant device) is the
defensive control under test.

Evidence: writes a single JSON record describing the attempt to stdout
(or --evidence-out path).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

import msal

from replay_log import redact_tenant_id
from roe_gate import require_sandbox


BORROWED_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"  # Microsoft Graph Command Line Tools
DEFAULT_TENANT_ID = "76b87c33-6178-4ff9-94a7-164792c8e4c6"   # cloudharbordemo
DEFAULT_ACTOR_UPN = "meganb@cloudharbor-demo.com"
DEFAULT_SCOPES = ["https://graph.microsoft.com/.default"]
EXPECTED_AADSTS = 53000

# AADSTS codes that mean "ROPC itself is disabled / inapplicable" — surface
# distinctly so we don't claim a CA device-compliance win when the trigger
# never reached CA evaluation.
ROPC_DISABLED_OR_USER_INVALID = {7000218, 50126, 50034, 50056, 50057, 50059, 50053}


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def classify(error_codes: list[int]) -> str:
    if EXPECTED_AADSTS in error_codes:
        return "blocked_by_ca_device_compliance"
    if any(code in ROPC_DISABLED_OR_USER_INVALID for code in error_codes):
        return "ropc_disabled_or_user_invalid"
    if 50076 in error_codes or 50158 in error_codes or 50079 in error_codes:
        return "blocked_by_ca_other_mfa"
    if 53003 in error_codes or 53001 in error_codes:
        return "blocked_by_ca_other_generic"
    if not error_codes:
        return "other_error"
    return "other_aadsts"


def run(actor_upn: str, password: str, tenant_id: str, scopes: list[str]) -> dict:
    # G-1 (ADR 0008): this demo calls MSAL directly and bypasses the consent gate
    # in identity.acquire_token, so it stays sandbox-only.
    require_sandbox(tenant_id, "demo_b007_device_compliance.py")
    authority = f"https://login.microsoftonline.com/{tenant_id}"
    app = msal.PublicClientApplication(
        client_id=BORROWED_CLIENT_ID,
        authority=authority,
    )

    started = utcnow_iso()
    result = app.acquire_token_by_username_password(
        username=actor_upn,
        password=password,
        scopes=scopes,
    )
    completed = utcnow_iso()

    record = {
        "tool": "demo_b007_device_compliance",
        "technique": "T1078.004",
        "scenario": "ZT-S01-DeviceCompliance",
        "tenant_id": redact_tenant_id(tenant_id),
        "borrowed_client_id": BORROWED_CLIENT_ID,
        "actor_upn": actor_upn,
        "requested_scopes": scopes,
        "expected_aadsts": EXPECTED_AADSTS,
        "ca_grant_control_under_test": "CompliantDevice",
        "started_at_utc": started,
        "completed_at_utc": completed,
    }

    if "access_token" in result:
        record["outcome"] = "unexpected_success"
        record["matched_expected_53000"] = False
        record["note"] = (
            "Token returned. CA device-compliance policy did not block. "
            "Verify the policy targets this user/app/cloud combination and "
            "that the test device is not registered as compliant."
        )
        record["token_type"] = result.get("token_type")
        record["expires_in"] = result.get("expires_in")
    else:
        error_codes = result.get("error_codes", []) or []
        record["outcome"] = classify(error_codes)
        record["matched_expected_53000"] = EXPECTED_AADSTS in error_codes
        record["error_short"] = result.get("error")
        record["error_description"] = result.get("error_description")
        record["aadsts_codes"] = error_codes
        record["primary_aadsts"] = error_codes[0] if error_codes else None
        record["correlation_id"] = result.get("correlation_id")
        record["trace_id"] = result.get("trace_id")
        record["timestamp_sts"] = result.get("timestamp")
        record["error_uri"] = result.get("error_uri")

    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Rejewski B007 device-compliance demo (MSAL ROPC, expects AADSTS53000)."
    )
    parser.add_argument("--actor", default=os.environ.get("REJEWSKI_ACTOR_UPN", DEFAULT_ACTOR_UPN))
    parser.add_argument("--tenant", default=os.environ.get("AZURE_TENANT_ID", DEFAULT_TENANT_ID))
    parser.add_argument(
        "--scope",
        action="append",
        default=None,
        help="Repeatable. Defaults to https://graph.microsoft.com/.default.",
    )
    parser.add_argument(
        "--evidence-out",
        default=None,
        help="Write evidence JSON to this path instead of stdout.",
    )
    args = parser.parse_args(argv)

    password = os.environ.get("REJEWSKI_ACTOR_PASSWORD")
    if not password:
        print(
            "REJEWSKI_ACTOR_PASSWORD env var is required (seed-user password for the ROPC attempt).",
            file=sys.stderr,
        )
        return 2

    scopes = args.scope or DEFAULT_SCOPES

    record = run(
        actor_upn=args.actor,
        password=password,
        tenant_id=args.tenant,
        scopes=scopes,
    )

    payload = json.dumps(record, indent=2, sort_keys=False)
    if args.evidence_out:
        with open(args.evidence_out, "w", encoding="utf-8") as f:
            f.write(payload + "\n")
        print(f"Evidence written to {args.evidence_out}", file=sys.stderr)
    else:
        print(payload)
        sys.stdout.flush()

    return 0 if record.get("matched_expected_53000") else 1


if __name__ == "__main__":
    raise SystemExit(main())
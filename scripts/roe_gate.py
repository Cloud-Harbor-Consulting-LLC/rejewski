#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Rejewski: Rules of Engagement gate (G-1 consent-bound tenant lock, ADR 0008).

A run may target any Microsoft 365 tenant, but only the tenant named in that run's
consent record. `authorize_run()` is called by `scripts/identity.acquire_token`
before any token request leaves the machine, and again by `replay_log.write_entry`
for any entry whose tenant is not the operator's lab tenant, so evidence cannot be
recorded for an unconsented tenant either.

Rules (each check can only deny):

  * A run ID is required. The consent record is found by run ID.
  * The replay-log directory must hold exactly one `consent.granted` record for the
    run, or several that all name the same tenant.
  * The record's tenant must equal the tenant the run is about to use.
  * Lab tenant (the tenant named in REJEWSKI_LAB_TENANT_ID, if set): the v1
    replay-log-embedded record is enough.
  * Any other tenant: the record must be a v2 durable record
    (schemas/roe-consent/v2.json) with `engagement.status == "active"` and today's
    UTC date inside `authorization.effective_date .. expiry_date`. For
    `engagement.type == "third_party_assessment"` it must also be counter-signed:
    `counterparty.is_self_test` false and a signature method other than
    `self_test_attestation` (docs/external-auth.md §2).

Local only: reads JSON files in the replay-log directory. No network calls.
"""

from __future__ import annotations

import json
import os
import re
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Optional

# The operator's own lab tenant, if any. Unset means no tenant gets the lighter
# v1-record rule: every run needs a v2 durable record.
LAB_TENANT_ENV = "REJEWSKI_LAB_TENANT_ID"
CONSENT_EVENT = "consent.granted"
SELF_TEST_SIGNATURE = "self_test_attestation"
_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


class ConsentError(RuntimeError):
    """Raised when a run has no consent record that authorizes its tenant (G-1)."""


def is_tenant_guid(tenant_id: Any) -> bool:
    return isinstance(tenant_id, str) and bool(_GUID_RE.match(tenant_id))


def lab_tenant_id() -> Optional[str]:
    """The lab tenant GUID from REJEWSKI_LAB_TENANT_ID (lowercase), or None if unset or not a GUID."""
    value = os.environ.get(LAB_TENANT_ENV, "").strip()
    return value.lower() if is_tenant_guid(value) else None


def is_lab_tenant(tenant_id: str) -> bool:
    lab = lab_tenant_id()
    return lab is not None and isinstance(tenant_id, str) and tenant_id.lower() == lab


def require_lab_tenant(tenant_id: str, script: str) -> None:
    """For lab-only demo and smoke scripts that bypass identity.acquire_token."""
    if not is_lab_tenant(tenant_id):
        raise ConsentError(
            f"G-1: {script} is a lab-only script and refuses tenant {tenant_id!r}; set "
            f"{LAB_TENANT_ENV} to your lab tenant, or use the technique tools with a "
            "consent record to assess another tenant"
        )


def _iter_records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [p for p in payload if isinstance(p, dict)]
    if isinstance(payload, dict):
        return [payload]
    return []


def find_consent_records(run_id: str, log_dir: Path) -> list[dict[str, Any]]:
    """Every consent.granted record for run_id in log_dir (non-recursive)."""
    found: list[dict[str, Any]] = []
    if not log_dir.is_dir():
        return found
    for path in sorted(log_dir.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for rec in _iter_records(payload):
            if (
                rec.get("event") == CONSENT_EVENT
                and "kind" not in rec
                and rec.get("run_id") == run_id
            ):
                found.append(rec)
    return found


def _parse_date(value: Any, field: str) -> date:
    try:
        return date.fromisoformat(str(value))
    except ValueError as exc:
        raise ConsentError(f"G-1: consent record {field} is not a YYYY-MM-DD date: {value!r}") from exc


def _check_durable(rec: dict[str, Any], tenant_id: str, today: date) -> None:
    engagement = rec.get("engagement")
    authorization = rec.get("authorization")
    counterparty = rec.get("counterparty")
    if not (isinstance(engagement, dict) and isinstance(authorization, dict)
            and isinstance(counterparty, dict)):
        raise ConsentError(
            f"G-1: tenant {tenant_id} is not the lab tenant, so the run needs a v2 durable "
            "consent record (engagement, counterparty, authorization; "
            "schemas/roe-consent/v2.json). Build one with scripts/write_consent_record.py."
        )
    status = engagement.get("status")
    if status != "active":
        raise ConsentError(f"G-1: consent record engagement.status is {status!r}; it must be 'active'")
    start = _parse_date(authorization.get("effective_date"), "authorization.effective_date")
    end = _parse_date(authorization.get("expiry_date"), "authorization.expiry_date")
    if not start <= today <= end:
        raise ConsentError(
            f"G-1: today ({today.isoformat()}) is outside the authorization window "
            f"{start.isoformat()} to {end.isoformat()}"
        )
    if engagement.get("type") == "third_party_assessment":
        if counterparty.get("is_self_test") is not False:
            raise ConsentError("G-1: a third-party assessment needs counterparty.is_self_test false")
        if authorization.get("signature_method") == SELF_TEST_SIGNATURE:
            raise ConsentError(
                "G-1: a third-party assessment cannot use the self_test_attestation "
                "signature method; it must be counter-signed (docs/external-auth.md §2)"
            )


def authorize_run(
    *,
    run_id: Optional[str],
    tenant_id: str,
    log_dir: Path,
    today: Optional[date] = None,
) -> dict[str, Any]:
    """Return the consent record that authorizes tenant_id for run_id, or raise ConsentError."""
    if not is_tenant_guid(tenant_id):
        raise ConsentError(f"G-1: tenant_id must be a tenant GUID, got {tenant_id!r}")
    if not run_id:
        raise ConsentError(
            "G-1: a run ID is required (--run-id). Every run needs a consent record "
            "for that run ID before the first token request."
        )
    records = find_consent_records(run_id, log_dir)
    if not records:
        raise ConsentError(
            f"G-1: no consent.granted record for run {run_id!r} in {log_dir.name}/. "
            "Write the run's consent record before running any tool (README, Rules of Engagement)."
        )
    tenants = {str(r.get("tenant_id", "")).lower() for r in records}
    if len(tenants) > 1:
        raise ConsentError(f"G-1: run {run_id!r} has consent records for more than one tenant")
    rec = records[-1]
    if str(rec.get("tenant_id", "")).lower() != tenant_id.lower():
        raise ConsentError(
            f"G-1: run {run_id!r} is consented for tenant {rec.get('tenant_id')!r}, "
            f"not {tenant_id!r}"
        )
    if not is_lab_tenant(tenant_id):
        _check_durable(rec, tenant_id, today or datetime.now(timezone.utc).date())
    return rec

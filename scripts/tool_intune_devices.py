#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Rejewski Tool 8 — intune_devices
ATT&CK T1082 System Information Discovery

Enumerates the Intune managed-device inventory via Microsoft Graph
GET /deviceManagement/managedDevices. The managed-device collection is a
system-information goldmine: per device it yields the device name, owner type
(company vs personal), operating system and version, compliance state,
management state, enrollment and last-sync timestamps, the bound Entra device
ID, the assigned user, hardware manufacturer/model, and disk-encryption status.
From this an adversary maps the endpoint estate — which OS versions are in play
(and therefore which client-side exploits apply), which devices are
non-compliant or unencrypted (softer targets), and which users own which
hardware (pivot and targeting data). This is system-information discovery at
fleet scale.

Token acquisition, silent reuse, and CAE/CP1 handling are owned by ADR 0005's
encrypted PersistedTokenCache helper. This tool consumes the token via a
token_getter callable; 401 mid-pagination recovers from the encrypted cache, not
in-memory MSAL state.

No tenant-side app registration is created in the target tenant (ADR 0001 §1,
guardrail G-3). Borrowed first-party client defaults to Microsoft Graph Command
Line Tools (14d82eec) per ADR 0004.

Every emitted invocation writes a replay-log entry under the v0.5 schema with
kind="graph_call". An empty inventory is not an error: the tool prints a notice
to stderr and still writes a graph_call entry with row_count (object_count) 0.

REQUIRED PRIVILEGE:
    GET /deviceManagement/managedDevices requires the
    DeviceManagementManagedDevices.Read.All delegated scope, admin-consented on
    the borrowed Microsoft Graph Command Line Tools client in cloudharbordemo.
    Managed-device enumeration is gated behind an Intune-administrator-class
    grant; it is a post-foothold discovery step, not a first-foothold capability.

Required environment variables:
    AZURE_TENANT_ID            Target tenant ID (cloudharbordemo: 76b87c33-...)
    FOCI_CLIENT_ID             Borrowed first-party client (default: 14d82eec-...)
    COMPROMISED_USER_UPN       Seed user UPN (meganb@cloudharbor-demo.com)
    COMPROMISED_USER_PASSWORD  Seed user password (cache-miss fallback only)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Callable

import requests
from dotenv import load_dotenv

import identity
from replay_log import (
    ReplayLogEntry,
    make_error,
    redact_tenant_id,
    utc_now_iso,
    write_entry,
)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = ["https://graph.microsoft.com/.default"]
GRAPH_ENDPOINT = f"{GRAPH_BASE}/deviceManagement/managedDevices"
# Path recorded on the replay-log request and asserted by the technique doc's
# detection section (MicrosoftGraphActivityLogs RequestUri).
ENDPOINT_PATH = "/deviceManagement/managedDevices"
# $select limits the response to the documented evidence surface. managedDevice
# carries dozens of fields; restricting the projection keeps the read tight and
# the evidence JSON readable.
DEFAULT_SELECT = (
    "id,deviceName,managedDeviceOwnerType,operatingSystem,osVersion,"
    "complianceState,managementState,lastSyncDateTime,enrolledDateTime,"
    "azureADDeviceId,userPrincipalName,userDisplayName,manufacturer,model,"
    "isEncrypted"
)
# Conservative page size: the managedDevices endpoint paginates aggressively and
# does not document a $top maximum. 100 is a safe per-page size; the loop below
# follows @odata.nextLink until the inventory is exhausted.
DEFAULT_TOP = 100
DEFAULT_ROW_CAP = 1000
MAX_RETRIES = 3
USER_AGENT = (
    "rejewski-tool-intune-devices/0.1 "
    "(+https://github.com/Cloud-Harbor-Consulting-LLC/rejewski)"
)
REQ_TIMEOUT = (5, 30)
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPLAY_LOG_DIR = REPO_ROOT / "replay-logs"
TECHNIQUE_ID = "T1082"
TECHNIQUE_NAME = "System Information Discovery"
TOOL_NAME = "tool_intune_devices"
ERROR_TYPE_URN = "urn:rejewski:error:tool-invocation-failed"


def graph_get(
    url: str,
    token: str,
    token_getter: Callable[[], str],
) -> tuple[dict[str, Any], str, int, int]:
    """GET with Retry-After on 429/5xx (max 3) and one 401 cache-backed recovery.

    The 401 path delegates to token_getter, which routes through
    identity.acquire_token (silent reuse from the encrypted cache, ROPC fallback
    on miss). Returns (json_body, current_token, final_http_status,
    retry_count_for_this_call).
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }
    attempted_refresh = False
    retry_count = 0
    for attempt in range(1, MAX_RETRIES + 1):
        resp = requests.get(url, headers=headers, timeout=REQ_TIMEOUT)
        if resp.status_code == 200:
            return resp.json(), token, 200, retry_count
        if resp.status_code == 401 and not attempted_refresh:
            token = token_getter()
            headers["Authorization"] = f"Bearer {token}"
            attempted_refresh = True
            retry_count += 1
            continue
        if resp.status_code == 429 or 500 <= resp.status_code < 600:
            retry_after = int(resp.headers.get("Retry-After", "2"))
            if attempt < MAX_RETRIES:
                time.sleep(retry_after)
                retry_count += 1
                continue
        raise RuntimeError(
            f"{url} -> HTTP {resp.status_code}: {resp.text[:400]}"
        )
    raise RuntimeError(f"{url} -> exhausted {MAX_RETRIES} retries")


def list_managed_devices(
    token: str,
    token_getter: Callable[[], str],
    select: str,
    page_size: int,
    row_cap: int,
    stats: dict[str, int],
) -> list[dict[str, Any]]:
    """Page through GET /deviceManagement/managedDevices until exhausted or the
    G-9 row cap is hit. Unlike the directory endpoints, the Intune device
    inventory routinely spans multiple pages, so @odata.nextLink is followed on
    every run.
    """
    devices: list[dict[str, Any]] = []
    url: str | None = f"{GRAPH_ENDPOINT}?$select={select}&$top={page_size}"
    while url and len(devices) < row_cap:
        body, token, status_code, retries = graph_get(url, token, token_getter)
        stats["page_count"] += 1
        stats["retry_count"] += retries
        stats["last_status"] = status_code
        page = body.get("value", [])
        remaining = row_cap - len(devices)
        devices.extend(page[:remaining])
        if len(devices) >= row_cap:
            break
        url = body.get("@odata.nextLink")
    return devices


def _compute_device_summary(devices: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute Intune-specific aggregate metrics for the evidence JSON output.

    Written into the evidence JSON for detection-engineering consumers only.
    NOT added to the replay-log entry — the v0.5 schema enforces
    additionalProperties: false on the graph_call response branch, so
    device-specific counts would fail schema validation (mirrors the CA-policy
    summary handling in tool_list_ca_policies.py).
    """
    def _count_by(key: str) -> dict[str, int]:
        breakdown: dict[str, int] = {}
        for d in devices:
            value = d.get(key) or "unknown"
            breakdown[value] = breakdown.get(value, 0) + 1
        return breakdown

    compliant = sum(1 for d in devices if d.get("complianceState") == "compliant")
    encrypted = sum(1 for d in devices if d.get("isEncrypted") is True)
    return {
        "device_count": len(devices),
        "devices_compliant": compliant,
        "devices_noncompliant": len(devices) - compliant,
        "devices_encrypted": encrypted,
        "devices_not_encrypted": len(devices) - encrypted,
        "compliance_state_breakdown": _count_by("complianceState"),
        "owner_type_breakdown": _count_by("managedDeviceOwnerType"),
        "operating_system_breakdown": _count_by("operatingSystem"),
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Rejewski Tool 8 - T1082 System Information Discovery (Intune devices)"
    )
    p.add_argument("--select", default=DEFAULT_SELECT, help="OData $select fields")
    p.add_argument(
        "--page-size", type=int, default=DEFAULT_TOP,
        help="$top page size (default: 100; @odata.nextLink is followed until exhausted)",
    )
    p.add_argument(
        "--row-cap", type=int, default=DEFAULT_ROW_CAP,
        help="G-9 enumeration row cap",
    )
    p.add_argument(
        "--output",
        help="optional path to write evidence JSON summary (default: stdout)",
    )
    p.add_argument(
        "--replay-log-dir",
        default=str(DEFAULT_REPLAY_LOG_DIR),
        help=(
            "directory for the replay-log entry "
            "(default: replay-logs/ - gitignored; "
            "use samples/replay-log for canonical runs)"
        ),
    )
    p.add_argument(
        "--emit",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "write the replay-log entry for this run (default: on, honoring the "
            "G-5 evidence-capture rule). Pass --no-emit for a local dry run that "
            "performs the Graph read but writes no entry."
        ),
    )
    p.add_argument(
        "--run-id",
        default=None,
        help="run binding key (e.g. R009); propagated to replay-log entry",
    )
    return p.parse_args()


def main() -> int:
    load_dotenv()
    tenant_id = os.environ["AZURE_TENANT_ID"]
    client_id = os.environ.get("FOCI_CLIENT_ID", identity.DEFAULT_CLIENT_ID)
    upn = os.environ["COMPROMISED_USER_UPN"]
    password = os.environ.get("COMPROMISED_USER_PASSWORD")

    args = parse_args()
    replay_log_dir = Path(args.replay_log_dir)

    def token_getter() -> str:
        result = identity.acquire_token(
            actor_upn=upn,
            tenant_id=tenant_id,
            client_id=client_id,
            scopes=GRAPH_SCOPE,
            password=password,
            replay_log_dir=replay_log_dir,
            run_id=args.run_id,
        )
        return result["access_token"]

    started_at = utc_now_iso()
    initial_url = f"{GRAPH_ENDPOINT}?$select={args.select}&$top={args.page_size}"
    request_obj: dict[str, Any] = {
        "method": "GET",
        "url": initial_url,
        "headers": {
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json",
        },
    }

    stats: dict[str, int] = {"page_count": 0, "retry_count": 0, "last_status": 0}
    devices: list[dict[str, Any]] = []
    error_block: dict[str, Any] | None = None
    outcome: str

    try:
        token = token_getter()
        devices = list_managed_devices(
            token=token,
            token_getter=token_getter,
            select=args.select,
            page_size=args.page_size,
            row_cap=args.row_cap,
            stats=stats,
        )
        row_cap_hit = len(devices) >= args.row_cap
        outcome = "row_cap_hit" if row_cap_hit else "success"
    except (RuntimeError, requests.RequestException) as exc:
        outcome = "error"
        error_block = make_error(
            type_=ERROR_TYPE_URN,
            message=str(exc),
            status_code=stats["last_status"] or None,
        )

    completed_at = utc_now_iso()

    # Empty inventory is a valid, non-error outcome (G-5): notice to stderr keeps
    # stdout machine-readable, and the graph_call entry below still records
    # object_count 0.
    if outcome != "error" and not devices:
        print("No managed devices found", file=sys.stderr)

    response_obj: dict[str, Any] = {
        "status_code": stats["last_status"] if stats["last_status"] else (200 if outcome != "error" else 0),
        "page_count": stats["page_count"],
        "row_count": len(devices),
        "row_cap": args.row_cap,
        "row_cap_hit": len(devices) >= args.row_cap,
        "retry_count": stats["retry_count"],
    }

    replay_path: Path | None = None
    if args.emit:
        replay_entry = ReplayLogEntry(
            kind="graph_call",
            tool=TOOL_NAME,
            technique_id=TECHNIQUE_ID,
            technique_name=TECHNIQUE_NAME,
            tenant_id=tenant_id,
            borrowed_client_id=client_id,
            actor_upn=upn,
            started_at_utc=started_at,
            completed_at_utc=completed_at,
            request=request_obj,
            response=response_obj,
            outcome=outcome,
            error=error_block,
            run_id=args.run_id,
        )
        replay_path = write_entry(replay_entry, log_dir=replay_log_dir)

    device_summary = _compute_device_summary(devices) if outcome != "error" else {}

    evidence = {
        "tool": TOOL_NAME,
        "technique": TECHNIQUE_ID,
        "tenant_id": redact_tenant_id(tenant_id),
        "borrowed_client_id": client_id,
        "actor_upn": upn,
        "started_at_utc": started_at,
        "completed_at_utc": completed_at,
        "endpoint": ENDPOINT_PATH,
        "select": args.select,
        "page_size": args.page_size,
        "row_cap": args.row_cap,
        "row_count": len(devices),
        "row_cap_hit": len(devices) >= args.row_cap,
        "page_count": stats["page_count"],
        "retry_count": stats["retry_count"],
        "outcome": outcome,
        "replay_log_entry": str(replay_path) if replay_path else None,
        **device_summary,
        "managed_devices": devices,
    }
    if error_block is not None:
        evidence["error"] = error_block

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(evidence, fh, indent=2)
    else:
        json.dump(evidence, sys.stdout, indent=2)
        sys.stdout.write("\n")
        sys.stdout.flush()

    return 0 if outcome in {"success", "row_cap_hit"} else 1


if __name__ == "__main__":
    sys.exit(main())

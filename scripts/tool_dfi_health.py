#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Rejewski Tool 7 — dfi_health
ATT&CK T1518.001 Software Discovery: Security Software Discovery

Enumerates the Microsoft Defender for Identity (DfI) sensor fleet via Microsoft
Graph GET /security/identities/sensors (namespace microsoft.graph.security).
Reading the sensor inventory tells an adversary exactly where Defender for
Identity is watching: which domain controllers, AD FS, AD CS, and Entra Connect
hosts carry a sensor, which sensors are healthy, which are outdated or
unreachable, and how many open health issues exist per sensor. A coverage gap
(an un-sensored domain controller, a stopped service, an unreachable sensor)
identifies the blind spots where on-premises Kerberos- and NTLM-based attacks go
undetected. This is security-software discovery: the adversary inventories the
defensive product surface to guide later technique selection and detection
evasion.

Token acquisition, silent reuse, and CAE/CP1 handling are owned by ADR 0005's
encrypted PersistedTokenCache helper. This tool consumes the token via a
token_getter callable; 401 mid-pagination recovers from the encrypted cache, not
in-memory MSAL state.

No tenant-side app registration is created in the target tenant (ADR 0001 §1,
guardrail G-3). Borrowed first-party client defaults to Microsoft Graph Command
Line Tools (14d82eec) per ADR 0004.

Every emitted invocation writes a replay-log entry under the v0.5 schema with
kind="graph_call". An empty fleet is not an error: the tool prints a notice to
stderr and still writes a graph_call entry with row_count (object_count) 0.

REQUIRED PRIVILEGE:
    GET /security/identities/sensors requires the SecurityIdentitiesSensors.Read.All
    delegated scope, admin-consented on the borrowed Microsoft Graph Command Line
    Tools client in the lab tenant. Like CA-policy enumeration (Tool 4), sensor
    enumeration is a post-foothold discovery step: it requires a Defender XDR /
    Security Reader-class grant, not an ordinary licensed user.

Required environment variables:
    AZURE_TENANT_ID            Target tenant ID (your lab or consented tenant GUID)
    FOCI_CLIENT_ID             Borrowed first-party client (default: 14d82eec-...)
    COMPROMISED_USER_UPN       Seed user UPN (e.g. meganb@<lab-domain>)
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
GRAPH_ENDPOINT = f"{GRAPH_BASE}/security/identities/sensors"
# Path recorded on the replay-log request and asserted by the technique doc's
# detection section (MicrosoftGraphActivityLogs RequestUri).
ENDPOINT_PATH = "/security/identities/sensors"
# Fields surfaced per sensor object. The sensors endpoint does not document a
# $select contract, so the full object is requested and the surface is projected
# locally (see _project_sensor) into the evidence JSON.
SENSOR_FIELDS = (
    "id",
    "displayName",
    "sensorType",
    "version",
    "deploymentStatus",
    "healthStatus",
    "openHealthIssuesCount",
    "domainName",
    "serviceStatus",
    "createdDateTime",
)
# Conservative page size: the sensors endpoint maximum $top is not documented by
# Microsoft. The DfI fleet is small in every realistic tenant; 100 avoids a 400
# from an undocumented cap while still paginating defensively via @odata.nextLink.
DEFAULT_TOP = 100
DEFAULT_ROW_CAP = 1000
MAX_RETRIES = 3
USER_AGENT = (
    "rejewski-tool-dfi-health/0.1 "
    "(+https://github.com/Cloud-Harbor-Consulting-LLC/rejewski)"
)
REQ_TIMEOUT = (5, 30)
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPLAY_LOG_DIR = REPO_ROOT / "replay-logs"
TECHNIQUE_ID = "T1518.001"
TECHNIQUE_NAME = "Software Discovery: Security Software Discovery"
TOOL_NAME = "tool_dfi_health"
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


def list_sensors(
    token: str,
    token_getter: Callable[[], str],
    page_size: int,
    row_cap: int,
    stats: dict[str, int],
) -> list[dict[str, Any]]:
    """Page through GET /security/identities/sensors until exhausted or the G-9
    row cap is hit. The DfI fleet returns in a single page in every realistic
    tenant; pagination is implemented defensively in case that changes.
    """
    sensors: list[dict[str, Any]] = []
    url: str | None = f"{GRAPH_ENDPOINT}?$top={page_size}"
    while url and len(sensors) < row_cap:
        body, token, status_code, retries = graph_get(url, token, token_getter)
        stats["page_count"] += 1
        stats["retry_count"] += retries
        stats["last_status"] = status_code
        page = body.get("value", [])
        remaining = row_cap - len(sensors)
        sensors.extend(page[:remaining])
        if len(sensors) >= row_cap:
            break
        url = body.get("@odata.nextLink")
    return sensors


def _project_sensor(sensor: dict[str, Any]) -> dict[str, Any]:
    """Project a raw sensor object down to the documented evidence surface."""
    return {field: sensor.get(field) for field in SENSOR_FIELDS}


def _compute_sensor_summary(sensors: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute DfI-specific aggregate metrics for the evidence JSON output.

    These metrics are written into the evidence JSON for detection-engineering
    consumers only. They are NOT added to the replay-log entry — the v0.5 schema
    enforces additionalProperties: false on the graph_call response branch, so
    sensor-specific counts would fail schema validation (mirrors the CA-policy
    summary handling in tool_list_ca_policies.py).
    """
    def _count_by(key: str) -> dict[str, int]:
        breakdown: dict[str, int] = {}
        for s in sensors:
            value = s.get(key) or "unknown"
            breakdown[value] = breakdown.get(value, 0) + 1
        return breakdown

    healthy = sum(1 for s in sensors if s.get("healthStatus") == "healthy")
    open_issues = sum(int(s.get("openHealthIssuesCount") or 0) for s in sensors)
    return {
        "sensor_count": len(sensors),
        "sensors_healthy": healthy,
        "sensors_not_healthy": len(sensors) - healthy,
        "open_health_issues_total": open_issues,
        "health_status_breakdown": _count_by("healthStatus"),
        "deployment_status_breakdown": _count_by("deploymentStatus"),
        "service_status_breakdown": _count_by("serviceStatus"),
        "sensor_type_breakdown": _count_by("sensorType"),
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Rejewski Tool 7 - T1518.001 Security Software Discovery (DfI sensors)"
    )
    p.add_argument(
        "--page-size", type=int, default=DEFAULT_TOP,
        help=(
            "$top page size for sensors (default: 100; the endpoint maximum is "
            "undocumented — reduce if a 400 Bad Request is returned)"
        ),
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
        help="run binding key (e.g. R008); propagated to replay-log entry",
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
    initial_url = f"{GRAPH_ENDPOINT}?$top={args.page_size}"
    request_obj: dict[str, Any] = {
        "method": "GET",
        "url": initial_url,
        "headers": {
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json",
        },
    }

    stats: dict[str, int] = {"page_count": 0, "retry_count": 0, "last_status": 0}
    sensors: list[dict[str, Any]] = []
    error_block: dict[str, Any] | None = None
    outcome: str

    try:
        token = token_getter()
        sensors = list_sensors(
            token=token,
            token_getter=token_getter,
            page_size=args.page_size,
            row_cap=args.row_cap,
            stats=stats,
        )
        row_cap_hit = len(sensors) >= args.row_cap
        outcome = "row_cap_hit" if row_cap_hit else "success"
    except (RuntimeError, requests.RequestException) as exc:
        outcome = "error"
        error_block = make_error(
            type_=ERROR_TYPE_URN,
            message=str(exc),
            status_code=stats["last_status"] or None,
        )

    completed_at = utc_now_iso()

    # Empty fleet is a valid, non-error outcome (G-5): notice to stderr keeps
    # stdout machine-readable, and the graph_call entry below still records
    # object_count 0.
    if outcome != "error" and not sensors:
        print("No DfI sensors found", file=sys.stderr)

    response_obj: dict[str, Any] = {
        "status_code": stats["last_status"] if stats["last_status"] else (200 if outcome != "error" else 0),
        "page_count": stats["page_count"],
        "row_count": len(sensors),
        "row_cap": args.row_cap,
        "row_cap_hit": len(sensors) >= args.row_cap,
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

    projected = [_project_sensor(s) for s in sensors]
    sensor_summary = _compute_sensor_summary(projected) if outcome != "error" else {}

    evidence = {
        "tool": TOOL_NAME,
        "technique": TECHNIQUE_ID,
        "tenant_id": redact_tenant_id(tenant_id),
        "borrowed_client_id": client_id,
        "actor_upn": upn,
        "started_at_utc": started_at,
        "completed_at_utc": completed_at,
        "endpoint": ENDPOINT_PATH,
        "page_size": args.page_size,
        "row_cap": args.row_cap,
        "row_count": len(sensors),
        "row_cap_hit": len(sensors) >= args.row_cap,
        "page_count": stats["page_count"],
        "retry_count": stats["retry_count"],
        "outcome": outcome,
        "replay_log_entry": str(replay_path) if replay_path else None,
        **sensor_summary,
        "sensors": projected,
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

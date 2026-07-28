#!/usr/bin/env python3
"""
Rejewski Sprint 3 W12 Tool 12 — list_security_alerts
ATT&CK T1654 Log Enumeration (Surface B — Security Alerts)

Enumerates Microsoft Defender XDR security alerts via Microsoft Graph
GET /security/alerts_v2. Where Surface A (Tool 10, scripts/tool_signin_logs.py)
reads the tenant's authentication telemetry, Surface B reads the defender's own
alert queue: what has already been detected, which categories are firing, which
alerts are active versus resolved, and whether any investigation is assigned.

An adversary holding this view learns whether their earlier enumeration activity
(T1087.004, T1526, T1580) has generated alerts, can select techniques and timing
to avoid future detection, and can confirm whether post-compromise activity has
been noticed. Reading the alert queue is reflexive — a member account reading the
defender's alerts from inside the tenant should itself surface as a Defender for
Cloud Apps anomaly on the first non-baseline read.

Token acquisition, silent reuse, and CAE/CP1 handling are owned by ADR 0005's
encrypted PersistedTokenCache helper. This tool consumes the token via a
token_getter callable; 401 mid-pagination recovers from the encrypted cache, not
in-memory MSAL state.

No tenant-side app registration is created in the target tenant (ADR 0001 §1,
guardrail G-3). Borrowed first-party client defaults to Microsoft Graph Command
Line Tools (14d82eec) per ADR 0004 and the ADR 0006 FOCI client allowlist.

Every emitted invocation writes a replay-log entry under the v0.5 schema with
kind="graph_call". A tenant with no matching alerts is not an error: the tool
prints a notice to stderr and still writes a graph_call entry with row_count
(object_count) 0.

REQUIRED PRIVILEGE — SCOPE AND DIRECTORY ROLE:
    GET /security/alerts_v2 requires BOTH:
      (1) SecurityAlert.Read.All delegated scope — admin-consented on the
          borrowed Microsoft Graph Command Line Tools client (14d82eec) in
          cloudharbordemo. Without it the call returns HTTP 403.
      (2) One of the following Entra directory roles on the signed-in user:
            - Security Reader (minimum)
            - Security Operator
            - Security Administrator
            - Global Reader
            - Global Administrator
    A member account without a qualifying role receives HTTP 403 regardless of
    scope consent. In cloudharbordemo, meganb@cloudharbor-demo.com must hold
    Security Reader or higher.

See docs/techniques/T1654.md Surface B for the full module.

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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

import requests
from dotenv import load_dotenv

import identity
from replay_log import (
    ReplayLogEntry,
    make_error,
    utc_now_iso,
    write_entry,
)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = ["https://graph.microsoft.com/.default"]
GRAPH_ENDPOINT = f"{GRAPH_BASE}/security/alerts_v2"
# Path recorded on the replay-log request and asserted by the technique doc's
# detection section (MicrosoftGraphActivityLogs RequestUri).
ENDPOINT_PATH = "/security/alerts_v2"
# $select keeps the projection to the triage-relevant fields. `evidence` and
# `comments` are navigation properties that expand to large payloads and are
# deliberately out of scope for this surface (see T1654.md Surface B Limitations).
DEFAULT_SELECT = (
    "id,title,severity,status,classification,determination,category,"
    "alertType,createdDateTime,lastModifiedDateTime,assignedTo"
)
DEFAULT_TOP = 100
DEFAULT_ROW_CAP = 1000
DEFAULT_DAYS = 30
MAX_RETRIES = 3
USER_AGENT = (
    "rejewski-tool-list-security-alerts/0.1 "
    "(+https://github.com/Cloud-Harbor-Consulting-LLC/rejewski)"
)
REQ_TIMEOUT = (5, 30)
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPLAY_LOG_DIR = REPO_ROOT / "replay-logs"
TECHNIQUE_ID = "T1654"
TECHNIQUE_NAME = "Log Enumeration"
TOOL_NAME = "tool_list_security_alerts"
ERROR_TYPE_URN = "urn:rejewski:error:tool-invocation-failed"

# Severity buckets pre-seeded in the evidence aggregate so a zero count is
# reported explicitly rather than being absent from the JSON.
SEVERITY_BUCKETS = ("informational", "low", "medium", "high")
# Status buckets pre-seeded likewise. The v1.0 alertStatus enum for
# /security/alerts_v2 is unknown | new | inProgress | resolved |
# unknownFutureValue — "new" is the value for a freshly-raised alert. "active"
# is a legacy /security/alerts (v1) value and is NOT valid on v1.0; it was
# corrected to "new" after the PR #76 delivery review. Any status the API
# returns outside these buckets is still counted dynamically, so no alert is
# dropped if Microsoft extends the enum.
STATUS_BUCKETS = ("new", "inProgress", "resolved")


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


def _build_filter(
    start_dt_iso: str | None,
    severity: str | None,
    status: str | None,
) -> str:
    """Build the $filter string from the optional date window, severity, and
    status filters. Clauses are combined with `and`. Returns "" when no filter
    applies (--days 0 with no severity/status), in which case the caller omits
    the $filter query parameter entirely.
    """
    clauses: list[str] = []
    if start_dt_iso:
        clauses.append(f"createdDateTime ge {start_dt_iso}")
    if severity:
        clauses.append(f"severity eq '{severity}'")
    if status:
        clauses.append(f"status eq '{status}'")
    return " and ".join(clauses)


def _build_url(select: str, filter_str: str, page_size: int) -> str:
    """Compose the initial request URL. $filter is omitted when empty."""
    url = f"{GRAPH_ENDPOINT}?$select={select}"
    if filter_str:
        quoted_filter = requests.utils.quote(filter_str, safe="' ")
        url += f"&$filter={quoted_filter}"
    return url + f"&$top={page_size}"


def list_security_alerts(
    token: str,
    token_getter: Callable[[], str],
    select: str,
    filter_str: str,
    page_size: int,
    row_cap: int,
    stats: dict[str, int],
) -> list[dict[str, Any]]:
    """Page through GET /security/alerts_v2 until exhausted or the G-9 row cap
    is hit. The cap applies to total alerts collected, not per page.
    """
    alerts: list[dict[str, Any]] = []
    url: str | None = _build_url(select, filter_str, page_size)
    while url and len(alerts) < row_cap:
        body, token, status_code, retries = graph_get(url, token, token_getter)
        stats["page_count"] += 1
        stats["retry_count"] += retries
        stats["last_status"] = status_code
        page = body.get("value", [])
        remaining = row_cap - len(alerts)
        alerts.extend(page[:remaining])
        if len(alerts) >= row_cap:
            break
        url = body.get("@odata.nextLink")
    return alerts


def _compute_alert_summary(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute alert-specific aggregate metrics for the evidence JSON output.

    Written into the evidence JSON for detection-engineering consumers only.
    NOT added to the replay-log entry — the v0.5 schema enforces
    additionalProperties: false on the graph_call response branch, so
    alert-specific counts would fail schema validation (mirrors the sign-in
    summary handling in tool_signin_logs.py).

    Severity and status buckets are pre-seeded at 0 so an absent category reads
    as an explicit zero; any value the API returns outside those buckets is
    still counted, so no alert is dropped from the totals.
    """
    by_severity: dict[str, int] = {k: 0 for k in SEVERITY_BUCKETS}
    by_status: dict[str, int] = {k: 0 for k in STATUS_BUCKETS}
    by_category: dict[str, int] = {}

    for a in alerts:
        severity = a.get("severity") or "unknown"
        by_severity[severity] = by_severity.get(severity, 0) + 1

        status = a.get("status") or "unknown"
        by_status[status] = by_status.get(status, 0) + 1

        category = a.get("category") or "unknown"
        by_category[category] = by_category.get(category, 0) + 1

    return {
        "total_alerts": len(alerts),
        "by_severity": by_severity,
        "by_status": by_status,
        "by_category": by_category,
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Rejewski Tool 12 - T1654 Log Enumeration "
            "(Defender XDR security alerts, Surface B)"
        )
    )
    p.add_argument("--select", default=DEFAULT_SELECT, help="OData $select fields")
    p.add_argument(
        "--page-size", type=int, default=DEFAULT_TOP,
        help="$top page size (default: 100; @odata.nextLink is followed until exhausted)",
    )
    p.add_argument(
        "--row-cap", type=int, default=DEFAULT_ROW_CAP,
        help="G-9 enumeration row cap applied to total alerts (not per page)",
    )
    p.add_argument(
        "--days", type=int, default=DEFAULT_DAYS,
        help=(
            "lookback window in days for the createdDateTime $filter "
            "(default: 30). Pass 0 to disable the date filter."
        ),
    )
    p.add_argument(
        "--severity",
        choices=["informational", "low", "medium", "high"],
        default=None,
        help="optional severity filter; omit to return all severities",
    )
    p.add_argument(
        "--status",
        choices=["new", "inProgress", "resolved"],
        default=None,
        help="optional status filter; omit to return all statuses",
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
        help="run binding key (e.g. R012); propagated to replay-log entry",
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

    # Window starts `--days` ago in UTC; --days 0 disables the date clause.
    # Microsoft Graph requires ISO-8601 with a Z suffix for OData datetime
    # literals.
    start_dt_iso: str | None = None
    if args.days > 0:
        start_dt = datetime.now(timezone.utc) - timedelta(days=args.days)
        start_dt_iso = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    filter_str = _build_filter(start_dt_iso, args.severity, args.status)

    started_at = utc_now_iso()
    initial_url = _build_url(args.select, filter_str, args.page_size)
    request_obj: dict[str, Any] = {
        "method": "GET",
        "url": initial_url,
        "headers": {
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json",
        },
    }

    stats: dict[str, int] = {"page_count": 0, "retry_count": 0, "last_status": 0}
    alerts: list[dict[str, Any]] = []
    error_block: dict[str, Any] | None = None
    outcome: str

    try:
        token = token_getter()
        alerts = list_security_alerts(
            token=token,
            token_getter=token_getter,
            select=args.select,
            filter_str=filter_str,
            page_size=args.page_size,
            row_cap=args.row_cap,
            stats=stats,
        )
        row_cap_hit = len(alerts) >= args.row_cap
        outcome = "row_cap_hit" if row_cap_hit else "success"
    except (RuntimeError, requests.RequestException) as exc:
        outcome = "error"
        error_block = make_error(
            type_=ERROR_TYPE_URN,
            message=str(exc),
            status_code=stats["last_status"] or None,
        )
        # A 403 here is nearly always a missing prerequisite rather than a code
        # defect; tell the operator exactly what to check instead of surfacing a
        # bare HTTP error.
        if "HTTP 403" in str(exc):
            print(
                "HTTP 403 — access denied reading /security/alerts_v2.\n"
                "  Confirm BOTH prerequisites in the target tenant:\n"
                "    1. SecurityAlert.Read.All is admin-consented on the borrowed\n"
                f"       client {client_id}.\n"
                "    2. The signed-in account holds Security Reader (or Security\n"
                "       Operator, Security Administrator, Global Reader, or Global\n"
                "       Administrator).\n"
                "  See docs/techniques/T1654.md Surface B for operator setup.",
                file=sys.stderr,
            )
        else:
            print(f"error: {exc}", file=sys.stderr)

    completed_at = utc_now_iso()

    # Empty result is a valid, non-error outcome (G-5): notice to stderr keeps
    # stdout machine-readable, and the graph_call entry below still records
    # row_count (object_count) 0.
    if outcome != "error" and not alerts:
        print("No alerts found for the specified period", file=sys.stderr)

    response_obj: dict[str, Any] = {
        "status_code": stats["last_status"] if stats["last_status"] else (200 if outcome != "error" else 0),
        "page_count": stats["page_count"],
        "row_count": len(alerts),
        "row_cap": args.row_cap,
        "row_cap_hit": len(alerts) >= args.row_cap,
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

    alert_summary = _compute_alert_summary(alerts) if outcome != "error" else {}

    evidence = {
        "tool": TOOL_NAME,
        "technique": TECHNIQUE_ID,
        "tenant_id": tenant_id,
        "borrowed_client_id": client_id,
        "actor_upn": upn,
        "started_at_utc": started_at,
        "completed_at_utc": completed_at,
        "endpoint": ENDPOINT_PATH,
        "select": args.select,
        "filter": filter_str,
        "days": args.days,
        "severity_filter": args.severity,
        "status_filter": args.status,
        "page_size": args.page_size,
        "row_cap": args.row_cap,
        "row_count": len(alerts),
        "row_cap_hit": len(alerts) >= args.row_cap,
        "page_count": stats["page_count"],
        "retry_count": stats["retry_count"],
        "outcome": outcome,
        "replay_log_entry": str(replay_path) if replay_path else None,
        **alert_summary,
        "alerts": alerts,
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

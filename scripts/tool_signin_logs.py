#!/usr/bin/env python3
"""
Rejewski Tool 10 — signin_logs
ATT&CK T1654 Log Enumeration

Reads Entra ID sign-in logs via Microsoft Graph GET /auditLogs/signIns (v1.0).
The sign-in log is an authentication-history goldmine: per event it surfaces
the identity that signed in (UPN, userId), the application that requested the
token (appId, appDisplayName), the IP address, the client app type, whether
the sign-in was interactive, the aggregate risk level, and the success/failure
status. An adversary holding a Reports Reader / Security Reader (or higher)
delegated grant uses this telemetry to map authentication patterns: which admin
accounts have signed in recently, which service principals are actively pulling
tokens, which IP ranges are normal for which users, where MFA failures cluster,
and which non-interactive (token-reuse) sign-ins might indicate long-dwell
sessions a defender has not yet noticed. The log read is itself the discovery —
no content collection happens here; only the metadata that tells the adversary
where to look next and how the defender's own monitoring baseline behaves.

Token acquisition, silent reuse, and CAE/CP1 handling are owned by ADR 0005's
encrypted PersistedTokenCache helper. This tool consumes the token via a
token_getter callable; 401 mid-pagination recovers from the encrypted cache, not
in-memory MSAL state.

No tenant-side app registration is created in the target tenant (ADR 0001 §1,
guardrail G-3). Borrowed first-party client defaults to Microsoft Graph Command
Line Tools (14d82eec) per ADR 0004.

Every emitted invocation writes a replay-log entry under the v0.5 schema with
kind="graph_call". A date window with no sign-ins is not an error: the tool
prints a notice to stderr and still writes a graph_call entry with row_count
(object_count) 0.

REQUIRED PRIVILEGE:
    GET /auditLogs/signIns requires the AuditLog.Read.All delegated scope,
    admin-consented on the borrowed Microsoft Graph Command Line Tools client in
    cloudharbordemo. Unlike T1580 (which is openly readable to any member with
    the scope consented), sign-in log enumeration carries a SECOND privilege
    prerequisite: the signed-in operator user must hold one of the following
    Entra directory roles, or the API returns 403 Forbidden regardless of scope
    consent — Global Reader, Reports Reader, Security Administrator, Security
    Operator, or Security Reader. This is the same role-gated pattern as
    CA-policy enumeration (T1526 requires Security Reader). See
    docs/techniques/T1654.md §Required privilege for the full operator
    prerequisite and attack-strategy note.

See docs/techniques/T1654.md for the full module.

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
GRAPH_ENDPOINT = f"{GRAPH_BASE}/auditLogs/signIns"
# Path recorded on the replay-log request and asserted by the technique doc's
# detection section (MicrosoftGraphActivityLogs RequestUri).
ENDPOINT_PATH = "/auditLogs/signIns"
# $select limits the response to the identity, risk, app, and status fields
# Rejewski projects into the evidence JSON. The signIn object carries dozens of
# fields (full deviceDetail, location, appliedConditionalAccessPolicies); keeping
# the projection tight keeps the read cheap and the evidence file readable.
# Note: signInEventType is a beta-only property — querying it via /v1.0 returns
# HTTP 400 "Could not find a property named 'signInEventType' on type
# 'microsoft.graph.signIn'". v1.0 /auditLogs/signIns returns interactive user
# sign-ins; isInteractive is retained for the evidence aggregate.
DEFAULT_SELECT = (
    "id,createdDateTime,userDisplayName,userPrincipalName,userId,appId,"
    "appDisplayName,ipAddress,clientAppUsed,isInteractive,"
    "riskLevelAggregated,riskState,status"
)
# /auditLogs/signIns enforces a $top maximum of 1000; 100 keeps each page small
# enough to bound the per-call latency while the pagination loop still walks the
# full window via @odata.nextLink.
DEFAULT_TOP = 100
DEFAULT_ROW_CAP = 1000
DEFAULT_DAYS = 7
MAX_RETRIES = 3
USER_AGENT = (
    "rejewski-tool-signin-logs/0.1 "
    "(+https://github.com/Cloud-Harbor-Consulting-LLC/rejewski)"
)
REQ_TIMEOUT = (5, 30)
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPLAY_LOG_DIR = REPO_ROOT / "replay-logs"
TECHNIQUE_ID = "T1654"
TECHNIQUE_NAME = "Log Enumeration"
TOOL_NAME = "tool_signin_logs"
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


def _build_filter(start_dt_iso: str) -> str:
    """Build the $filter string. createdDateTime is mandatory — without it the
    /auditLogs/signIns endpoint times out on large tenants.
    """
    return f"createdDateTime ge {start_dt_iso}"


def list_sign_ins(
    token: str,
    token_getter: Callable[[], str],
    select: str,
    filter_str: str,
    page_size: int,
    row_cap: int,
    stats: dict[str, int],
) -> list[dict[str, Any]]:
    """Page through GET /auditLogs/signIns until exhausted or the G-9 row cap is
    hit. The sign-in log routinely spans many pages over a 7-day window in a
    busy tenant, so @odata.nextLink is followed on every run and the row cap is
    applied to total rows collected (not per page).
    """
    sign_ins: list[dict[str, Any]] = []
    quoted_filter = requests.utils.quote(filter_str, safe="' ")
    url: str | None = (
        f"{GRAPH_ENDPOINT}?$select={select}"
        f"&$filter={quoted_filter}"
        f"&$top={page_size}"
    )
    while url and len(sign_ins) < row_cap:
        body, token, status_code, retries = graph_get(url, token, token_getter)
        stats["page_count"] += 1
        stats["retry_count"] += retries
        stats["last_status"] = status_code
        page = body.get("value", [])
        remaining = row_cap - len(sign_ins)
        sign_ins.extend(page[:remaining])
        if len(sign_ins) >= row_cap:
            break
        url = body.get("@odata.nextLink")
    return sign_ins


def _compute_signin_summary(sign_ins: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute sign-in-specific aggregate metrics for the evidence JSON output.

    Written into the evidence JSON for detection-engineering consumers only.
    NOT added to the replay-log entry — the v0.5 schema enforces
    additionalProperties: false on the graph_call response branch, so
    sign-in-specific counts would fail schema validation.
    """
    by_risk: dict[str, int] = {
        "none": 0, "low": 0, "medium": 0, "high": 0, "hidden": 0,
    }
    interactive_count = 0
    non_interactive_count = 0
    failed = 0
    apps: set[str] = set()
    users: set[str] = set()
    for s in sign_ins:
        if s.get("isInteractive") is True:
            interactive_count += 1
        else:
            non_interactive_count += 1

        risk = s.get("riskLevelAggregated") or "none"
        if risk in by_risk:
            by_risk[risk] += 1
        else:
            by_risk[risk] = by_risk.get(risk, 0) + 1

        status = s.get("status") or {}
        if isinstance(status, dict) and status.get("errorCode", 0) != 0:
            failed += 1

        app_name = s.get("appDisplayName")
        if app_name:
            apps.add(app_name)
        uid = s.get("userId")
        if uid:
            users.add(uid)

    return {
        "total_sign_ins": len(sign_ins),
        "interactive_count": interactive_count,
        "non_interactive_count": non_interactive_count,
        "by_risk_level": by_risk,
        "failed_count": failed,
        "unique_apps": len(apps),
        "unique_users": len(users),
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Rejewski Tool 10 - T1654 Log Enumeration (Entra sign-in logs)"
    )
    p.add_argument("--select", default=DEFAULT_SELECT, help="OData $select fields")
    p.add_argument(
        "--page-size", type=int, default=DEFAULT_TOP,
        help="$top page size (default: 100; @odata.nextLink is followed until exhausted)",
    )
    p.add_argument(
        "--row-cap", type=int, default=DEFAULT_ROW_CAP,
        help="G-9 enumeration row cap applied to total sign-ins (not per page)",
    )
    p.add_argument(
        "--days", type=int, default=DEFAULT_DAYS,
        help=(
            "lookback window in days (default: 7). The createdDateTime $filter is "
            "MANDATORY — without it, /auditLogs/signIns times out on large tenants."
        ),
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

    # Window starts `--days` ago in UTC. Microsoft Graph requires ISO-8601 with
    # a Z suffix for OData datetime literals on /auditLogs/signIns.
    start_dt = datetime.now(timezone.utc) - timedelta(days=args.days)
    start_dt_iso = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    filter_str = _build_filter(start_dt_iso)

    started_at = utc_now_iso()
    quoted_filter = requests.utils.quote(filter_str, safe="' ")
    initial_url = (
        f"{GRAPH_ENDPOINT}?$select={args.select}"
        f"&$filter={quoted_filter}"
        f"&$top={args.page_size}"
    )
    request_obj: dict[str, Any] = {
        "method": "GET",
        "url": initial_url,
        "headers": {
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json",
        },
    }

    stats: dict[str, int] = {"page_count": 0, "retry_count": 0, "last_status": 0}
    sign_ins: list[dict[str, Any]] = []
    error_block: dict[str, Any] | None = None
    outcome: str

    try:
        token = token_getter()
        sign_ins = list_sign_ins(
            token=token,
            token_getter=token_getter,
            select=args.select,
            filter_str=filter_str,
            page_size=args.page_size,
            row_cap=args.row_cap,
            stats=stats,
        )
        row_cap_hit = len(sign_ins) >= args.row_cap
        outcome = "row_cap_hit" if row_cap_hit else "success"
    except (RuntimeError, requests.RequestException) as exc:
        outcome = "error"
        error_block = make_error(
            type_=ERROR_TYPE_URN,
            message=str(exc),
            status_code=stats["last_status"] or None,
        )

    completed_at = utc_now_iso()

    # Empty window is a valid, non-error outcome (G-5): notice to stderr keeps
    # stdout machine-readable, and the graph_call entry below still records
    # object_count 0.
    if outcome != "error" and not sign_ins:
        print("No sign-ins found for the specified period", file=sys.stderr)

    response_obj: dict[str, Any] = {
        "status_code": stats["last_status"] if stats["last_status"] else (200 if outcome != "error" else 0),
        "page_count": stats["page_count"],
        "row_count": len(sign_ins),
        "row_cap": args.row_cap,
        "row_cap_hit": len(sign_ins) >= args.row_cap,
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

    signin_summary = _compute_signin_summary(sign_ins) if outcome != "error" else {}

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
        "page_size": args.page_size,
        "row_cap": args.row_cap,
        "row_count": len(sign_ins),
        "row_cap_hit": len(sign_ins) >= args.row_cap,
        "page_count": stats["page_count"],
        "retry_count": stats["retry_count"],
        "outcome": outcome,
        "replay_log_entry": str(replay_path) if replay_path else None,
        **signin_summary,
        "sign_ins": sign_ins,
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

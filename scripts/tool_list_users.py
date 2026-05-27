#!/usr/bin/env python3
"""
Rejewski Sprint 1 Tool 1 — list_users
ATT&CK T1087.004 Account Discovery: Cloud Account

Enumerates Entra ID users via Microsoft Graph GET /users using a delegated
token acquired through the shared scripts/identity.acquire_token helper
(ADR-0005). The helper handles MSAL ROPC on first invocation, encrypted
persistence via msal-extensions, and silent reuse on every subsequent run.

Every invocation writes a replay-log entry (success, error, throttled, or
row_cap_hit) to the configured replay-log directory. Default is
replay-logs/ (gitignored). For canonical evidence runs, pass
--replay-log-dir samples/replay-log to land the entry under samples/.

Reads creds from .env. Writes JSON evidence to stdout (default) or to a
file under .replay/ when --output is supplied. Honors guardrail G-9
enumeration row cap.

Required environment variables:
    AZURE_TENANT_ID            Target tenant ID (cloudharbordemo: 76b87c33-...)
    FOCI_CLIENT_ID             Borrowed first-party client (default: 14d82eec-...)
    COMPROMISED_USER_UPN       Seed user UPN (e.g. meganb@cloudharbor-demo.com)
    COMPROMISED_USER_PASSWORD  Seed user password (only needed on cache miss)
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
    utc_now_iso,
    write_entry,
)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = ["https://graph.microsoft.com/.default"]
DEFAULT_SELECT = "id,displayName,userPrincipalName,mail,jobTitle,department,accountEnabled"
DEFAULT_TOP = 999
DEFAULT_ROW_CAP = 1000
MAX_RETRIES = 3
USER_AGENT = "rejewski-tool-list-users/0.2 (+https://github.com/Cloud-Harbor-Consulting-LLC/rejewski)"
REQ_TIMEOUT = (5, 30)
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPLAY_LOG_DIR = REPO_ROOT / "replay-logs"
TECHNIQUE_ID = "T1087.004"
TECHNIQUE_NAME = "Account Discovery: Cloud Account"
TOOL_NAME = "tool_list_users"
ERROR_TYPE_URN = "urn:rejewski:error:tool-invocation-failed"


def graph_get(
    url: str,
    token: str,
    token_getter: Callable[[], str],
) -> tuple[dict[str, Any], str, int, int]:
    """GET with Retry-After on 429/5xx (max 3) and one 401 silent-refresh recovery.

    On 401, calls token_getter() — which routes through the encrypted cache
    via scripts/identity — instead of refreshing MSAL state inline.
    Returns (json_body, current_token, final_http_status, retry_count).
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


def list_users(
    token: str,
    token_getter: Callable[[], str],
    select: str,
    page_size: int,
    row_cap: int,
    stats: dict[str, int],
) -> list[dict[str, Any]]:
    users: list[dict[str, Any]] = []
    url: str | None = f"{GRAPH_BASE}/users?$select={select}&$top={page_size}"
    while url and len(users) < row_cap:
        body, token, status_code, retries = graph_get(url, token, token_getter)
        stats["page_count"] += 1
        stats["retry_count"] += retries
        stats["last_status"] = status_code
        page = body.get("value", [])
        remaining = row_cap - len(users)
        users.extend(page[:remaining])
        if len(users) >= row_cap:
            break
        url = body.get("@odata.nextLink")
    return users


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Rejewski Tool 1 - T1087.004 Account Discovery (cloud)"
    )
    p.add_argument("--select", default=DEFAULT_SELECT, help="OData $select fields")
    p.add_argument(
        "--page-size", type=int, default=DEFAULT_TOP,
        help="$top page size (Graph maximum for /users is 999)",
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
        "--run-id",
        default=None,
        help="run binding key (e.g. R002); propagated to replay-log entry",
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
    started_at = utc_now_iso()
    initial_url = f"{GRAPH_BASE}/users?$select={args.select}&$top={args.page_size}"
    request_obj: dict[str, Any] = {
        "method": "GET",
        "url": initial_url,
        "headers": {
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json",
        },
    }

    stats: dict[str, int] = {"page_count": 0, "retry_count": 0, "last_status": 0}
    users: list[dict[str, Any]] = []
    error_block: dict[str, Any] | None = None
    outcome: str

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

    try:
        token = token_getter()
        users = list_users(
            token=token,
            token_getter=token_getter,
            select=args.select,
            page_size=args.page_size,
            row_cap=args.row_cap,
            stats=stats,
        )
        row_cap_hit = len(users) >= args.row_cap
        outcome = "row_cap_hit" if row_cap_hit else "success"
    except (RuntimeError, requests.RequestException) as exc:
        outcome = "error"
        error_block = make_error(
            type_=ERROR_TYPE_URN,
            message=str(exc),
            status_code=stats["last_status"] or None,
        )

    completed_at = utc_now_iso()

    response_obj: dict[str, Any] = {
        "status_code": stats["last_status"]
        if stats["last_status"]
        else (200 if outcome != "error" else 0),
        "page_count": stats["page_count"],
        "row_count": len(users),
        "row_cap": args.row_cap,
        "row_cap_hit": len(users) >= args.row_cap,
        "retry_count": stats["retry_count"],
    }

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

    evidence = {
        "tool": TOOL_NAME,
        "technique": TECHNIQUE_ID,
        "tenant_id": tenant_id,
        "borrowed_client_id": client_id,
        "actor_upn": upn,
        "started_at_utc": started_at,
        "completed_at_utc": completed_at,
        "select": args.select,
        "page_size": args.page_size,
        "row_cap": args.row_cap,
        "row_count": len(users),
        "row_cap_hit": len(users) >= args.row_cap,
        "page_count": stats["page_count"],
        "retry_count": stats["retry_count"],
        "outcome": outcome,
        "replay_log_entry": str(replay_path),
        "users": users,
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
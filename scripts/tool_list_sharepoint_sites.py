#!/usr/bin/env python3
"""
Rejewski Sprint 4 W14 Tool 14 — list_sharepoint_sites
ATT&CK T1213.002 Data from Information Repositories: SharePoint (Surface A)

Enumerates SharePoint Online site collections via Microsoft Graph
GET /sites?search=*, reads each site's external-sharing policy (sharingCapability),
and — for sites whose sharing policy is high or medium risk — optionally enumerates
document libraries (GET /sites/{id}/drives) and lists (GET /sites/{id}/lists). Site
names alone (e.g. "HR-Compensation", "Finance-FY2026", "Legal-Contracts") expose
business function without reading a single file; a site set to
externalUserAndGuestSharing is a data-exfiltration-friendly target. This is repository
mapping — a precursor to Collection — and reads metadata only, never file content.

Token acquisition, silent reuse, and CAE/CP1 handling are owned by ADR 0005's encrypted
PersistedTokenCache helper. The token is consumed via a token_getter callable; 401
mid-pagination recovers from the encrypted cache, not in-memory MSAL state.

No tenant-side app registration is created in the target tenant (ADR 0001 §1, guardrail
G-3). Borrowed first-party client is Microsoft Graph Command Line Tools; the FOCI client
is fixed to 14d82eec per ADR-0006 and guardrail G-3.

Every emitted invocation writes one replay-log entry (kind="graph_call", v0.5 schema) per
distinct Graph request issued: the /sites search, and each /drives and /lists call for a
flagged site. A tenant with no SharePoint sites is not an error: the tool prints a notice
to stderr and still writes a graph_call entry with row_count 0.

REQUIRED PRIVILEGE — SCOPE:
    GET /sites?search=* requires the Sites.Read.All delegated scope, admin-consented on
    the borrowed client in cloudharbordemo. NO Entra directory role is required —
    Sites.Read.All grants read access to all site collections for any licensed user. If
    the scope is not pre-consented on the FOCI client, the call returns HTTP 403; grant
    admin consent in the Entra admin center first (same one-time setup pattern as the DfI
    spike, 06 - Research & References/phs-tool7-dfi-spike-2026-06-04.md).

See docs/techniques/T1213.002.md Surface A for the full module.

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
import re
import sys
import time
from pathlib import Path
from typing import Any, Callable

import requests
from dotenv import load_dotenv

import identity
from replay_log import (
    REDACTED,
    SANDBOX_TENANT_ID,
    ReplayLogEntry,
    make_error,
    redact_tenant_id,
    utc_now_iso,
    write_entry,
)

# The sandbox tenant GUID as a SUBSTRING scrubber for free-text fields (webUrl).
# Note: replay_log.redact_tenant_id() is an exact-match field redactor (for the
# evidence tenant_id field); it does NOT scrub a GUID embedded inside a URL, so a
# case-insensitive substring replace is used for webUrl (G-6).
_TENANT_GUID_RE = re.compile(re.escape(SANDBOX_TENANT_ID), re.IGNORECASE)


def _scrub_url(url: Any) -> str:
    return _TENANT_GUID_RE.sub(REDACTED, str(url or ""))

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = ["https://graph.microsoft.com/.default"]
SITES_SELECT = (
    "id,displayName,webUrl,description,sharingCapability,"
    "createdDateTime,lastModifiedDateTime"
)
DRIVE_SELECT = "id,name,driveType,createdDateTime,lastModifiedDateTime,quota"
LIST_SELECT = "id,displayName,description,createdDateTime,lastModifiedDateTime,list"
DEFAULT_TOP = 200
DEFAULT_ROW_CAP = 1000
MAX_RETRIES = 3
USER_AGENT = (
    "rejewski-tool-list-sharepoint-sites/0.1 "
    "(+https://github.com/Cloud-Harbor-Consulting-LLC/rejewski)"
)
REQ_TIMEOUT = (5, 30)
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPLAY_LOG_DIR = REPO_ROOT / "replay-logs"
TECHNIQUE_ID = "T1213.002"
TECHNIQUE_NAME = "Data from Information Repositories: Sharepoint"
TOOL_NAME = "tool_list_sharepoint_sites"
ERROR_TYPE_URN = "urn:rejewski:error:tool-invocation-failed"

# sharingCapability enum -> external-sharing risk. high/medium sites are "flagged"
# and proceed to drives/lists enumeration when --include-drives/--include-lists are set.
SHARING_RISK = {
    "externaluserandguestsharing": "high",
    "externalusersharingonly": "medium",
    "existingexternalusersharingonly": "low",
    "disabled": "none",
}
FLAGGED_RISKS = {"high", "medium"}
RISK_BUCKETS = ("high", "medium", "low", "none")


def _sharing_risk(capability: Any) -> str:
    return SHARING_RISK.get(str(capability or "").strip().lower(), "none")


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


def list_sites(
    token: str,
    token_getter: Callable[[], str],
    page_size: int,
    row_cap: int,
    stats: dict[str, int],
) -> list[dict[str, Any]]:
    """Page through GET /sites?search=* until exhausted or the G-9 row cap is hit."""
    sites: list[dict[str, Any]] = []
    url: str | None = (
        f"{GRAPH_BASE}/sites?search=*"
        f"&$select={SITES_SELECT}"
        f"&$top={page_size}"
    )
    while url and len(sites) < row_cap:
        body, token, status_code, retries = graph_get(url, token, token_getter)
        stats["page_count"] += 1
        stats["retry_count"] += retries
        stats["last_status"] = status_code
        page = body.get("value", [])
        remaining = row_cap - len(sites)
        sites.extend(page[:remaining])
        if len(sites) >= row_cap:
            break
        url = body.get("@odata.nextLink")
    return sites


def _collection(
    endpoint: str,
    select: str,
    token: str,
    token_getter: Callable[[], str],
    row_cap: int,
    stats: dict[str, int],
) -> list[dict[str, Any]]:
    """Page a per-site sub-collection (drives or lists) up to the row cap."""
    items: list[dict[str, Any]] = []
    url: str | None = f"{endpoint}?$select={select}&$top={DEFAULT_TOP}"
    while url and len(items) < row_cap:
        body, token, status_code, retries = graph_get(url, token, token_getter)
        stats["page_count"] += 1
        stats["retry_count"] += retries
        stats["last_status"] = status_code
        page = body.get("value", [])
        remaining = row_cap - len(items)
        items.extend(page[:remaining])
        if len(items) >= row_cap:
            break
        url = body.get("@odata.nextLink")
    return items


def _project_site(site: dict[str, Any]) -> dict[str, Any]:
    """Project a raw site to the evidence surface. webUrl is passed through
    redact_tenant_id (G-6) so a tenant GUID embedded in the URL is scrubbed before
    the evidence is committed to samples/."""
    return {
        "id": site.get("id"),
        "displayName": site.get("displayName"),
        "webUrl": _scrub_url(site.get("webUrl")) or None,
        "sharingCapability": site.get("sharingCapability"),
        "sharing_risk": _sharing_risk(site.get("sharingCapability")),
        "createdDateTime": site.get("createdDateTime"),
        "lastModifiedDateTime": site.get("lastModifiedDateTime"),
        "drives": [],
        "lists": [],
    }


def _project_drive(drive: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": drive.get("id"),
        "name": drive.get("name"),
        "driveType": drive.get("driveType"),
        "quota": drive.get("quota"),
        "createdDateTime": drive.get("createdDateTime"),
        "lastModifiedDateTime": drive.get("lastModifiedDateTime"),
    }


def _project_list(lst: dict[str, Any]) -> dict[str, Any]:
    list_facet = lst.get("list") or {}
    return {
        "id": lst.get("id"),
        "displayName": lst.get("displayName"),
        "template": list_facet.get("template"),
        "itemCount": lst.get("itemCount"),
        "createdDateTime": lst.get("createdDateTime"),
        "lastModifiedDateTime": lst.get("lastModifiedDateTime"),
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Rejewski Tool 14 - T1213.002 Data from Information Repositories: "
            "SharePoint (site enumeration, Surface A)"
        )
    )
    p.add_argument(
        "--row-cap", type=int, default=DEFAULT_ROW_CAP,
        help="G-9 enumeration row cap applied to total top-level sites",
    )
    p.add_argument(
        "--output",
        help="optional path to write evidence JSON summary (default: stdout)",
    )
    p.add_argument(
        "--replay-log-dir",
        default=str(DEFAULT_REPLAY_LOG_DIR),
        help=(
            "directory for the replay-log entries "
            "(default: replay-logs/ - gitignored; "
            "use samples/replay-log for canonical runs)"
        ),
    )
    p.add_argument(
        "--emit",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "write replay-log entries for this run (default: on, honoring G-5). "
            "Pass --no-emit for a local dry run that performs the reads but writes "
            "no entries."
        ),
    )
    p.add_argument(
        "--include-drives",
        action="store_true",
        help="enumerate drives (document libraries) for flagged (high/medium) sites",
    )
    p.add_argument(
        "--include-lists",
        action="store_true",
        help="enumerate lists for flagged (high/medium) sites",
    )
    p.add_argument(
        "--run-id",
        default=None,
        help="run binding key (e.g. R012); propagated to replay-log entries",
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

    def emit(
        request_obj: dict[str, Any],
        response_obj: dict[str, Any],
        started: str,
        completed: str,
        outcome: str,
        error_block: dict[str, Any] | None,
    ) -> None:
        """Write one graph_call replay-log entry (honors --emit / G-5)."""
        if not args.emit:
            return
        entry = ReplayLogEntry(
            kind="graph_call",
            tool=TOOL_NAME,
            technique_id=TECHNIQUE_ID,
            technique_name=TECHNIQUE_NAME,
            tenant_id=tenant_id,
            borrowed_client_id=client_id,
            actor_upn=upn,
            started_at_utc=started,
            completed_at_utc=completed,
            request=request_obj,
            response=response_obj,
            outcome=outcome,
            error=error_block,
            run_id=args.run_id,
        )
        write_entry(entry, log_dir=replay_log_dir)

    def _req(url: str) -> dict[str, Any]:
        return {
            "method": "GET",
            "url": url,
            "headers": {"User-Agent": USER_AGENT, "Content-Type": "application/json"},
        }

    def _resp(stats: dict[str, int], count: int, outcome: str) -> dict[str, Any]:
        return {
            "status_code": stats["last_status"] if stats["last_status"] else (200 if outcome != "error" else 0),
            "page_count": stats["page_count"],
            "row_count": count,
            "row_cap": args.row_cap,
            "row_cap_hit": count >= args.row_cap,
            "retry_count": stats["retry_count"],
        }

    # --- top-level site enumeration -------------------------------------------
    sites_url = f"{GRAPH_BASE}/sites?search=*&$select={SITES_SELECT}&$top={DEFAULT_TOP}"
    started = utc_now_iso()
    stats: dict[str, int] = {"page_count": 0, "retry_count": 0, "last_status": 0}
    sites: list[dict[str, Any]] = []
    error_block: dict[str, Any] | None = None
    outcome: str

    try:
        token = token_getter()
        sites = list_sites(token, token_getter, DEFAULT_TOP, args.row_cap, stats)
        outcome = "row_cap_hit" if len(sites) >= args.row_cap else "success"
    except (RuntimeError, requests.RequestException) as exc:
        outcome = "error"
        error_block = make_error(
            type_=ERROR_TYPE_URN, message=str(exc),
            status_code=stats["last_status"] or None,
        )
        if "HTTP 403" in str(exc):
            print(
                "HTTP 403 — access denied reading /sites?search=*.\n"
                "  Confirm Sites.Read.All is admin-consented on the borrowed client\n"
                f"  {client_id} in the target tenant. No Entra role is required; the\n"
                "  403 is a scope-consent gap. See docs/techniques/T1213.002.md.",
                file=sys.stderr,
            )
        else:
            print(f"error: {exc}", file=sys.stderr)

    completed = utc_now_iso()
    if outcome != "error" and not sites:
        print("No SharePoint sites found", file=sys.stderr)

    emit(_req(sites_url), _resp(stats, len(sites), outcome), started, completed,
         outcome, error_block)

    # --- per-flagged-site drives / lists --------------------------------------
    projected: list[dict[str, Any]] = []
    risk_summary = {k: 0 for k in RISK_BUCKETS}
    flagged_count = 0

    for site in sites:
        proj = _project_site(site)
        risk_summary[proj["sharing_risk"]] = risk_summary.get(proj["sharing_risk"], 0) + 1
        flagged = proj["sharing_risk"] in FLAGGED_RISKS
        if flagged:
            flagged_count += 1
        site_id = site.get("id")

        if flagged and args.include_drives and site_id and outcome != "error":
            d_stats = {"page_count": 0, "retry_count": 0, "last_status": 0}
            d_started = utc_now_iso()
            endpoint = f"{GRAPH_BASE}/sites/{site_id}/drives"
            try:
                drives = _collection(endpoint, DRIVE_SELECT, token, token_getter,
                                     args.row_cap, d_stats)
                proj["drives"] = [_project_drive(d) for d in drives]
                d_outcome, d_err = "success", None
            except (RuntimeError, requests.RequestException) as exc:
                d_outcome, d_err = "error", make_error(
                    type_=ERROR_TYPE_URN, message=str(exc),
                    status_code=d_stats["last_status"] or None)
            emit(_req(f"{endpoint}?$select={DRIVE_SELECT}"),
                 _resp(d_stats, len(proj["drives"]), d_outcome),
                 d_started, utc_now_iso(), d_outcome, d_err)

        if flagged and args.include_lists and site_id and outcome != "error":
            l_stats = {"page_count": 0, "retry_count": 0, "last_status": 0}
            l_started = utc_now_iso()
            endpoint = f"{GRAPH_BASE}/sites/{site_id}/lists"
            try:
                lists = _collection(endpoint, LIST_SELECT, token, token_getter,
                                    args.row_cap, l_stats)
                proj["lists"] = [_project_list(x) for x in lists]
                l_outcome, l_err = "success", None
            except (RuntimeError, requests.RequestException) as exc:
                l_outcome, l_err = "error", make_error(
                    type_=ERROR_TYPE_URN, message=str(exc),
                    status_code=l_stats["last_status"] or None)
            emit(_req(f"{endpoint}?$select={LIST_SELECT}"),
                 _resp(l_stats, len(proj["lists"]), l_outcome),
                 l_started, utc_now_iso(), l_outcome, l_err)

        projected.append(proj)

    evidence = {
        "tool": TOOL_NAME,
        "technique": TECHNIQUE_ID,
        "tenant_id": redact_tenant_id(tenant_id),
        "borrowed_client_id": client_id,
        "actor_upn": upn,
        "started_at_utc": started,
        "completed_at_utc": completed,
        "endpoint": "/sites?search=*",
        "row_cap": args.row_cap,
        "row_cap_hit": len(sites) >= args.row_cap,
        "outcome": outcome,
        "total_sites": len(sites),
        "flagged_sites": flagged_count,
        "sites": projected,
        "sharing_risk_summary": risk_summary,
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

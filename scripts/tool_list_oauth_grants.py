#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Rejewski Sprint 3 W11 Tool 11 — list_oauth_grants
ATT&CK T1087.004 Account Discovery: Cloud Account (Surface E — delegated grants)

Enumerates tenant-wide OAuth2 delegated permission grants via Microsoft Graph
GET /oauth2PermissionGrants. Each grant record reveals which client application
(by service-principal object ID, clientId) has been consented — admin-wide
(consentType=AllPrincipals) or for a single user (consentType=Principal) — for
which delegated API scopes against which resource API (resourceId). This is
account discovery at the delegated-authorization layer: knowing which apps hold
admin-consented Directory.ReadWrite.All, Mail.ReadWrite, or similarly broad
delegated scopes tells an adversary exactly which service principals are the
highest-value targets for later-stage lateral movement or data-access
operations. This module maps to T1087.004 Account Discovery: Cloud Account,
Surface E (ADR 0001 §3, threat-model.md §5).

Unlike role-assignment enumeration (Surface C), the /oauth2PermissionGrants
endpoint offers no $expand — each grant record already carries all relevant
fields inline (clientId, resourceId, consentType, principalId, scope). Human-
readable service-principal display-name resolution, if needed, is a separate
Surface D (tool_list_service_principals.py) join on the object IDs surfaced here.

Token acquisition, silent reuse, and CAE/CP1 handling are owned by ADR 0005's
encrypted PersistedTokenCache helper. This tool consumes the token via a
token_getter callable; 401 mid-pagination recovers from the encrypted cache, not
in-memory MSAL state.

No tenant-side app registration is created in the target tenant (ADR 0001 §1,
guardrail G-3). Borrowed first-party client is Microsoft Graph Command Line
Tools. The FOCI client is fixed to 14d82eec per ADR-0006 and guardrail G-3.

Every emitted invocation writes a replay-log entry under the v0.5 schema with
kind="graph_call". A tenant with no delegated grants configured is not an error:
the tool prints a notice to stderr and still writes a graph_call entry with
row_count (object_count) 0.

REQUIRED PRIVILEGE — SCOPE AND DIRECTORY ROLE:
    GET /oauth2PermissionGrants requires BOTH:
      (1) Directory.Read.All OAuth scope (delegated) — admin-consented on the
          borrowed Microsoft Graph Command Line Tools client (14d82eec) in the
          target tenant. This scope gates the endpoint per the Graph API docs.
          If it is not pre-consented on the FOCI client in the target tenant,
          the token is issued without it and the call returns HTTP 403. Verify
          with the target tenant administrator before running.
      (2) One of the following Entra directory roles on the signed-in user:
            - Directory Readers — minimum for full tenant-wide grant visibility
            - Global Reader — full visibility
            - Application Administrator — full visibility
    An ordinary licensed user with no qualifying directory role receives
    HTTP 403 regardless of scope consent.

ATTACK STRATEGY NOTE FOR REJEWSKI OPERATORS:
    Like CA-policy (Tool 4 / T1526) and role-assignment (Tool 5 / Surface C)
    enumeration, delegated-grant enumeration requires a privileged directory
    role. In a real-world simulation the adversary must first compromise an
    account holding Directory Readers or higher. Common adversary paths:

      1. Credential theft of a help-desk operator, IT admin, or app admin whose
         job function warrants Directory Readers or Application Administrator.
      2. Compromise of any account holding Global Reader or Application
         Administrator (both grant delegated-grant visibility as a side effect).
      3. PIM abuse: activate an eligible Directory Readers assignment without
         creating a permanent role assignment.

    High-value use of the output: a grant record showing an app service
    principal admin-consented (consentType=AllPrincipals) for a broad delegated
    scope — Directory.ReadWrite.All, Mail.ReadWrite, Files.ReadWrite.All — is a
    ranked target. Compromising that app's credentials (client secret or
    certificate) yields the app's full delegated authorization without touching
    a single user account. The high-privilege-grant count in the evidence
    summary is the adversary's shortlist.

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
GRAPH_ENDPOINT = f"{GRAPH_BASE}/oauth2PermissionGrants"
# Path recorded on the replay-log request and asserted by the technique doc's
# detection section (MicrosoftGraphActivityLogs RequestUri).
ENDPOINT_PATH = "/oauth2PermissionGrants"
# $select on the oauth2PermissionGrant object. No $expand is available on this
# endpoint — every relevant field is returned inline.
DEFAULT_SELECT = "id,clientId,resourceId,consentType,principalId,scope"
DEFAULT_TOP = 100
DEFAULT_ROW_CAP = 1000
MAX_RETRIES = 3
USER_AGENT = (
    "rejewski-tool-list-oauth-grants/0.1 "
    "(+https://github.com/Cloud-Harbor-Consulting-LLC/rejewski)"
)
REQ_TIMEOUT = (5, 30)
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPLAY_LOG_DIR = REPO_ROOT / "replay-logs"
TECHNIQUE_ID = "T1087.004"
TECHNIQUE_NAME = "Account Discovery: Cloud Account"
TOOL_NAME = "tool_list_oauth_grants"
ERROR_TYPE_URN = "urn:rejewski:error:tool-invocation-failed"

# consentType values on an oauth2PermissionGrant.
ADMIN_CONSENTED = "AllPrincipals"
USER_CONSENTED = "Principal"

# High-privilege scope strings to flag in the evidence output. Any grant whose
# scope string contains one of these (case-insensitive substring match) is
# considered high-privilege. The grant.scope field is a space-delimited list of
# delegated permission values, so a substring test flags a grant that carries
# any one of these permissions among possibly many.
HIGH_PRIVILEGE_SCOPES = {
    "Directory.ReadWrite.All",
    "Directory.Read.All",
    "RoleManagement.ReadWrite.Directory",
    "Mail.ReadWrite",
    "Mail.Read",
    "Files.ReadWrite.All",
    "Sites.ReadWrite.All",
    "User.ReadWrite.All",
    "GroupMember.ReadWrite.All",
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "DelegatedPermissionGrant.ReadWrite.All",
    "Policy.ReadWrite.ConditionalAccess",
    "AuditLog.Read.All",
}
# Pre-lowered once for the case-insensitive substring test.
_HIGH_PRIVILEGE_SCOPES_LOWER = {s.lower() for s in HIGH_PRIVILEGE_SCOPES}


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


def list_oauth_grants(
    token: str,
    token_getter: Callable[[], str],
    select: str,
    page_size: int,
    row_cap: int,
    stats: dict[str, int],
) -> list[dict[str, Any]]:
    """Page through GET /oauth2PermissionGrants until exhausted or the G-9 row
    cap is hit.
    """
    grants: list[dict[str, Any]] = []
    url: str | None = (
        f"{GRAPH_ENDPOINT}"
        f"?$select={select}"
        f"&$top={page_size}"
    )
    while url and len(grants) < row_cap:
        body, token, status_code, retries = graph_get(url, token, token_getter)
        stats["page_count"] += 1
        stats["retry_count"] += retries
        stats["last_status"] = status_code
        page = body.get("value", [])
        remaining = row_cap - len(grants)
        grants.extend(page[:remaining])
        if len(grants) >= row_cap:
            break
        url = body.get("@odata.nextLink")
    return grants


def _is_high_privilege(scope: Any) -> bool:
    """True if the grant's space-delimited scope string contains any
    high-privilege permission (case-insensitive substring match).
    """
    haystack = (scope or "").lower() if isinstance(scope, str) else ""
    return any(hp in haystack for hp in _HIGH_PRIVILEGE_SCOPES_LOWER)


def _compute_grant_summary(grants: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute delegated-grant aggregate metrics for the evidence JSON output.

    Written into the evidence JSON for detection-engineering consumers only.
    NOT added to the replay-log entry — the v0.5 schema enforces
    additionalProperties: false on the graph_call response branch, so
    grant-specific counts would fail schema validation (mirrors the RA summary
    handling in tool_list_role_assignments.py).
    """
    client_ids: set[str] = set()
    resource_ids: set[str] = set()
    admin_consented = 0
    user_consented = 0
    high_privilege = 0

    for g in grants:
        client_ids.add(g.get("clientId", ""))
        resource_ids.add(g.get("resourceId", ""))
        consent_type = g.get("consentType")
        if consent_type == ADMIN_CONSENTED:
            admin_consented += 1
        elif consent_type == USER_CONSENTED:
            user_consented += 1
        if _is_high_privilege(g.get("scope")):
            high_privilege += 1

    return {
        "grants_total_count": len(grants),
        "grants_admin_consented_count": admin_consented,
        "grants_user_consented_count": user_consented,
        "unique_client_sp_count": len(client_ids),
        "unique_resource_sp_count": len(resource_ids),
        "grants_high_privilege_count": high_privilege,
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Rejewski Tool 11 - T1087.004 Account Discovery "
            "(OAuth2 delegated permission grants, Surface E)"
        )
    )
    p.add_argument("--select", default=DEFAULT_SELECT, help="OData $select fields")
    p.add_argument(
        "--page-size", type=int, default=DEFAULT_TOP,
        help="$top page size (default: 100)",
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
        help="run binding key (e.g. R011); propagated to replay-log entry",
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
    initial_url = (
        f"{GRAPH_ENDPOINT}"
        f"?$select={args.select}"
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
    grants: list[dict[str, Any]] = []
    error_block: dict[str, Any] | None = None
    outcome: str

    try:
        token = token_getter()
        grants = list_oauth_grants(
            token=token,
            token_getter=token_getter,
            select=args.select,
            page_size=args.page_size,
            row_cap=args.row_cap,
            stats=stats,
        )
        row_cap_hit = len(grants) >= args.row_cap
        outcome = "row_cap_hit" if row_cap_hit else "success"
    except (RuntimeError, requests.RequestException) as exc:
        outcome = "error"
        error_block = make_error(
            type_=ERROR_TYPE_URN,
            message=str(exc),
            status_code=stats["last_status"] or None,
        )

    completed_at = utc_now_iso()

    # Empty result is a valid, non-error outcome (G-5): notice to stderr keeps
    # stdout machine-readable, and the graph_call entry below still records
    # row_count (object_count) 0.
    if outcome != "error" and not grants:
        print("No OAuth2 permission grants found", file=sys.stderr)

    response_obj: dict[str, Any] = {
        "status_code": stats["last_status"] if stats["last_status"] else (200 if outcome != "error" else 0),
        "page_count": stats["page_count"],
        "row_count": len(grants),
        "row_cap": args.row_cap,
        "row_cap_hit": len(grants) >= args.row_cap,
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

    replay_path: Path | None = None
    if args.emit:
        replay_path = write_entry(replay_entry, log_dir=replay_log_dir)

    grant_summary = _compute_grant_summary(grants) if outcome != "error" else {}

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
        "row_count": len(grants),
        "row_cap_hit": len(grants) >= args.row_cap,
        "page_count": stats["page_count"],
        "retry_count": stats["retry_count"],
        "outcome": outcome,
        "replay_log_entry": str(replay_path) if replay_path else None,
        **grant_summary,
        "grants": grants,
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

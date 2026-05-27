#!/usr/bin/env python3
"""
Rejewski Sprint 2 W5 (pull-forward) Tool 5 — list_role_assignments
ATT&CK T1087.004 Account Discovery: Cloud Account

Enumerates Entra ID directory role assignments via Microsoft Graph
GET /roleManagement/directory/roleAssignments. Role assignment enumeration
reveals which user, group, and service-principal accounts hold which
privileged directory roles across the tenant — Global Administrator,
Security Administrator, Privileged Role Administrator, and so on. This is
account discovery at the privilege layer: knowing which accounts carry the
highest blast-radius roles is prerequisite to targeting those accounts in
later-stage lateral movement or persistence operations. This module maps to
T1087.004 Account Discovery: Cloud Account (ADR 0001 §3, threat-model.md §5).

The tool uses $expand=principal,roleDefinition to resolve human-readable
principal display names and role definition names in a single paginated
call, avoiding a separate roleDefinitions pre-fetch.

Token acquisition, silent reuse, and CAE/CP1 handling are owned by
ADR 0005's encrypted PersistedTokenCache helper. This tool consumes the
token via a token_getter callable; 401 mid-pagination recovers from the
encrypted cache, not in-memory MSAL state.

No tenant-side app registration is created in the target tenant
(ADR 0001 §1, guardrail G-3). Borrowed first-party client defaults to
Microsoft Graph Command Line Tools (14d82eec) with Azure CLI (04b07795)
FOCI fallback per ADR 0004 v0.2.

Every invocation writes a replay-log entry under the v0.3 schema with
kind="graph_call".

REQUIRED PRIVILEGE — SCOPE AND DIRECTORY ROLE:
    GET /roleManagement/directory/roleAssignments requires BOTH:
      (1) RoleManagement.Read.Directory OAuth scope — admin-consented on
          the client. Note: this scope is less commonly pre-consented on
          first-party Microsoft clients than Policy.Read.All. If the
          borrowed Graph PowerShell client (14d82eec) does not have this
          scope pre-consented in the target tenant, the token will be
          issued without it and the API call will return HTTP 403. Verify
          with the target tenant administrator before running.
          Alternative: Directory.Read.All (broader scope; includes
          RoleManagement read access).
      (2) One of the following Entra directory roles on the signed-in user:
            - Directory Readers — full visibility of ALL role assignments
              across the tenant (recommended minimum for complete enumeration)
            - Global Reader — full visibility
            - Privileged Role Administrator — full visibility
            - Security Reader — PARTIAL visibility; returns only
              security-relevant assignments (exact subset undocumented;
              test empirically if Security Reader is the only available role)
    An ordinary licensed user with no directory role receives HTTP 403.

VISIBILITY NOTE:
    Directory Readers gives complete tenant-wide visibility of all role
    assignments. Security Reader returns a subset of security-relevant
    assignments — the exact scope is undocumented by Microsoft and must
    be validated empirically. If completeness of enumeration is required
    (e.g., counting all Global Administrator assignments), ensure the
    signed-in account holds Directory Readers or higher.

ATTACK STRATEGY NOTE FOR REJEWSKI OPERATORS:
    Like CA policy enumeration (Tool 4 / T1526), role assignment enumeration
    requires a privileged directory role. In a real-world simulation, the
    adversary must first compromise an account holding Directory Readers or
    higher. Common adversary paths:

      1. Credential theft of a help-desk operator, IT admin, or security
         analyst whose job function warrants Directory Readers.
      2. Compromise of any account that holds Global Reader, Security Admin,
         or Privileged Role Administrator (all of which also grant full
         role assignment visibility as a side effect of their broader scope).
      3. PIM abuse: activate an eligible Directory Readers assignment via
         a compromised account without creating a permanent role assignment.
      4. Application-level escalation: a service principal with
         RoleManagement.Read.Directory at application permission level
         sees all role assignments without any user-level directory role
         (Sprint 2+ Rejewski scope; not emulated here).

    High-value use of the output: identifying which accounts hold Global
    Administrator, Privileged Role Administrator, or Exchange Administrator
    roles gives the adversary a ranked target list for subsequent
    credential-theft or lateral movement operations. These assignments are
    the crown jewels of the tenant's identity plane.

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
    utc_now_iso,
    write_entry,
)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = ["https://graph.microsoft.com/.default"]
GRAPH_ENDPOINT = f"{GRAPH_BASE}/roleManagement/directory/roleAssignments"
# $select applies to the roleAssignment object itself; expanded sub-entities
# (principal, roleDefinition) are returned whole unless nested $select is used.
DEFAULT_SELECT = "id,principalId,roleDefinitionId,directoryScopeId"
# $expand=principal,roleDefinition resolves human-readable names in a single
# call (+1 RU per expand in the IAM throttling model; negligible at sandbox scale).
DEFAULT_EXPAND = "principal,roleDefinition"
DEFAULT_TOP = 100
DEFAULT_ROW_CAP = 1000
MAX_RETRIES = 3
USER_AGENT = (
    "rejewski-tool-list-role-assignments/0.1 "
    "(+https://github.com/Cloud-Harbor-Consulting-LLC/rejewski)"
)
REQ_TIMEOUT = (5, 30)
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPLAY_LOG_DIR = REPO_ROOT / "replay-logs"
TECHNIQUE_ID = "T1087.004"
TECHNIQUE_NAME = "Account Discovery: Cloud Account"
TOOL_NAME = "tool_list_role_assignments"
ERROR_TYPE_URN = "urn:rejewski:error:tool-invocation-failed"

# Entra built-in role display names considered high-privilege for evidence
# summary purposes. Adversaries who enumerate these assignments have found
# their highest-value lateral-movement targets.
HIGH_PRIVILEGE_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "User Administrator",
    "Authentication Administrator",
    "Cloud Application Administrator",
    "Application Administrator",
    "Hybrid Identity Administrator",
    "Intune Administrator",
    "Compliance Administrator",
    "Billing Administrator",
}


def graph_get(
    url: str,
    token: str,
    token_getter: Callable[[], str],
) -> tuple[dict[str, Any], str, int, int]:
    """GET with Retry-After on 429/5xx (max 3) and one 401 cache-backed recovery.

    The 401 path delegates to token_getter, which routes through
    identity.acquire_token (silent reuse from the encrypted cache, ROPC
    fallback on miss). Returns (json_body, current_token, final_http_status,
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


def list_role_assignments(
    token: str,
    token_getter: Callable[[], str],
    select: str,
    expand: str,
    page_size: int,
    row_cap: int,
    stats: dict[str, int],
) -> list[dict[str, Any]]:
    """Page through GET /roleManagement/directory/roleAssignments until
    exhausted or the G-9 row cap is hit.
    """
    assignments: list[dict[str, Any]] = []
    url: str | None = (
        f"{GRAPH_ENDPOINT}"
        f"?$select={select}"
        f"&$expand={expand}"
        f"&$top={page_size}"
    )
    while url and len(assignments) < row_cap:
        body, token, status_code, retries = graph_get(url, token, token_getter)
        stats["page_count"] += 1
        stats["retry_count"] += retries
        stats["last_status"] = status_code
        page = body.get("value", [])
        remaining = row_cap - len(assignments)
        assignments.extend(page[:remaining])
        if len(assignments) >= row_cap:
            break
        url = body.get("@odata.nextLink")
    return assignments


def _compute_ra_summary(assignments: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute role-assignment-specific aggregate metrics from the enumerated list.

    These metrics are written into the evidence JSON output for
    detection-engineering consumers. They are NOT added to the replay log
    entry — the v0.3 schema enforces additionalProperties: false on the
    response branch, and RA-specific counts would fail schema validation.
    """
    principal_ids: set[str] = set()
    role_def_ids: set[str] = set()
    global_admin_count = 0
    privileged_role_admin_count = 0
    high_privilege_count = 0
    external_principal_count = 0
    tenant_wide_scope_count = 0

    for a in assignments:
        principal_ids.add(a.get("principalId", ""))
        role_def_ids.add(a.get("roleDefinitionId", ""))

        # Count tenant-wide vs AU-scoped assignments
        if a.get("directoryScopeId") == "/":
            tenant_wide_scope_count += 1

        # Role name resolution via expanded roleDefinition
        role_def = a.get("roleDefinition") or {}
        role_name = role_def.get("displayName", "")
        if role_name == "Global Administrator":
            global_admin_count += 1
        if role_name == "Privileged Role Administrator":
            privileged_role_admin_count += 1
        if role_name in HIGH_PRIVILEGE_ROLES:
            high_privilege_count += 1

        # Guest/external detection via expanded principal
        principal = a.get("principal") or {}
        if principal.get("userType") == "Guest":
            external_principal_count += 1

    return {
        "ra_unique_principals": len(principal_ids),
        "ra_unique_roles": len(role_def_ids),
        "ra_global_admin_count": global_admin_count,
        "ra_privileged_role_admin_count": privileged_role_admin_count,
        "ra_high_privilege_count": high_privilege_count,
        "ra_external_principal_count": external_principal_count,
        "ra_tenant_wide_scope_count": tenant_wide_scope_count,
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Rejewski Tool 5 - T1087.004 Account Discovery (role assignments)"
        )
    )
    p.add_argument("--select", default=DEFAULT_SELECT, help="OData $select fields")
    p.add_argument(
        "--expand", default=DEFAULT_EXPAND,
        help=(
            "OData $expand navigation properties "
            "(default: principal,roleDefinition — resolves display names inline; "
            "set to empty string to skip expand and return IDs only)"
        ),
    )
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

    def token_getter() -> str:
        result = identity.acquire_token(
            actor_upn=upn,
            tenant_id=tenant_id,
            client_id=client_id,
            scopes=GRAPH_SCOPE,
            password=password,
            replay_log_dir=replay_log_dir,
        )
        return result["access_token"]

    started_at = utc_now_iso()
    # Construct initial URL; omit $expand clause if expand arg is empty
    expand_clause = f"&$expand={args.expand}" if args.expand else ""
    initial_url = (
        f"{GRAPH_ENDPOINT}"
        f"?$select={args.select}"
        f"{expand_clause}"
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
    assignments: list[dict[str, Any]] = []
    error_block: dict[str, Any] | None = None
    outcome: str

    try:
        token = token_getter()
        assignments = list_role_assignments(
            token=token,
            token_getter=token_getter,
            select=args.select,
            expand=args.expand,
            page_size=args.page_size,
            row_cap=args.row_cap,
            stats=stats,
        )
        row_cap_hit = len(assignments) >= args.row_cap
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
        "status_code": stats["last_status"] if stats["last_status"] else (200 if outcome != "error" else 0),
        "page_count": stats["page_count"],
        "row_count": len(assignments),
        "row_cap": args.row_cap,
        "row_cap_hit": len(assignments) >= args.row_cap,
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

    ra_summary = _compute_ra_summary(assignments) if outcome != "error" else {}

    evidence = {
        "tool": TOOL_NAME,
        "technique": TECHNIQUE_ID,
        "tenant_id": tenant_id,
        "borrowed_client_id": client_id,
        "actor_upn": upn,
        "started_at_utc": started_at,
        "completed_at_utc": completed_at,
        "select": args.select,
        "expand": args.expand,
        "page_size": args.page_size,
        "row_cap": args.row_cap,
        "row_count": len(assignments),
        "row_cap_hit": len(assignments) >= args.row_cap,
        "page_count": stats["page_count"],
        "retry_count": stats["retry_count"],
        "outcome": outcome,
        "replay_log_entry": str(replay_path),
        **ra_summary,
        "role_assignments": assignments,
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

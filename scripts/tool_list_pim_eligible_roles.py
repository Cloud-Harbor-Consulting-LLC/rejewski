#!/usr/bin/env python3
"""
Rejewski Sprint 6 W22 Tool 15 — list_pim_eligible_roles
ATT&CK T1087.004 Account Discovery: Cloud Account (Surface F)

Enumerates Entra ID PIM-eligible directory role assignments via Microsoft Graph
GET /roleManagement/directory/roleEligibilityScheduleInstances. Where Tool 5
(tool_list_role_assignments.py, GET /roleManagement/directory/roleAssignments)
enumerates ACTIVE assignments — the roles a principal holds right now — this tool
enumerates ELIGIBLE assignments: the roles a principal can activate just-in-time
through Privileged Identity Management but does not hold at rest.

The eligible-but-not-activated set is a materially different discovery signal. A
user eligible for Global Administrator carries real escalation risk that active-
assignment enumeration misses entirely: at any snapshot the account looks
unprivileged, yet it can self-elevate to tenant-wide control. Enumerating who is
eligible for the highest-privilege roles gives an adversary the just-in-time
escalation target list that the active-assignment view (Tool 5) cannot see. This
is the eligible-not-active variant of the same "which cloud accounts hold
privilege" discovery, so it maps to T1087.004 as Surface F alongside Tool 5's
active-assignment surface (ADR 0001 §3, threat-model.md §5, docs/techniques/T1087.004.md).

The point-in-time roleEligibilityScheduleInstances view is used (not
roleEligibilitySchedules, which also carries future and pending schedule objects)
because "who could activate privilege right now" is the discovery-relevant signal.
A single $expand=roleDefinition resolves the human-readable role display name so
Global Administrator and other high-privilege eligibilities can be flagged;
roleDefinition display names are built-in Entra role names, not user data, so no
G-6 redaction applies to them. principalId stays a GUID; no user UPN or display
name is read.

Token acquisition, silent reuse, and CAE/CP1 handling are owned by ADR 0005's
encrypted PersistedTokenCache helper. This tool consumes the token via a
token_getter callable; 401 mid-pagination recovers from the encrypted cache.

No tenant-side app registration is created in the target tenant (ADR 0001 §1,
guardrail G-2). Borrowed first-party client defaults to Microsoft Graph Command
Line Tools; the FOCI client is fixed to 14d82eec per ADR 0006 and guardrail G-3.

Every emitted invocation writes a replay-log entry under the v0.5 schema with
kind="graph_call".

REQUIRED PRIVILEGE — SCOPE AND DIRECTORY ROLE (verified against current Graph v1.0
docs, learn.microsoft.com rbacapplication-list-roleeligibilityscheduleinstances,
page updated 2025-11-13):
    GET /roleManagement/directory/roleEligibilityScheduleInstances requires BOTH:
      (1) RoleEligibilitySchedule.Read.Directory OAuth scope (least privileged) —
          admin-consented on the client. Broader alternatives that also work:
          RoleManagement.Read.Directory, RoleManagement.Read.All. If the borrowed
          Graph Command Line Tools client (14d82eec) does not have an eligible
          scope pre-consented in the target tenant, the token is issued without it
          and the API returns HTTP 403.
      (2) One of the following Entra directory roles on the signed-in user:
            Global Reader, Security Operator, Security Reader, Security
            Administrator, or Privileged Role Administrator.
          NOTE: Directory Readers is sufficient for Tool 5 (active assignments) but
          is NOT in the supported-role list for this eligibility endpoint. An
          operator who can run Tool 5 on Directory Readers alone may still receive
          HTTP 403 here. An HTTP 403 is a legitimate sandbox-config finding (the
          operator lacks a supported role, or the scope is not consented), not a
          tool defect.

AVAILABILITY NOTE:
    PIM eligibility requires Microsoft Entra ID P2. A tenant with no eligible
    assignments configured returns HTTP 200 with an empty value array (0 rows) —
    a valid, non-error empty result, not a failure. Zero eligible assignments is
    reported honestly; it is never padded.

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
GRAPH_ENDPOINT = f"{GRAPH_BASE}/roleManagement/directory/roleEligibilityScheduleInstances"
# $select applies to the instance object; the expanded roleDefinition is returned
# whole. A single navigation property is expanded (roleDefinition) to resolve the
# role display name — this stays within the Graph v1.0 one-property-per-$expand
# limit that bit Tool 5 (B030), so no two-call merge is needed here.
DEFAULT_SELECT = "id,principalId,roleDefinitionId,directoryScopeId,startDateTime,endDateTime,memberType"
DEFAULT_EXPAND = "roleDefinition"
DEFAULT_TOP = 100
DEFAULT_ROW_CAP = 1000
MAX_RETRIES = 3
USER_AGENT = (
    "rejewski-tool-list-pim-eligible-roles/0.1 "
    "(+https://github.com/Cloud-Harbor-Consulting-LLC/rejewski)"
)
REQ_TIMEOUT = (5, 30)
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPLAY_LOG_DIR = REPO_ROOT / "replay-logs"
TECHNIQUE_ID = "T1087.004"
TECHNIQUE_NAME = "Account Discovery: Cloud Account"
TOOL_NAME = "tool_list_pim_eligible_roles"
ERROR_TYPE_URN = "urn:rejewski:error:tool-invocation-failed"

# Well-known built-in Global Administrator roleTemplateId. For built-in directory
# roles the roleDefinitionId equals the template id, so an eligible-for-GA flag can
# be computed from roleDefinitionId even if $expand=roleDefinition is unavailable.
GLOBAL_ADMIN_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"

# Entra built-in role display names considered high-privilege for evidence summary.
# An account eligible to activate any of these can reach high-blast-radius control.
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


def list_eligible_roles(
    token: str,
    token_getter: Callable[[], str],
    select: str,
    expand: str,
    page_size: int,
    row_cap: int,
    stats: dict[str, int],
) -> list[dict[str, Any]]:
    """Page through GET roleEligibilityScheduleInstances until exhausted or the
    G-9 row cap is hit.
    """
    instances: list[dict[str, Any]] = []
    url: str | None = (
        f"{GRAPH_ENDPOINT}"
        f"?$select={select}"
        f"&$expand={expand}"
        f"&$top={page_size}"
    )
    while url and len(instances) < row_cap:
        body, token, status_code, retries = graph_get(url, token, token_getter)
        stats["page_count"] += 1
        stats["retry_count"] += retries
        stats["last_status"] = status_code
        page = body.get("value", [])
        remaining = row_cap - len(instances)
        instances.extend(page[:remaining])
        if len(instances) >= row_cap:
            break
        url = body.get("@odata.nextLink")
    return instances


def _compute_pim_summary(instances: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute PIM-eligibility aggregate metrics from the enumerated instances.

    These metrics go into the evidence JSON output for detection-engineering
    consumers. They are NOT added to the replay-log entry — the v0.5 schema
    enforces additionalProperties: false on the response branch, so tool-specific
    counts there would fail validation (same constraint as Tool 5).
    """
    principal_ids: set[str] = set()
    role_def_ids: set[str] = set()
    eligible_global_admin = 0
    eligible_high_privilege = 0
    permanent_eligible = 0
    time_bound_eligible = 0
    tenant_wide_scope = 0

    for inst in instances:
        principal_ids.add(inst.get("principalId", ""))
        role_id = inst.get("roleDefinitionId", "")
        role_def_ids.add(role_id)

        if inst.get("directoryScopeId") == "/":
            tenant_wide_scope += 1

        # Permanent eligibility (no end date) is higher-risk than time-bound.
        if not inst.get("endDateTime"):
            permanent_eligible += 1
        else:
            time_bound_eligible += 1

        role_def = inst.get("roleDefinition") or {}
        role_name = role_def.get("displayName", "")
        # Flag Global Administrator by either the resolved name or the well-known
        # roleTemplateId, so the GA flag survives even if $expand was unavailable.
        if role_name == "Global Administrator" or role_id == GLOBAL_ADMIN_ROLE_ID:
            eligible_global_admin += 1
        if role_name in HIGH_PRIVILEGE_ROLES:
            eligible_high_privilege += 1

    return {
        "pim_eligible_total": len(instances),
        "pim_unique_principals": len(principal_ids),
        "pim_unique_roles": len(role_def_ids),
        "pim_eligible_global_admin_count": eligible_global_admin,
        "pim_eligible_high_privilege_count": eligible_high_privilege,
        "pim_permanent_eligible_count": permanent_eligible,
        "pim_time_bound_eligible_count": time_bound_eligible,
        "pim_tenant_wide_scope_count": tenant_wide_scope,
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Rejewski Tool 15 - T1087.004 Account Discovery (PIM-eligible roles)"
        )
    )
    p.add_argument("--select", default=DEFAULT_SELECT, help="OData $select fields")
    p.add_argument(
        "--expand", default=DEFAULT_EXPAND,
        help="single navigation property to $expand (default: roleDefinition)",
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
        help="run binding key (e.g. R016); propagated to replay-log entry",
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
        f"&$expand={args.expand}"
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
    instances: list[dict[str, Any]] = []
    error_block: dict[str, Any] | None = None
    outcome: str

    try:
        token = token_getter()
        instances = list_eligible_roles(
            token=token,
            token_getter=token_getter,
            select=args.select,
            expand=args.expand,
            page_size=args.page_size,
            row_cap=args.row_cap,
            stats=stats,
        )
        row_cap_hit = len(instances) >= args.row_cap
        outcome = "row_cap_hit" if row_cap_hit else "success"
    except (RuntimeError, requests.RequestException) as exc:
        outcome = "error"
        error_block = make_error(
            type_=ERROR_TYPE_URN,
            message=str(exc),
            status_code=stats["last_status"] or None,
        )

    completed_at = utc_now_iso()

    # Empty result is a valid, non-error outcome (G-5). A tenant without Entra ID
    # P2 PIM, or with no eligible assignments configured, returns 0 rows honestly.
    if outcome != "error" and not instances:
        print("No PIM-eligible role assignments found", file=sys.stderr)

    response_obj: dict[str, Any] = {
        "status_code": stats["last_status"] if stats["last_status"] else (200 if outcome != "error" else 0),
        "page_count": stats["page_count"],
        "row_count": len(instances),
        "row_cap": args.row_cap,
        "row_cap_hit": len(instances) >= args.row_cap,
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

    pim_summary = _compute_pim_summary(instances) if outcome != "error" else {}

    evidence = {
        "tool": TOOL_NAME,
        "technique": TECHNIQUE_ID,
        "tenant_id": redact_tenant_id(tenant_id),
        "borrowed_client_id": client_id,
        "actor_upn": upn,
        "started_at_utc": started_at,
        "completed_at_utc": completed_at,
        "select": args.select,
        "expand": args.expand,
        "page_size": args.page_size,
        "row_cap": args.row_cap,
        "row_count": len(instances),
        "row_cap_hit": len(instances) >= args.row_cap,
        "page_count": stats["page_count"],
        "retry_count": stats["retry_count"],
        "outcome": outcome,
        "replay_log_entry": str(replay_path) if replay_path else None,
        **pim_summary,
        "eligible_role_instances": instances,
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

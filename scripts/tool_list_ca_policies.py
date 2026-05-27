#!/usr/bin/env python3
"""
Rejewski Sprint 2 W5 (pull-forward) Tool 4 — list_ca_policies
ATT&CK T1526 Cloud Service Discovery

Enumerates Entra ID Conditional Access policies via Microsoft Graph
GET /identity/conditionalAccess/policies. CA policy enumeration reveals
the organization's access-control posture: which users, groups, and roles
are covered; what grant controls (MFA, compliant device, block) are in
force; and which applications are in scope. This maps to T1526 Cloud
Service Discovery under the Rejewski threat-actor framing (ADR 0001 §3,
threat-model.md v0.4 §5).

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

REQUIRED PRIVILEGE — SECURITY READER OR ABOVE:
    GET /identity/conditionalAccess/policies requires BOTH:
      (1) Policy.Read.All OAuth scope — admin-consented on the client.
          The borrowed Microsoft Graph PowerShell client (14d82eec) has
          this scope pre-consented as a first-party Microsoft application.
      (2) One of the following Entra directory roles on the signed-in user:
            - Security Reader (minimum)
            - Security Administrator
            - Conditional Access Administrator
            - Global Reader
            - Global Administrator
    An ordinary licensed user without one of these roles receives HTTP 403.
    Unlike GET /users and GET /groups (Tools 1–3), CA policy enumeration
    is gated behind a privileged directory role — this is by design in
    Microsoft Entra ID.

ATTACK STRATEGY NOTE FOR REJEWSKI OPERATORS:
    Because CA policy enumeration requires a security-role account, this
    tool represents a post-privilege-escalation discovery step in the
    adversary kill chain — not a first-foothold capability. In a real-world
    simulation, the adversary must first obtain credentials for an account
    holding Security Reader or higher before this enumeration is possible.
    Common adversary paths that lead to the required role:

      1. Targeted phishing of a security administrator, help-desk operator,
         or compliance officer (accounts most likely to hold Security Reader
         or Security Administrator by job function).
      2. Password spray or credential stuffing against accounts in the
         security or IT operations groups (higher privilege density, often
         targeted by adversaries for exactly this reason).
      3. Privileged Identity Management (PIM) abuse — if the compromised
         account holds an *eligible* Security Reader assignment, the
         adversary activates the role to complete the enumeration without
         leaving a permanent role assignment.
      4. Application-level escalation — gaining control of a service
         principal or application registration that holds Policy.Read.All
         at application permission level (this is a Sprint 2+ Rejewski
         technique; not emulated here).

    In the cloudharbordemo sandbox, meganb@cloudharbor-demo.com is assigned
    Security Reader to simulate a scenario where a security-role account has
    been compromised. Operators running against a different sandbox tenant
    must ensure the designated test account holds at least Security Reader.

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
GRAPH_ENDPOINT = f"{GRAPH_BASE}/identity/conditionalAccess/policies"
# $select works on top-level fields only; conditions, grantControls, and
# sessionControls are complex nested objects returned whole.
DEFAULT_SELECT = (
    "id,displayName,state,conditions,grantControls,sessionControls,"
    "createdDateTime,modifiedDateTime"
)
# Conservative page size: the CA policies endpoint maximum $top is not
# documented by Microsoft. Most tenants have fewer than 100 policies;
# the default of 100 avoids a 400 Bad Request from an undocumented cap.
DEFAULT_TOP = 100
DEFAULT_ROW_CAP = 1000
MAX_RETRIES = 3
USER_AGENT = (
    "rejewski-tool-list-ca-policies/0.1 "
    "(+https://github.com/Cloud-Harbor-Consulting-LLC/rejewski)"
)
REQ_TIMEOUT = (5, 30)
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPLAY_LOG_DIR = REPO_ROOT / "replay-logs"
TECHNIQUE_ID = "T1526"
TECHNIQUE_NAME = "Cloud Service Discovery"
TOOL_NAME = "tool_list_ca_policies"
ERROR_TYPE_URN = "urn:rejewski:error:tool-invocation-failed"


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


def list_ca_policies(
    token: str,
    token_getter: Callable[[], str],
    select: str,
    page_size: int,
    row_cap: int,
    stats: dict[str, int],
) -> list[dict[str, Any]]:
    """Page through GET /identity/conditionalAccess/policies until exhausted
    or the G-9 row cap is hit. Most tenants return all policies in a single
    page; pagination is implemented defensively in case that changes.
    """
    policies: list[dict[str, Any]] = []
    url: str | None = f"{GRAPH_ENDPOINT}?$select={select}&$top={page_size}"
    while url and len(policies) < row_cap:
        body, token, status_code, retries = graph_get(url, token, token_getter)
        stats["page_count"] += 1
        stats["retry_count"] += retries
        stats["last_status"] = status_code
        page = body.get("value", [])
        remaining = row_cap - len(policies)
        policies.extend(page[:remaining])
        if len(policies) >= row_cap:
            break
        url = body.get("@odata.nextLink")
    return policies


def _compute_ca_summary(policies: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute CA-specific aggregate metrics from the enumerated policy list.

    These metrics are written into the evidence JSON output for
    detection-engineering consumers. They are NOT added to the replay log
    entry — the v0.3 schema enforces additionalProperties: false on the
    response branch, and CA-specific counts would fail schema validation.
    """
    def _built_in_controls(p: dict[str, Any]) -> list[str]:
        gc = p.get("grantControls") or {}
        return gc.get("builtInControls") or []

    enabled = sum(1 for p in policies if p.get("state") == "enabled")
    disabled = sum(1 for p in policies if p.get("state") == "disabled")
    report_only = sum(
        1 for p in policies
        if p.get("state") == "enabledForReportingButNotEnforced"
    )
    mfa_count = sum(1 for p in policies if "mfa" in _built_in_controls(p))
    block_count = sum(1 for p in policies if "block" in _built_in_controls(p))
    compliant_device_count = sum(
        1 for p in policies if "compliantDevice" in _built_in_controls(p)
    )
    return {
        "ca_policies_enabled": enabled,
        "ca_policies_disabled": disabled,
        "ca_policies_report_only": report_only,
        "ca_mfa_policy_count": mfa_count,
        "ca_block_policy_count": block_count,
        "ca_compliant_device_count": compliant_device_count,
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Rejewski Tool 4 - T1526 Cloud Service Discovery (CA policies)"
    )
    p.add_argument("--select", default=DEFAULT_SELECT, help="OData $select fields")
    p.add_argument(
        "--page-size", type=int, default=DEFAULT_TOP,
        help=(
            "$top page size for CA policies (default: 100; the endpoint maximum "
            "is undocumented — reduce if a 400 Bad Request is returned)"
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
        "--run-id",
        default=None,
        help="run binding key (e.g. R005); propagated to replay-log entry",
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
    policies: list[dict[str, Any]] = []
    error_block: dict[str, Any] | None = None
    outcome: str

    try:
        token = token_getter()
        policies = list_ca_policies(
            token=token,
            token_getter=token_getter,
            select=args.select,
            page_size=args.page_size,
            row_cap=args.row_cap,
            stats=stats,
        )
        row_cap_hit = len(policies) >= args.row_cap
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
        "row_count": len(policies),
        "row_cap": args.row_cap,
        "row_cap_hit": len(policies) >= args.row_cap,
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

    ca_summary = _compute_ca_summary(policies) if outcome != "error" else {}

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
        "row_count": len(policies),
        "row_cap_hit": len(policies) >= args.row_cap,
        "page_count": stats["page_count"],
        "retry_count": stats["retry_count"],
        "outcome": outcome,
        "replay_log_entry": str(replay_path),
        **ca_summary,
        "ca_policies": policies,
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

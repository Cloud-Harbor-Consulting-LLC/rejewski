#!/usr/bin/env python3
"""
Rejewski Sprint 2 W5 (pull-forward) Tool 6 — list_service_principals
ATT&CK T1087.004 Account Discovery: Cloud Account — Surface D (service principal layer)

Enumerates Entra ID service principals via Microsoft Graph
GET /servicePrincipals. Service principal enumeration reveals the full
inventory of application identities in the tenant — first-party Microsoft
services, third-party SaaS integrations, managed identities, and any
custom line-of-business application service principals. This is account
discovery at the non-human identity layer: knowing which SPs exist, which
are multi-tenant, and which are registered by external tenant owners gives
an adversary a target list for SP credential theft, OAuth application abuse,
and cross-tenant attack paths. Maps to T1087.004 Account Discovery: Cloud
Account (ADR 0001 §3, threat-model.md §5, docs/techniques/T1087.004.md).

Observed in adversary campaigns: Storm-0501 (SP enumeration as precursor to
SP-persistence after compromising Entra Connect Sync accounts) and Midnight
Blizzard / APT29 (delegated token used against /servicePrincipals to read
targeted mailboxes via SP identity).

Token acquisition, silent reuse, and CAE/CP1 handling are owned by
ADR 0005's encrypted PersistedTokenCache helper. This tool consumes the
token via a token_getter callable; 401 mid-pagination recovers from the
encrypted cache, not in-memory MSAL state.

No tenant-side app registration is created in the target tenant
(ADR 0001 §1, guardrail G-3). Borrowed first-party client defaults to
Microsoft Graph Command Line Tools. The FOCI client is fixed to 14d82eec per
ADR-0006 and guardrail G-3.

Every emitted invocation writes a replay-log entry under the v0.5 schema with
kind="graph_call". The schema version is set from replay_log.SCHEMA_VERSION.

REQUIRED PRIVILEGE — SCOPE AND DIRECTORY ROLE:
    GET /servicePrincipals (delegated) requires:
      (1) OAuth scope: Application.Read.All — the least-privileged delegated
          permission for this endpoint. Pre-consented on the borrowed
          Microsoft Graph Command Line Tools client (14d82eec) in tenants
          where it has been admin-consented. Directory.Read.All also works
          but is higher-privilege than needed.
      (2) Entra directory role on the signed-in user — minimum required for
          tenant-wide visibility:
            - Directory Readers — full inventory of all service principals
            - Global Reader — full inventory (read-only admin scope)
            - Application Administrator — full inventory
            - Cloud Application Administrator — full inventory

VISIBILITY NOTE:
    A signed-in user with NO directory role receives HTTP 200 with an empty
    value: [] — NOT a 403. The tool will complete with row_count: 0 and
    outcome: success, which does NOT indicate a successful enumeration. This
    silent-filter behavior is by Graph design and means under-privileged
    operators will not receive an error signal. Always confirm the signed-in
    account holds at least Directory Readers before treating a row_count: 0
    result as definitive (tenant has no SPs).

ATTACK STRATEGY NOTE FOR REJEWSKI OPERATORS:
    Like CA policy enumeration (Tool 4 / T1526) and role assignment
    enumeration (Tool 5), full SP inventory requires a privileged directory
    role. In a real-world simulation, common adversary paths to acquire
    Directory Readers:

      1. Credential theft of a help-desk operator, IT admin, or security
         analyst whose job function warrants Directory Readers.
      2. Compromise of any account that holds Global Reader, Application
         Administrator, or Cloud Application Administrator (all of which
         grant full /servicePrincipals visibility as a side effect).
      3. Application registration abuse: if application registration is not
         blocked by tenant policy, register a new app → become the owner of
         its service principal. This grants Application Developer role
         (implicit) and allows reading SPs you own — partial visibility only,
         not tenant-wide. Useful as a stepping stone to SP credential theft
         and escalation.
      4. FOCI / pre-consented scope exploitation: if the borrowed client has
         Application.Read.All pre-consented and the signed-in user already
         holds Directory Readers (e.g., from a prior privilege-escalation
         step), full enumeration proceeds with no additional tenant-side
         configuration.

    High-value use of the output: SPs with appOwnerOrganizationId pointing
    to external tenants represent third-party integration attack paths. SPs
    with servicePrincipalType=ManagedIdentity are workload-identity targets
    for lateral movement to Azure resources. Multi-tenant SPs (signInAudience
    ≠ AzureADMyOrg) may be exploitable via the app's home tenant if their
    credentials are weak.

    $top maximum for GET /servicePrincipals is 100 (Graph enforced limit —
    distinct from GET /users which accepts $top=999). This tool defaults to
    100 and will page correctly across large tenants.

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
from collections import Counter
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
GRAPH_ENDPOINT = f"{GRAPH_BASE}/servicePrincipals"
GRAPH_SCOPE = ["https://graph.microsoft.com/.default"]
# Narrow $select keeps pages small and backs all SP-specific aggregate metrics.
# id required for deduplication; appId for SP identity; others for metrics.
DEFAULT_SELECT = (
    "id,appId,displayName,accountEnabled,servicePrincipalType,"
    "signInAudience,appOwnerOrganizationId,tags,homepage"
)
DEFAULT_TOP = 100          # Graph enforced maximum $top for /servicePrincipals
DEFAULT_ROW_CAP = 1000
MAX_RETRIES = 3
USER_AGENT = (
    "rejewski-tool-list-service-principals/0.1 "
    "(+https://github.com/Cloud-Harbor-Consulting-LLC/rejewski)"
)
REQ_TIMEOUT = (5, 30)
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPLAY_LOG_DIR = REPO_ROOT / "replay-logs"
TECHNIQUE_ID = "T1087.004"
TECHNIQUE_NAME = "Account Discovery: Cloud Account"
TOOL_NAME = "tool_list_service_principals"
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


def list_service_principals(
    token: str,
    token_getter: Callable[[], str],
    select: str,
    page_size: int,
    row_cap: int,
    stats: dict[str, int],
) -> list[dict[str, Any]]:
    """Page through GET /servicePrincipals until exhausted or G-9 row cap hit."""
    sps: list[dict[str, Any]] = []
    url: str | None = f"{GRAPH_ENDPOINT}?$select={select}&$top={page_size}"
    while url and len(sps) < row_cap:
        body, token, status_code, retries = graph_get(url, token, token_getter)
        stats["page_count"] += 1
        stats["retry_count"] += retries
        stats["last_status"] = status_code
        page = body.get("value", [])
        remaining = row_cap - len(sps)
        sps.extend(page[:remaining])
        if len(sps) >= row_cap:
            break
        url = body.get("@odata.nextLink")
    return sps


def _compute_sp_summary(
    sps: list[dict[str, Any]], tenant_id: str
) -> dict[str, Any]:
    """Compute SP-specific aggregate metrics for the evidence JSON envelope.

    Not written to the replay-log entry (v0.5 schema enforces
    additionalProperties: false on the response branch).
    """
    enabled = sum(1 for sp in sps if sp.get("accountEnabled") is True)
    type_counts: Counter = Counter(
        sp.get("servicePrincipalType", "Unknown") for sp in sps
    )
    multi_tenant = sum(
        1 for sp in sps
        if sp.get("signInAudience", "AzureADMyOrg") not in ("AzureADMyOrg", "")
    )
    external_owner_tenant_ids = {
        sp["appOwnerOrganizationId"]
        for sp in sps
        if sp.get("appOwnerOrganizationId") and sp["appOwnerOrganizationId"] != tenant_id
    }
    unique_homepage_count = len({sp["homepage"] for sp in sps if sp.get("homepage")})
    return {
        "sp_enabled": enabled,
        "sp_disabled": len(sps) - enabled,
        "sp_type_application": type_counts.get("Application", 0),
        "sp_type_managed_identity": type_counts.get("ManagedIdentity", 0),
        "sp_type_legacy": type_counts.get("Legacy", 0),
        "sp_type_social_idp": type_counts.get("SocialIdp", 0),
        "sp_multi_tenant_count": multi_tenant,
        "sp_external_owner_tenant_count": len(external_owner_tenant_ids),
        "sp_unique_homepage_count": unique_homepage_count,
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Rejewski Tool 6 - T1087.004 Account Discovery (service principals)"
    )
    p.add_argument("--select", default=DEFAULT_SELECT, help="OData $select fields")
    p.add_argument(
        "--page-size", type=int, default=DEFAULT_TOP,
        help=(
            "$top page size (Graph maximum for /servicePrincipals is 100; "
            "distinct from /users which accepts $top=999)"
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
        help="run binding key (e.g. R006); propagated to replay-log entry",
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
    sps: list[dict[str, Any]] = []
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
        sps = list_service_principals(
            token=token,
            token_getter=token_getter,
            select=args.select,
            page_size=args.page_size,
            row_cap=args.row_cap,
            stats=stats,
        )
        row_cap_hit = len(sps) >= args.row_cap
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
    # row_count (object_count) 0. Note the VISIBILITY caveat above: an
    # under-privileged operator also gets an empty list (HTTP 200), not a 403.
    if outcome != "error" and not sps:
        print("No service principals found", file=sys.stderr)

    response_obj: dict[str, Any] = {
        "status_code": stats["last_status"]
        if stats["last_status"]
        else (200 if outcome != "error" else 0),
        "page_count": stats["page_count"],
        "row_count": len(sps),
        "row_cap": args.row_cap,
        "row_cap_hit": len(sps) >= args.row_cap,
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

    sp_summary = _compute_sp_summary(sps, tenant_id) if outcome != "error" else {}

    evidence = {
        "tool": TOOL_NAME,
        "technique": TECHNIQUE_ID,
        "tenant_id": redact_tenant_id(tenant_id),
        "borrowed_client_id": client_id,
        "actor_upn": upn,
        "started_at_utc": started_at,
        "completed_at_utc": completed_at,
        "select": args.select,
        "page_size": args.page_size,
        "row_cap": args.row_cap,
        "row_count": len(sps),
        "row_cap_hit": len(sps) >= args.row_cap,
        "page_count": stats["page_count"],
        "retry_count": stats["retry_count"],
        "outcome": outcome,
        "replay_log_entry": str(replay_path) if replay_path else None,
        **sp_summary,
        "service_principals": sps,
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

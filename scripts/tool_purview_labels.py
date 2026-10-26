#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Rejewski Tool 9 — purview_labels
ATT&CK T1580 Cloud Infrastructure Discovery

Enumerates the Microsoft Purview sensitivity-label inventory via Microsoft Graph
GET /security/dataSecurityAndGovernance/sensitivityLabels. The sensitivity-label
collection answers a tightly-scoped infrastructure-discovery question: how is
this tenant choosing to *classify* its data, which labels are actively enforced,
and where (email, file, teamwork) is each label allowed to apply. An adversary
who reads the label inventory learns the defender's data-protection posture
without ever touching the content the labels guard: which labels carry endpoint
protection, which apply automatically vs by recommendation vs only when the user
picks them, the priority ordering (the highest priority a labeled object can
carry), and the sub-label tree (Confidential/Highly Confidential variants). That
posture map directly informs later-stage Collection targeting — labels that are
defined but `isEnabled: false`, or labels with no `isEndpointProtectionEnabled`
guard, identify data classes that are nominally classified but operationally
unguarded.

Token acquisition, silent reuse, and CAE/CP1 handling are owned by ADR 0005's
encrypted PersistedTokenCache helper. This tool consumes the token via a
token_getter callable; 401 mid-pagination recovers from the encrypted cache, not
in-memory MSAL state.

No tenant-side app registration is created in the target tenant (ADR 0001 §1,
guardrail G-3). Borrowed first-party client defaults to Microsoft Graph Command
Line Tools (14d82eec) per ADR 0004.

Every emitted invocation writes a replay-log entry under the v0.5 schema with
kind="graph_call". A tenant with no Purview sensitivity labels configured is not
an error: the tool prints a notice to stderr and still writes a graph_call entry
with row_count (object_count) 0.

REQUIRED PRIVILEGE:
    GET /security/dataSecurityAndGovernance/sensitivityLabels requires the
    SensitivityLabel.Read delegated scope, admin-consented on the borrowed
    Microsoft Graph Command Line Tools client in cloudharbordemo. Unlike CA-policy
    (T1526), DfI-sensor (T1518.001), and managed-device (T1082) enumeration, no
    Entra directory role is required on the signed-in user — any authenticated
    member with the scope consented can read the tenant's label inventory. This
    keeps T1580 at the same low privilege tier as the other Discovery-leg
    techniques runnable immediately after the T1078.004 initial-access step.

See docs/techniques/T1580.md for the full module.

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
GRAPH_ENDPOINT = f"{GRAPH_BASE}/security/dataSecurityAndGovernance/sensitivityLabels"
# Path recorded on the replay-log request and asserted by the technique doc's
# detection section (MicrosoftGraphActivityLogs RequestUri).
ENDPOINT_PATH = "/security/dataSecurityAndGovernance/sensitivityLabels"
# Fields surfaced per label. The sensitivityLabels endpoint returns the full
# object on a v1.0 read; the projection is enforced locally (see _project_label)
# rather than via $select, matching the tool_dfi_health.py pattern for resources
# whose $select contract is undocumented or unstable.
LABEL_FIELDS = (
    "id",
    "name",
    "description",
    "priority",
    "isEnabled",
    "isEndpointProtectionEnabled",
    "actionSource",
    "applicableTo",
    "sublabels",
)
# Conservative page size: the sensitivity-label collection is small in every
# realistic tenant (single-digit-to-low-double-digit label counts). 100 leaves
# generous headroom while still paginating defensively via @odata.nextLink.
DEFAULT_TOP = 100
DEFAULT_ROW_CAP = 1000
MAX_RETRIES = 3
USER_AGENT = (
    "rejewski-tool-purview-labels/0.1 "
    "(+https://github.com/Cloud-Harbor-Consulting-LLC/rejewski)"
)
REQ_TIMEOUT = (5, 30)
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPLAY_LOG_DIR = REPO_ROOT / "replay-logs"
TECHNIQUE_ID = "T1580"
TECHNIQUE_NAME = "Cloud Infrastructure Discovery"
TOOL_NAME = "tool_purview_labels"
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


def list_labels(
    token: str,
    token_getter: Callable[[], str],
    page_size: int,
    row_cap: int,
    stats: dict[str, int],
) -> list[dict[str, Any]]:
    """Page through GET /security/dataSecurityAndGovernance/sensitivityLabels
    until exhausted or the G-9 row cap is hit. The label inventory returns in a
    single page in every realistic tenant; pagination is implemented defensively
    in case that changes.
    """
    labels: list[dict[str, Any]] = []
    url: str | None = f"{GRAPH_ENDPOINT}?$top={page_size}"
    while url and len(labels) < row_cap:
        body, token, status_code, retries = graph_get(url, token, token_getter)
        stats["page_count"] += 1
        stats["retry_count"] += retries
        stats["last_status"] = status_code
        page = body.get("value", [])
        remaining = row_cap - len(labels)
        labels.extend(page[:remaining])
        if len(labels) >= row_cap:
            break
        url = body.get("@odata.nextLink")
    return labels


def _project_label(label: dict[str, Any]) -> dict[str, Any]:
    """Project a raw label object down to the documented evidence surface."""
    return {field: label.get(field) for field in LABEL_FIELDS}


def _compute_label_summary(labels: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute Purview-specific aggregate metrics for the evidence JSON output.

    Written into the evidence JSON for detection-engineering consumers only.
    NOT added to the replay-log entry — the v0.5 schema enforces
    additionalProperties: false on the graph_call response branch, so
    label-specific counts would fail schema validation (mirrors the DfI sensor
    summary handling in tool_dfi_health.py).
    """
    def _count_action_source() -> dict[str, int]:
        breakdown: dict[str, int] = {}
        for label in labels:
            value = label.get("actionSource") or "unknown"
            breakdown[value] = breakdown.get(value, 0) + 1
        return breakdown

    def _count_applicable_to() -> dict[str, int]:
        # applicableTo is reported per label by the live Graph API as a
        # comma-delimited string ("email,teamwork,file"); the OpenAPI schema
        # also permits an array shape. Split commas so the breakdown shows how
        # many labels cover each surface individually, not how many share the
        # exact same combination of surfaces.
        breakdown: dict[str, int] = {}
        for label in labels:
            raw = label.get("applicableTo") or []
            if isinstance(raw, str):
                scopes = [s.strip() for s in raw.split(",") if s.strip()]
            else:
                scopes = [s for s in raw if s]
            for scope in scopes:
                breakdown[scope] = breakdown.get(scope, 0) + 1
        return breakdown

    enabled = sum(1 for label in labels if label.get("isEnabled") is True)
    with_sublabels = sum(
        1 for label in labels if (label.get("sublabels") or [])
    )
    return {
        "total_labels": len(labels),
        "enabled_count": enabled,
        "disabled_count": len(labels) - enabled,
        "applicable_to_breakdown": _count_applicable_to(),
        "labels_with_sublabels": with_sublabels,
        "action_source_breakdown": _count_action_source(),
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Rejewski Tool 9 - T1580 Cloud Infrastructure Discovery (Purview labels)"
    )
    p.add_argument(
        "--page-size", type=int, default=DEFAULT_TOP,
        help=(
            "$top page size for sensitivity labels (default: 100; the label "
            "inventory returns in a single page in every realistic tenant — "
            "pagination is defensive)"
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

    started_at = utc_now_iso()
    initial_url = f"{GRAPH_ENDPOINT}?$top={args.page_size}"
    request_obj: dict[str, Any] = {
        "method": "GET",
        "url": initial_url,
        "headers": {
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json",
        },
    }

    stats: dict[str, int] = {"page_count": 0, "retry_count": 0, "last_status": 0}
    labels: list[dict[str, Any]] = []
    error_block: dict[str, Any] | None = None
    outcome: str

    try:
        token = token_getter()
        labels = list_labels(
            token=token,
            token_getter=token_getter,
            page_size=args.page_size,
            row_cap=args.row_cap,
            stats=stats,
        )
        row_cap_hit = len(labels) >= args.row_cap
        outcome = "row_cap_hit" if row_cap_hit else "success"
    except (RuntimeError, requests.RequestException) as exc:
        outcome = "error"
        error_block = make_error(
            type_=ERROR_TYPE_URN,
            message=str(exc),
            status_code=stats["last_status"] or None,
        )

    completed_at = utc_now_iso()

    # Empty inventory is a valid, non-error outcome (G-5): notice to stderr keeps
    # stdout machine-readable, and the graph_call entry below still records
    # object_count 0.
    if outcome != "error" and not labels:
        print("No sensitivity labels found", file=sys.stderr)

    response_obj: dict[str, Any] = {
        "status_code": stats["last_status"] if stats["last_status"] else (200 if outcome != "error" else 0),
        "page_count": stats["page_count"],
        "row_count": len(labels),
        "row_cap": args.row_cap,
        "row_cap_hit": len(labels) >= args.row_cap,
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

    projected = [_project_label(label) for label in labels]
    label_summary = _compute_label_summary(projected) if outcome != "error" else {}

    evidence = {
        "tool": TOOL_NAME,
        "technique": TECHNIQUE_ID,
        "tenant_id": redact_tenant_id(tenant_id),
        "borrowed_client_id": client_id,
        "actor_upn": upn,
        "started_at_utc": started_at,
        "completed_at_utc": completed_at,
        "endpoint": ENDPOINT_PATH,
        "page_size": args.page_size,
        "row_cap": args.row_cap,
        "row_count": len(labels),
        "row_cap_hit": len(labels) >= args.row_cap,
        "page_count": stats["page_count"],
        "retry_count": stats["retry_count"],
        "outcome": outcome,
        "replay_log_entry": str(replay_path) if replay_path else None,
        **label_summary,
        "sensitivity_labels": projected,
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

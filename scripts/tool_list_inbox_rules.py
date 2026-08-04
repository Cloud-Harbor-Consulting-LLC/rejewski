#!/usr/bin/env python3
"""
Rejewski Sprint 4 W13 Tool 13 — list_inbox_rules
ATT&CK T1114.002 Email Collection: Remote Email Collection (Surface A — inbox rules)

Enumerates a mailbox's inbox message rules via Microsoft Graph
GET /users/{id}/mailFolders/inbox/messageRules (or /me/... for the operator's own
mailbox). Inbox rules are the adversary's email-collection and covering-tracks
configuration layer: a rule that forwards or redirects to an external address is a
collection indicator, and a rule that deletes or moves incoming mail to a hidden
folder is a covering-tracks indicator. Reading the rule set tells an adversary
whether email-collection plumbing already exists — their own from a prior stage, or
a defender's — before they act.

This maps to T1114.002 as the inbox-rule surface (Surface A). It complements the
originally-catalogued folder/message-metadata surface documented in
docs/techniques/T1114.002.md, which remains deferred.

Token acquisition, silent reuse, and CAE/CP1 handling are owned by ADR 0005's
encrypted PersistedTokenCache helper. The token is consumed via a token_getter
callable; identity.acquire_token emits the token_event (T1078.004 on a fresh ROPC
sign-in, T1550.001 on silent reuse, per B029). 401 mid-pagination recovers from the
encrypted cache, not in-memory MSAL state.

No tenant-side app registration is created in the target tenant (ADR 0001 §1,
guardrail G-3). Borrowed first-party client is Microsoft Graph Command Line Tools.
The FOCI client is fixed to 14d82eec per ADR-0006 and guardrail G-3.

Every emitted invocation writes a replay-log entry under the v0.5 schema with
kind="graph_call". A mailbox with no inbox rules is not an error: the tool prints a
notice to stderr and still writes a graph_call entry with row_count (rule_count) 0.

REQUIRED PRIVILEGE — SCOPE AND DIRECTORY ROLE:
    GET /users/{id}/mailFolders/inbox/messageRules requires the MailboxSettings.Read
    delegated scope, admin-consented on the borrowed client in cloudharbordemo.
    - Self (--user-id me): no Entra directory role required — any authenticated
      member can read their own inbox rules.
    - Cross-user (--user-id <object-id>): requires Exchange Administrator or Global
      Reader on the signed-in user. Without a qualifying role, reading another
      user's mailbox returns HTTP 403.
    In cloudharbordemo, meganb@cloudharbor-demo.com reads her own rules with no role;
    cross-user enumeration is a post-privilege step.

See docs/techniques/T1114.002.md Surface A for the full module.

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
DEFAULT_USER = "me"
DEFAULT_ROW_CAP = 500  # G-9: inbox rules per mailbox
MAX_RETRIES = 3
USER_AGENT = (
    "rejewski-tool-list-inbox-rules/0.1 "
    "(+https://github.com/Cloud-Harbor-Consulting-LLC/rejewski)"
)
REQ_TIMEOUT = (5, 30)
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPLAY_LOG_DIR = REPO_ROOT / "replay-logs"
TECHNIQUE_ID = "T1114.002"
TECHNIQUE_NAME = "Email Collection: Remote Email Collection"
TOOL_NAME = "tool_list_inbox_rules"
ERROR_TYPE_URN = "urn:rejewski:error:tool-invocation-failed"


def _mailbox_path(user_id: str) -> str:
    """Graph path segment for the target mailbox: /me/... for self, else
    /users/{id}/... for a named mailbox."""
    if user_id == DEFAULT_USER:
        return "me"
    return f"users/{user_id}"


def _build_url(user_id: str) -> str:
    return f"{GRAPH_BASE}/{_mailbox_path(user_id)}/mailFolders/inbox/messageRules"


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


def list_inbox_rules(
    token: str,
    token_getter: Callable[[], str],
    user_id: str,
    row_cap: int,
    stats: dict[str, int],
) -> list[dict[str, Any]]:
    """Page through the inbox messageRules collection until exhausted or the G-9
    row cap is hit. The collection returns in a single page in every realistic
    mailbox; @odata.nextLink is followed defensively and the cap is applied to
    total rules collected, not per page.
    """
    rules: list[dict[str, Any]] = []
    url: str | None = _build_url(user_id)
    while url and len(rules) < row_cap:
        body, token, status_code, retries = graph_get(url, token, token_getter)
        stats["page_count"] += 1
        stats["retry_count"] += retries
        stats["last_status"] = status_code
        page = body.get("value", [])
        remaining = row_cap - len(rules)
        rules.extend(page[:remaining])
        if len(rules) >= row_cap:
            break
        url = body.get("@odata.nextLink")
    return rules


def _recipient_addresses(recipients: Any) -> list[str]:
    """Extract the email addresses from a Graph recipient list. These are the
    forwarding/redirect targets — the high-signal collection indicator — so they
    are retained (they are the point of the enumeration). No message body content
    is present in a rule object."""
    out: list[str] = []
    for r in recipients or []:
        email = (r or {}).get("emailAddress") or {}
        address = email.get("address")
        if address:
            out.append(address)
    return out


def _project_rule(rule: dict[str, Any]) -> dict[str, Any]:
    """Project a raw messageRule down to the documented evidence surface:
    identity + enablement + the forwarding/hiding actions and matching
    conditions that indicate collection or covering-tracks configuration."""
    actions = rule.get("actions") or {}
    conditions = rule.get("conditions") or {}
    return {
        "id": rule.get("id"),
        "displayName": rule.get("displayName"),
        "isEnabled": rule.get("isEnabled"),
        "hasError": rule.get("hasError"),
        "actions": {
            "forwardTo": _recipient_addresses(actions.get("forwardTo")),
            "forwardAsAttachmentTo": _recipient_addresses(
                actions.get("forwardAsAttachmentTo")
            ),
            "redirectTo": _recipient_addresses(actions.get("redirectTo")),
            "delete": bool(actions.get("delete", False)),
            "moveToFolder": actions.get("moveToFolder"),
        },
        "conditions": {
            "senderContains": conditions.get("senderContains") or [],
            "subjectContains": conditions.get("subjectContains") or [],
            "bodyContains": conditions.get("bodyContains") or [],
        },
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Rejewski Tool 13 - T1114.002 Email Collection "
            "(inbox message rules, Surface A)"
        )
    )
    p.add_argument(
        "--user-id",
        default=DEFAULT_USER,
        help=(
            "target mailbox: 'me' (default, operator's own inbox — no role "
            "required) or an Entra user object ID (cross-user — requires "
            "Exchange Administrator or Global Reader)"
        ),
    )
    p.add_argument(
        "--row-cap", type=int, default=DEFAULT_ROW_CAP,
        help="G-9 enumeration row cap applied to total rules (not per page)",
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
        help="run binding key (e.g. R012); propagated to replay-log entry",
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
    initial_url = _build_url(args.user_id)
    request_obj: dict[str, Any] = {
        "method": "GET",
        "url": initial_url,
        "headers": {
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json",
        },
    }

    stats: dict[str, int] = {"page_count": 0, "retry_count": 0, "last_status": 0}
    rules: list[dict[str, Any]] = []
    error_block: dict[str, Any] | None = None
    outcome: str

    try:
        token = token_getter()
        rules = list_inbox_rules(
            token=token,
            token_getter=token_getter,
            user_id=args.user_id,
            row_cap=args.row_cap,
            stats=stats,
        )
        row_cap_hit = len(rules) >= args.row_cap
        outcome = "row_cap_hit" if row_cap_hit else "success"
    except (RuntimeError, requests.RequestException) as exc:
        outcome = "error"
        error_block = make_error(
            type_=ERROR_TYPE_URN,
            message=str(exc),
            status_code=stats["last_status"] or None,
        )
        if "HTTP 403" in str(exc):
            print(
                "HTTP 403 — access denied reading inbox message rules.\n"
                "  Self-mailbox (--user-id me) needs only MailboxSettings.Read on\n"
                f"  the borrowed client {client_id}. Cross-user enumeration also\n"
                "  requires Exchange Administrator or Global Reader on the signed-in\n"
                "  account. See docs/techniques/T1114.002.md Surface A.",
                file=sys.stderr,
            )
        else:
            print(f"error: {exc}", file=sys.stderr)

    completed_at = utc_now_iso()

    # Empty result is a valid, non-error outcome (G-5): notice to stderr keeps
    # stdout machine-readable, and the graph_call entry below still records
    # row_count (rule_count) 0.
    if outcome != "error" and not rules:
        print("No inbox rules found", file=sys.stderr)

    response_obj: dict[str, Any] = {
        "status_code": stats["last_status"] if stats["last_status"] else (200 if outcome != "error" else 0),
        "page_count": stats["page_count"],
        "row_count": len(rules),
        "row_cap": args.row_cap,
        "row_cap_hit": len(rules) >= args.row_cap,
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

    projected = [_project_rule(r) for r in rules]

    evidence = {
        "tool": TOOL_NAME,
        "technique": TECHNIQUE_ID,
        "tenant_id": redact_tenant_id(tenant_id),
        "borrowed_client_id": client_id,
        "actor_upn": upn,
        "user_id": args.user_id,
        "started_at_utc": started_at,
        "completed_at_utc": completed_at,
        "endpoint": _build_url(args.user_id),
        "rule_count": len(rules),
        "row_cap": args.row_cap,
        "row_cap_hit": len(rules) >= args.row_cap,
        "page_count": stats["page_count"],
        "retry_count": stats["retry_count"],
        "outcome": outcome,
        "replay_log_entry": str(replay_path) if replay_path else None,
        "rules": projected,
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

#!/usr/bin/env python3
"""
Rejewski — Sonnet/Opus reasoning-loop driver.

Walks a recon plan one step at a time. For each step it asks the routing config
(rejewski.config.json -> rejewski.routing, loaded via scripts/rejewski_runtime.py)
which Claude model should handle the step:

  * Sonnet 4.6 (default) for routine enumeration steps.
  * Opus 4.6 for "hard" steps — deeper, multi-hop inference (privilege-graph
    correlation, alternate-auth token chaining, domain-trust analysis,
    finding-to-control mapping). A step is hard when its name is in
    routing.hard_steps or its ATT&CK technique is in routing.hard_techniques.

It then writes one replay-log entry per step, stamped with the chosen model_id
(replay-log schema v0.5). Routing + the model_id stamp are this loop's
contribution; the per-step request/response envelope mirrors what the underlying
technique tool (scripts/tool_list_*.py, scripts/identity.py) emits.

This driver runs OFFLINE. It routes and records — it does not make live
Microsoft Graph calls. Live recon is performed by the operator-run technique
tools against the sandbox tenant (which authenticate the compromised user and
hit Graph); wiring those tools to the agent loop requires a Graph MCP server,
which is intentionally not configured in rejewski.config.json. The reasoning
loop here is the model-routing layer that sits above those tools and labels each
resulting replay-log entry with the model that drove the step.

Usage:
    python scripts/reasoning_loop.py --run-id RLOOP-01
    python scripts/reasoning_loop.py --run-id RLOOP-01 --emit
    python scripts/reasoning_loop.py --run-id RLOOP-01 --emit --log-dir replay-logs
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from replay_log import (
    DEFAULT_LOG_DIR,
    SANDBOX_TENANT_ID,
    ReplayLogEntry,
    utc_now_iso,
    write_entry,
)
from rejewski_runtime import RoutingConfig, load_config

DEFAULT_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
DEFAULT_ACTOR_UPN = "meganb@cloudharbor-demo.com"


@dataclass
class Step:
    """One planned reasoning-loop step.

    ``name`` is the routing key matched against routing.hard_steps; ``kind`` is
    the replay-log kind ("graph_call" or "token_event"); ``request`` and
    ``response`` are the envelope the underlying tool would emit for this step.
    """

    name: str
    technique_id: str
    technique_name: str
    tool: str
    kind: str
    request: dict[str, Any]
    response: dict[str, Any]
    outcome: str = "success"
    hard: bool | None = None  # None -> classify via routing config


def _graph_request(url: str, ua: str) -> dict[str, Any]:
    return {
        "method": "GET",
        "url": url,
        "headers": {
            "User-Agent": ua,
            "Content-Type": "application/json",
        },
    }


def _token_request() -> dict[str, Any]:
    return {
        "method": "POST",
        "url": (
            f"https://login.microsoftonline.com/{SANDBOX_TENANT_ID}"
            "/oauth2/v2.0/token"
        ),
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "flow": "silent",
        "scopes": ["https://graph.microsoft.com/.default"],
    }


def _graph_response(rows: int, pages: int = 1) -> dict[str, Any]:
    return {
        "status_code": 200,
        "page_count": pages,
        "row_count": rows,
        "row_cap": 1000,
        "row_cap_hit": False,
        "retry_count": 0,
    }


def _token_response() -> dict[str, Any]:
    return {
        "status_code": 200,
        "aadsts_code": None,
        "correlation_id": None,
        "persistence_kind": "encrypted",
        "cache_path": "<redacted>",
        "flow": "silent",
    }


# Representative sandbox-tenant recon plan. Mixes routine enumeration steps
# (routed to Sonnet) with hard multi-hop analysis steps (routed to Opus).
PLAN: list[Step] = [
    Step(
        name="list_users",
        technique_id="T1087.004",
        technique_name="Account Discovery: Cloud Account",
        tool="tool_list_users",
        kind="graph_call",
        request=_graph_request(
            "https://graph.microsoft.com/v1.0/users"
            "?$select=id,displayName,userPrincipalName&$top=999",
            "rejewski-tool-list-users/0.2",
        ),
        response=_graph_response(rows=8),
    ),
    Step(
        name="list_groups",
        technique_id="T1069.003",
        technique_name="Permission Groups Discovery: Cloud Groups",
        tool="tool_list_groups",
        kind="graph_call",
        request=_graph_request(
            "https://graph.microsoft.com/v1.0/groups"
            "?$select=id,displayName,groupTypes&$top=999",
            "rejewski-tool-list-groups/0.2",
        ),
        response=_graph_response(rows=19),
    ),
    Step(
        name="list_service_principals",
        technique_id="T1087.004",
        technique_name="Account Discovery: Cloud Account",
        tool="tool_list_service_principals",
        kind="graph_call",
        request=_graph_request(
            "https://graph.microsoft.com/v1.0/servicePrincipals"
            "?$select=id,appId,displayName,servicePrincipalType&$top=100",
            "rejewski-tool-list-service-principals/0.2",
        ),
        response=_graph_response(rows=279, pages=3),
    ),
    Step(
        name="role_assignment_analysis",
        technique_id="T1087.004",
        technique_name="Account Discovery: Cloud Account",
        tool="tool_list_role_assignments",
        kind="graph_call",
        request=_graph_request(
            "https://graph.microsoft.com/v1.0/roleManagement/directory/"
            "roleAssignments?$expand=principal,roleDefinition",
            "rejewski-tool-list-role-assignments/0.2",
        ),
        response=_graph_response(rows=31),
    ),
    Step(
        name="token_chaining",
        technique_id="T1550.001",
        technique_name="Application Access Token (refresh-token reuse)",
        tool="scripts.identity",
        kind="token_event",
        request=_token_request(),
        response=_token_response(),
    ),
    Step(
        name="domain_trust_analysis",
        technique_id="T1482",
        technique_name="Domain Trust Discovery",
        tool="tool_list_domains",
        kind="graph_call",
        request=_graph_request(
            "https://graph.microsoft.com/v1.0/domains"
            "?$select=id,authenticationType,isDefault,isVerified",
            "rejewski-tool-list-domains/0.2",
        ),
        response=_graph_response(rows=4),
    ),
]


@dataclass
class StepResult:
    name: str
    technique_id: str
    kind: str
    model_id: str
    hard: bool
    written_path: Path | None = None


def run_plan(
    plan: list[Step],
    routing: RoutingConfig,
    *,
    run_id: str,
    emit: bool = False,
    log_dir: Path | None = None,
    actor_upn: str = DEFAULT_ACTOR_UPN,
    borrowed_client_id: str = DEFAULT_CLIENT_ID,
) -> list[StepResult]:
    """Route each step, optionally writing a model_id-stamped replay entry.

    Returns one StepResult per step (model decision + written path). When
    ``emit`` is False the routing decisions are computed and returned but no
    files are written — handy for tests and dry runs.
    """
    results: list[StepResult] = []
    for step in plan:
        hard = routing.is_hard(step=step.name, technique_id=step.technique_id)
        if step.hard is not None:
            hard = step.hard
        model_id = routing.select_model(hard=hard)

        written_path: Path | None = None
        if emit:
            now = utc_now_iso()
            entry = ReplayLogEntry(
                kind=step.kind,
                tool=step.tool,
                technique_id=step.technique_id,
                technique_name=step.technique_name,
                tenant_id=SANDBOX_TENANT_ID,
                borrowed_client_id=borrowed_client_id,
                actor_upn=actor_upn,
                started_at_utc=now,
                completed_at_utc=now,
                request=dict(step.request),
                response=dict(step.response),
                outcome=step.outcome,
                run_id=run_id,
                model_id=model_id,
            )
            written_path = write_entry(entry, log_dir=log_dir)

        results.append(
            StepResult(
                name=step.name,
                technique_id=step.technique_id,
                kind=step.kind,
                model_id=model_id,
                hard=hard,
                written_path=written_path,
            )
        )
    return results


def _print_summary(results: list[StepResult]) -> None:
    width = max(len(r.name) for r in results)
    print(f"{'step'.ljust(width)}  technique   model")
    print(f"{'-' * width}  ---------   -----")
    for r in results:
        tag = "  (hard)" if r.hard else ""
        print(
            f"{r.name.ljust(width)}  {r.technique_id.ljust(10)}  "
            f"{r.model_id}{tag}"
        )
    models = sorted({r.model_id for r in results})
    print(
        f"\n--- {len(results)} steps routed across {len(models)} models: "
        f"{', '.join(models)} ---"
    )


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run-id",
        required=True,
        help="Run ID bound to every emitted replay-log entry (e.g. RLOOP-01).",
    )
    parser.add_argument(
        "--emit",
        action="store_true",
        help="Write one model_id-stamped replay-log entry per step.",
    )
    parser.add_argument(
        "--log-dir",
        default=None,
        help=(
            "Directory for emitted entries (default: "
            f"{DEFAULT_LOG_DIR.relative_to(DEFAULT_LOG_DIR.parents[1])})."
        ),
    )
    parser.add_argument(
        "--actor-upn",
        default=DEFAULT_ACTOR_UPN,
        help="Operator UPN recorded on each entry.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    cfg = load_config()
    log_dir = Path(args.log_dir) if args.log_dir else None

    results = run_plan(
        PLAN,
        cfg.rejewski.routing,
        run_id=args.run_id,
        emit=args.emit,
        log_dir=log_dir,
        actor_upn=args.actor_upn,
    )

    _print_summary(results)

    models = {r.model_id for r in results}
    if len(models) < 2:
        print(
            "warning: routing produced a single model — expected a mix of "
            f"{cfg.rejewski.routing.default_model} and "
            f"{cfg.rejewski.routing.hard_step_model}",
            file=sys.stderr,
        )
        return 1

    if args.emit:
        written = [r.written_path for r in results if r.written_path]
        print(f"\nwrote {len(written)} replay-log entries (run {args.run_id})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

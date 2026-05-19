from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from scripts.replay_log import (
    DEFAULT_KIND,
    ReplayLogEntry,
    make_error,
    utc_now_iso,
    write_entry,
)

WRAPPER_ERROR_TYPE_URN = "urn:rejewski:error:wrapped-tool-failed"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a Rejewski tool and write a replay-log entry."
    )
    parser.add_argument("--tool-name", required=True)
    parser.add_argument("--technique-id", required=True)
    parser.add_argument("--technique-name", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--borrowed-client-id", required=True)
    parser.add_argument("--actor-upn", required=True)
    parser.add_argument("--graph-method", default="GET")
    parser.add_argument("--graph-url", required=True)
    parser.add_argument(
        "--graph-query",
        help="JSON object of query parameters",
        default=None,
    )
    parser.add_argument(
        "tool_cmd",
        nargs=argparse.REMAINDER,
        help="Tool invocation after --, e.g. -- python scripts/tool_list_users.py --top 999",
    )
    return parser.parse_args()


def _parse_query(raw: str | None) -> dict | None:
    if not raw:
        return None
    return json.loads(raw)


def _row_count_from_stdout(stdout: str) -> int:
    try:
        body = json.loads(stdout)
    except json.JSONDecodeError:
        return 0
    if isinstance(body, dict) and isinstance(body.get("value"), list):
        return len(body["value"])
    if isinstance(body, list):
        return len(body)
    return 0


def main() -> int:
    args = _parse_args()
    cmd = args.tool_cmd
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        sys.stderr.write("error: pass the tool invocation after --\n")
        return 2

    started = utc_now_iso()
    proc = subprocess.run(cmd, capture_output=True, text=True)
    completed = utc_now_iso()

    request = {
        "method": args.graph_method,
        "url": args.graph_url,
        "headers": {"User-Agent": f"rejewski-{args.tool_name}/0.1"},
    }
    query = _parse_query(args.graph_query)
    if query is not None:
        request["query"] = query

    if proc.returncode == 0:
        outcome = "success"
        error = None
        response = {
            "status_code": 200,
            "page_count": 1,
            "row_count": _row_count_from_stdout(proc.stdout),
        }
    else:
        outcome = "error"
        message = (proc.stderr or "").strip()[:500] or "wrapped tool exited non-zero"
        error = make_error(
            type_=WRAPPER_ERROR_TYPE_URN,
            message=message,
        )
        response = {
            "status_code": 0,
            "page_count": 0,
            "row_count": 0,
        }

    entry = ReplayLogEntry(
        tool=args.tool_name,
        technique_id=args.technique_id,
        technique_name=args.technique_name,
        tenant_id=args.tenant_id,
        borrowed_client_id=args.borrowed_client_id,
        actor_upn=args.actor_upn,
        started_at_utc=started,
        completed_at_utc=completed,
        request=request,
        response=response,
        outcome=outcome,
        error=error,
        kind=DEFAULT_KIND,
    )

    path = write_entry(entry)
    sys.stdout.write(f"replay-log entry written: {path}\n")
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
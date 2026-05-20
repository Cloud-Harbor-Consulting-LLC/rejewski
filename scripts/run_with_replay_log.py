#!/usr/bin/env python3
"""
Rejewski — external subprocess wrapper that guarantees a replay-log entry
even if the wrapped tool crashes mid-run.

Usage:
    python scripts/run_with_replay_log.py \\
        --tool scripts/tool_list_users.py \\
        --technique-id T1087.004 \\
        --technique-name "Account Discovery: Cloud Account" \\
        --tenant-id <guid> --actor-upn <upn> [-- <tool args...>]

The wrapper runs the tool as a subprocess, records start/end timestamps,
captures the tool's stdout JSON envelope (when present), and emits one
graph_call replay-log entry to samples/replay-log/.

If the tool exits non-zero or fails to emit a parseable envelope, the
wrapper writes an outcome=error entry with stderr tail in error.message.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from replay_log import (
    ReplayLogEntry,
    make_error,
    utc_now_iso,
    write_entry,
)

DEFAULT_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
ERROR_TYPE_URN = "urn:rejewski:error:tool-subprocess-failed"
STDERR_TAIL_CHARS = 4000


def _parse_args() -> tuple[argparse.Namespace, list[str]]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", required=True, help="Path to the tool script")
    parser.add_argument("--technique-id", required=True)
    parser.add_argument("--technique-name", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--actor-upn", required=True)
    parser.add_argument("--borrowed-client-id", default=DEFAULT_CLIENT_ID)
    parser.add_argument("--tool-name", default=None)
    return parser.parse_known_args()


def _tool_label(args: argparse.Namespace) -> str:
    if args.tool_name:
        return args.tool_name
    return Path(args.tool).stem


def _try_parse_envelope(stdout: str) -> dict | None:
    stdout = (stdout or "").strip()
    if not stdout:
        return None
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        for line in reversed(stdout.splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
    return None


def main() -> int:
    args, tool_args = _parse_args()
    started_at = utc_now_iso()
    cmd = [sys.executable, args.tool, *tool_args]

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )

    completed_at = utc_now_iso()
    envelope = _try_parse_envelope(proc.stdout)
    stderr_tail = (proc.stderr or "")[-STDERR_TAIL_CHARS:]

    if proc.returncode == 0 and envelope is not None:
        outcome = envelope.get("outcome", "success")
        request_obj = envelope.get("request") or {
            "method": "GET",
            "url": "n/a",
            "headers": {},
        }
        response_obj = envelope.get("response") or {
            "status_code": 200,
            "page_count": 0,
            "row_count": 0,
        }
        error_block = envelope.get("error")
    else:
        outcome = "error"
        request_obj = {
            "method": "subprocess",
            "url": args.tool,
            "headers": {},
            "argv": cmd,
        }
        response_obj = {
            "status_code": 0,
            "page_count": 0,
            "row_count": 0,
            "retry_count": 0,
        }
        msg = (
            f"tool subprocess exit={proc.returncode}; "
            f"stderr_tail={stderr_tail!r}"
        )
        error_block = make_error(
            type_=ERROR_TYPE_URN,
            message=msg,
            status_code=None,
        )

    entry = ReplayLogEntry(
        kind="graph_call",
        tool=_tool_label(args),
        technique_id=args.technique_id,
        technique_name=args.technique_name,
        tenant_id=args.tenant_id,
        borrowed_client_id=args.borrowed_client_id,
        actor_upn=args.actor_upn,
        started_at_utc=started_at,
        completed_at_utc=completed_at,
        request=request_obj,
        response=response_obj,
        outcome=outcome,
        error=error_block,
    )
    target = write_entry(entry)

    sys.stdout.write(proc.stdout)
    if proc.stderr:
        sys.stderr.write(proc.stderr)
    sys.stderr.write(f"\n[replay-log] wrote {target}\n")
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
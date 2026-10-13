#!/usr/bin/env python3
"""
Rejewski — replay-log run consolidator (B022 + B023).

Reads every .json file in replay-logs/, selects the entries belonging to a
single run, and writes them as one JSON array to samples/replay-log/<run-id>.json.

Replaces the Sprint 1 Checkpoint demo's combine step, which used a `[-3:]`
slice to pick "the last 3 files". A run that exercises N tools produces 2N
replay-log files (one token_event + one graph_call per tool), so the slice
silently dropped entries on any run larger than a single tool (B022). This
utility reads *all* files in replay-logs/ instead.

It also automatically redacts the operator-local `cache_path` value on every
token_event entry before writing to samples/, replacing it with "<redacted>"
(B023, G-6). The redaction is unconditional — there is no flag to disable it,
so no operator filesystem path can reach samples/ through this tool.

Usage:
    python scripts/consolidate_run.py --run-id R007
    python scripts/consolidate_run.py --run-id R007 --keep-session

Session teardown (G-8): consolidation is the last step of a run, so after the
run's evidence is written this utility ends the session for every account that
acquired a token in the run, by deleting that account's local token cache
(scripts/identity.end_session). The next run signs in again instead of
silently reusing a refresh token from this one. Pass --keep-session to skip the
teardown, for example when consolidating part of a run that is still going.
Teardown is local only; see identity.end_session for why the refresh token is
not revoked at Entra ID.

Entry selection:
  * graph_call / token_event entries carry a `run_id` field; they are
    included when it matches --run-id.
  * Consent records (roe-consent-flow.md §3) are detected by the presence of
    an `event` key rather than `kind`. They also carry a `run_id`; they are
    included when it matches and skipped otherwise.

Exits 0 on success. Exits 1 with a stderr message if replay-logs/ does not
exist or if no entry matching --run-id was found in any file.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
REPLAY_LOGS_DIR = REPO_ROOT / "replay-logs"
SAMPLES_DIR = REPO_ROOT / "samples" / "replay-log"

REDACTED_CACHE_PATH = "<redacted>"


def _is_consent_record(entry: dict[str, Any]) -> bool:
    """Consent records carry an `event` key rather than a `kind` key."""
    return "event" in entry and "kind" not in entry


def _matches_run(entry: dict[str, Any], run_id: str) -> bool:
    """Both replay entries and consent records carry a run_id field."""
    return entry.get("run_id") == run_id


def _redact_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Replace cache_path on token_event entries with a redaction marker.

    Operates on a shallow copy so the source object is left untouched. Only
    token_event entries carry cache_path (in response); other entries pass
    through unchanged.
    """
    if entry.get("kind") != "token_event":
        return entry
    response = entry.get("response")
    if isinstance(response, dict) and "cache_path" in response:
        entry = dict(entry)
        entry["response"] = {**response, "cache_path": REDACTED_CACHE_PATH}
    return entry


def _iter_entries(payload: Any) -> list[dict[str, Any]]:
    """A replay-log file is a single JSON object or an array of objects."""
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        return [payload]
    return []


def collect_run_entries(run_id: str, log_dir: Path) -> list[dict[str, Any]]:
    """Return every entry across log_dir whose run_id matches, redacted."""
    matched: list[dict[str, Any]] = []
    for path in sorted(log_dir.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            print(f"warning: skipping unreadable file {path}: {exc}", file=sys.stderr)
            continue
        for entry in _iter_entries(payload):
            if _matches_run(entry, run_id):
                matched.append(_redact_entry(entry))
    return matched


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run-id",
        required=True,
        help="Run ID to consolidate (e.g. R007).",
    )
    parser.add_argument(
        "--keep-session",
        action="store_true",
        help="Skip the G-8 session teardown (leave the run's token caches in place).",
    )
    return parser.parse_args(argv)


def run_actor_upns(entries: list[dict[str, Any]]) -> list[str]:
    """Accounts that acquired a token in the run (token_event actor_upn), in order."""
    upns: list[str] = []
    for entry in entries:
        upn = entry.get("actor_upn")
        if entry.get("kind") == "token_event" and upn and upn not in upns:
            upns.append(upn)
    return upns


def end_run_sessions(entries: list[dict[str, Any]]) -> int:
    """G-8 teardown: delete the local token cache of every account in the run.

    Returns the number of files removed. Prints per-account counts only, never the
    operator-local cache path (G-6).
    """
    import identity  # deferred: identity pulls in msal, which consolidation alone does not need

    removed_total = 0
    for upn in run_actor_upns(entries):
        removed = identity.end_session(upn)
        removed_total += len(removed)
        state = "token cache deleted" if removed else "no token cache found"
        print(f"G-8 session teardown for {upn}: {state}")
    return removed_total


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    run_id = args.run_id

    if not REPLAY_LOGS_DIR.is_dir():
        print(
            f"error: replay-logs directory does not exist: {REPLAY_LOGS_DIR}",
            file=sys.stderr,
        )
        return 1

    entries = collect_run_entries(run_id, REPLAY_LOGS_DIR)
    if not entries:
        print(
            f"error: no entries found for run_id {run_id!r} in {REPLAY_LOGS_DIR}",
            file=sys.stderr,
        )
        return 1

    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    out_path = SAMPLES_DIR / f"{run_id}.json"
    out_path.write_text(
        json.dumps(entries, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(entries)} entries for run {run_id} to {out_path}")
    if args.keep_session:
        print("G-8 session teardown skipped (--keep-session)")
    else:
        end_run_sessions(entries)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

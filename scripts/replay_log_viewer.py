#!/usr/bin/env python3
"""
Rejewski replay-log viewer (v0.1 prototype)

Reads any Rejewski replay-log file and prints it to stdout in a compact,
human-readable form. Pure local file reader — no Microsoft Graph calls, no
network, no schema validation.

A replay-log file is either a single JSON object or a JSON array of objects.
Three entry shapes are recognised:

  * graph_call   — a Graph request/response pair (kind == "graph_call")
  * token_event  — an identity token acquisition (kind == "token_event")
  * consent      — a consent.granted / consent.declined record

Consent records as written today (roe-consent-flow.md §3) use an "event"
key rather than "kind", and carry operator_object_id / confirmed_at instead
of operator_upn / timestamp_utc. The viewer reads both that real shape and
the kind/operator_upn/timestamp_utc variant described in the schema notes,
so it stays readable regardless of which producer wrote the file.

Usage:
    python scripts/replay_log_viewer.py <path>
    cat <path> | python scripts/replay_log_viewer.py -
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any
from urllib.parse import urlsplit


def _read_source(path: str) -> str:
    """Return the raw text of the replay log, from stdin if path is '-'."""
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _short_tenant(tenant_id: Any) -> str:
    """First GUID segment of a tenant ID, e.g. 76b87c33-... -> 76b87c33."""
    if not isinstance(tenant_id, str) or not tenant_id:
        return "?"
    return tenant_id.split("-", 1)[0]


def _short_url(url: Any) -> str:
    """Path portion of a Graph URL, with the /v1.0 or /beta version prefix
    and the query string stripped for readability."""
    if not isinstance(url, str) or not url:
        return "?"
    path = urlsplit(url).path or url
    for prefix in ("/v1.0", "/beta"):
        if path.startswith(prefix + "/"):
            path = path[len(prefix):]
            break
    return path or "/"


def _classify(entry: dict[str, Any]) -> str:
    """Return one of: graph_call, token_event, consent, other."""
    kind = entry.get("kind")
    if kind == "graph_call":
        return "graph_call"
    if kind == "token_event":
        return "token_event"
    event = entry.get("event")
    if isinstance(kind, str) and kind.startswith("consent."):
        return "consent"
    if isinstance(event, str) and event.startswith("consent."):
        return "consent"
    return "other"


def _technique_label(entry: dict[str, Any]) -> str:
    """Render the technique block as 'T1087.004 Account Discovery: ...'."""
    technique = entry.get("technique")
    if isinstance(technique, dict):
        tid = technique.get("id", "?")
        name = technique.get("name")
        return f"{tid} {name}" if name else str(tid)
    if isinstance(technique, str):
        return technique
    return "?"


def _format_consent(entry: dict[str, Any]) -> str:
    label = entry.get("event") or entry.get("kind") or "consent"
    run_id = entry.get("run_id", "?")
    operator = entry.get("operator_upn") or entry.get("operator_object_id") or "?"
    tenant = _short_tenant(entry.get("tenant_id"))
    techniques = entry.get("techniques")
    techniques_str = ",".join(techniques) if isinstance(techniques, list) else "?"
    when = (
        entry.get("timestamp_utc")
        or entry.get("confirmed_at")
        or entry.get("prompt_emitted_at")
        or "?"
    )
    return (
        f"[{label}] run_id={run_id} operator={operator} "
        f"tenant={tenant} techniques={techniques_str} @ {when}"
    )


def _format_graph_call(entry: dict[str, Any]) -> str:
    technique = _technique_label(entry)
    tool = entry.get("tool", "?")
    request = entry.get("request") or {}
    method = request.get("method", "?")
    url = _short_url(request.get("url"))
    response = entry.get("response") or {}
    rows = response.get("row_count", "?")
    pages = response.get("page_count", "?")
    outcome = entry.get("outcome", "?")
    when = entry.get("started_at_utc", "?")
    return (
        f"[graph_call] {technique} | {tool} | {method} {url} | "
        f"{rows} rows | {pages} page | outcome={outcome} @ {when}"
    )


def _format_token_event(entry: dict[str, Any]) -> str:
    technique = _technique_label(entry)
    tool = entry.get("tool", "?")
    response = entry.get("response") or {}
    status = response.get("status_code", "?")
    outcome = entry.get("outcome", "?")
    when = entry.get("started_at_utc", "?")
    return (
        f"[token_event] {technique} | {tool} | status={status} | "
        f"outcome={outcome} @ {when}"
    )


def _format_other(entry: dict[str, Any]) -> str:
    label = entry.get("kind") or entry.get("event") or "unknown"
    return f"[{label}] (unrecognised entry shape)"


def format_entry(entry: dict[str, Any]) -> str:
    category = _classify(entry)
    if category == "consent":
        return _format_consent(entry)
    if category == "graph_call":
        return _format_graph_call(entry)
    if category == "token_event":
        return _format_token_event(entry)
    return _format_other(entry)


def render(entries: list[dict[str, Any]]) -> list[str]:
    """Return the list of output lines, including the trailing summary."""
    lines: list[str] = []
    counts = {"graph_call": 0, "token_event": 0, "consent": 0, "other": 0}
    for entry in entries:
        if not isinstance(entry, dict):
            lines.append(f"[?] (non-object entry: {entry!r})")
            counts["other"] += 1
            continue
        counts[_classify(entry)] += 1
        lines.append(format_entry(entry))

    total = len(entries)
    summary = (
        f"--- {total} entries "
        f"({counts['graph_call']} graph_call, "
        f"{counts['token_event']} token_event, "
        f"{counts['consent']} consent"
    )
    if counts["other"]:
        summary += f", {counts['other']} other"
    summary += ") ---"
    lines.append(summary)
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Print a Rejewski replay-log file in human-readable form."
    )
    parser.add_argument(
        "path",
        help="Path to a replay-log JSON file, or '-' to read from stdin.",
    )
    args = parser.parse_args(argv)

    try:
        raw = _read_source(args.path)
    except FileNotFoundError:
        print(f"error: file not found: {args.path}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: could not read {args.path}: {exc}", file=sys.stderr)
        return 1

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"error: invalid JSON in {args.path}: {exc}", file=sys.stderr)
        return 1

    if isinstance(data, dict):
        entries = [data]
    elif isinstance(data, list):
        entries = data
    else:
        print(
            f"error: expected a JSON object or array, got {type(data).__name__}",
            file=sys.stderr,
        )
        return 1

    for line in render(entries):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())

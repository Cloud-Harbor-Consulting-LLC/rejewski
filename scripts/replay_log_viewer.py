#!/usr/bin/env python3
"""
Rejewski replay-log viewer (v0.2)

Reads any Rejewski replay-log file and renders it in a human-readable form.
Two output formats:

  * --format text (default) — compact one-line-per-entry output to stdout,
    unchanged from v0.1.
  * --format html — a self-contained HTML report written to --output FILE
    (required for HTML): run-metadata header, consent section, graph-calls
    table, token-events table, and a summary footer. No external resources,
    no JavaScript — openable in any browser offline.

Pure local file reader — no Microsoft Graph calls, no network, no schema
validation.

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
    python scripts/replay_log_viewer.py --format html --output run.html <path>
"""

from __future__ import annotations

import argparse
import json
import sys
from html import escape
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


_HTML_STYLE = """
body       { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
             font-size: 14px; color: #212529; margin: 2em auto; max-width: 960px;
             padding: 0 1em; }
table      { border-collapse: collapse; width: 100%; margin-bottom: 1.5em; }
th         { background: #f8f9fa; text-align: left; padding: 8px 10px;
             border-bottom: 2px solid #dee2e6; font-weight: 600; }
td         { padding: 7px 10px; border-bottom: 1px solid #dee2e6; vertical-align: top; }
tr:nth-child(even) td { background: #f8f9fa; }
code       { font-family: "SFMono-Regular", Consolas, monospace; font-size: 0.88em; }
h1         { font-size: 1.3em; margin-bottom: 0.25em; }
h2         { font-size: 1em; font-weight: 600; margin: 1.5em 0 0.5em;
             text-transform: uppercase; letter-spacing: 0.05em; color: #6c757d; }
.meta      { color: #6c757d; font-size: 0.9em; margin-bottom: 1em; }
.consent   { padding: 0.75em 1em; border-left: 4px solid #ccc;
             margin-bottom: 0.75em; background: #f8f9fa; }
.consent.granted { border-left-color: #28a745; }
.consent.declined { border-left-color: #dc3545; }
footer     { margin-top: 2em; padding-top: 1em; border-top: 1px solid #dee2e6;
             color: #6c757d; font-size: 0.9em; }
.badge-success  { background: #d4edda; color: #155724; padding: 2px 8px; border-radius: 3px; font-size: 0.85em; }
.badge-error    { background: #f8d7da; color: #721c24; padding: 2px 8px; border-radius: 3px; font-size: 0.85em; }
.badge-other    { background: #e2e3e5; color: #383d41; padding: 2px 8px; border-radius: 3px; font-size: 0.85em; }
""".strip()


def _esc(value: Any) -> str:
    """HTML-escape any value (defence in depth; the source is a trusted local
    file, but escaping keeps a stray '<' in a name or URL from breaking layout)."""
    return escape(str(value), quote=True)


def _first_key(entries: list[dict[str, Any]], key: str) -> Any:
    """First truthy value of `key` across all entries, or None."""
    for entry in entries:
        if isinstance(entry, dict) and entry.get(key):
            return entry[key]
    return None


def _short_time(ts: Any) -> str:
    """Time portion of an ISO timestamp: 2026-07-18T16:31:35Z -> 16:31:35 UTC."""
    if not isinstance(ts, str) or "T" not in ts:
        return "?"
    return f"{ts.split('T', 1)[1].rstrip('Z')} UTC"


def _outcome_badge(outcome: Any) -> str:
    """Coloured outcome badge: success/row_cap_hit -> green, error -> red, else grey."""
    if outcome in ("success", "row_cap_hit"):
        cls = "badge-success"
    elif outcome == "error":
        cls = "badge-error"
    else:
        cls = "badge-other"
    return f'<span class="{cls}">{_esc(outcome)}</span>'


def _run_metadata(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Extract run-level header fields from the entry list. Operator prefers a
    UPN (actor_upn / operator_upn) over the raw operator_object_id so the header
    reads as a person, not a GUID."""
    tenant_raw = _first_key(entries, "tenant_id")
    when = (
        _first_key(entries, "started_at_utc")
        or _first_key(entries, "confirmed_at")
        or _first_key(entries, "prompt_emitted_at")
        or _first_key(entries, "timestamp_utc")
    )
    date = (
        when.split("T", 1)[0]
        if isinstance(when, str) and "T" in when
        else (when or "—")
    )
    return {
        "run_id": _first_key(entries, "run_id") or "—",
        "tenant": _short_tenant(tenant_raw) if tenant_raw else "—",
        "operator": (
            _first_key(entries, "actor_upn")
            or _first_key(entries, "operator_upn")
            or _first_key(entries, "operator_object_id")
            or "—"
        ),
        "date": date,
        "count": len(entries),
    }


def render_html(entries: list[dict[str, Any]]) -> str:
    """Render the replay log as a complete, self-contained HTML5 document."""
    meta = _run_metadata(entries)
    counts = {"graph_call": 0, "token_event": 0, "consent": 0, "other": 0}
    consent_entries: list[dict[str, Any]] = []
    graph_entries: list[dict[str, Any]] = []
    token_entries: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            counts["other"] += 1
            continue
        category = _classify(entry)
        counts[category] += 1
        if category == "consent":
            consent_entries.append(entry)
        elif category == "graph_call":
            graph_entries.append(entry)
        elif category == "token_event":
            token_entries.append(entry)

    p: list[str] = []
    p.append("<!DOCTYPE html>")
    p.append('<html lang="en">')
    p.append("<head>")
    p.append('<meta charset="utf-8">')
    p.append(f"<title>Rejewski Run Report — {_esc(meta['run_id'])}</title>")
    p.append(f"<style>\n{_HTML_STYLE}\n</style>")
    p.append("</head>")
    p.append("<body>")

    # Header
    p.append("<header>")
    p.append("<h1>Rejewski Run Report</h1>")
    p.append(
        '<p class="meta">'
        f"Run: {_esc(meta['run_id'])} · Tenant: {_esc(meta['tenant'])} · "
        f"Operator: {_esc(meta['operator'])} · Date: {_esc(meta['date'])}"
        "</p>"
    )
    p.append(f'<p class="meta">{meta["count"]} entries</p>')
    p.append("</header>")

    # Consent
    p.append("<section>")
    p.append("<h2>Consent</h2>")
    if consent_entries:
        for c in consent_entries:
            label = str(c.get("event") or c.get("kind") or "consent")
            state = (
                "granted" if "granted" in label
                else "declined" if "declined" in label
                else ""
            )
            when = (
                c.get("confirmed_at")
                or c.get("timestamp_utc")
                or c.get("prompt_emitted_at")
                or "?"
            )
            techniques = c.get("techniques")
            tech_str = (
                ", ".join(techniques) if isinstance(techniques, list) else "—"
            )
            css_class = f"consent {state}".strip()
            p.append(f'<div class="{css_class}">')
            p.append(f"<strong>{_esc(label)}</strong> · <code>{_esc(when)}</code><br>")
            p.append(f"Techniques: {_esc(tech_str)}")
            p.append("</div>")
    else:
        p.append("<p>No consent record found in this log.</p>")
    p.append("</section>")

    # Graph calls
    p.append("<section>")
    p.append("<h2>Graph calls</h2>")
    if graph_entries:
        p.append("<table>")
        p.append(
            "<thead><tr><th>Time</th><th>Technique</th><th>Tool</th>"
            "<th>Endpoint</th><th>Rows</th><th>Outcome</th></tr></thead>"
        )
        p.append("<tbody>")
        for g in graph_entries:
            request = g.get("request") or {}
            response = g.get("response") or {}
            rows = response.get("row_count", "?")
            p.append("<tr>")
            p.append(f"<td><code>{_esc(_short_time(g.get('started_at_utc')))}</code></td>")
            p.append(f"<td>{_esc(_technique_label(g))}</td>")
            p.append(f"<td>{_esc(g.get('tool', '?'))}</td>")
            p.append(f"<td><code>{_esc(_short_url(request.get('url')))}</code></td>")
            p.append(f"<td>{_esc(rows)}</td>")
            p.append(f"<td>{_outcome_badge(g.get('outcome'))}</td>")
            p.append("</tr>")
        p.append("</tbody></table>")
    else:
        p.append("<p>No graph calls in this log.</p>")
    p.append("</section>")

    # Token events
    p.append("<section>")
    p.append("<h2>Token events</h2>")
    if token_entries:
        p.append("<table>")
        p.append(
            "<thead><tr><th>Time</th><th>Technique</th><th>Outcome</th></tr></thead>"
        )
        p.append("<tbody>")
        for t in token_entries:
            p.append("<tr>")
            p.append(f"<td><code>{_esc(_short_time(t.get('started_at_utc')))}</code></td>")
            p.append(f"<td>{_esc(_technique_label(t))}</td>")
            p.append(f"<td>{_outcome_badge(t.get('outcome'))}</td>")
            p.append("</tr>")
        p.append("</tbody></table>")
    else:
        p.append("<p>No token events in this log.</p>")
    p.append("</section>")

    # Footer summary
    footer = (
        f"{meta['count']} entries — {counts['graph_call']} graph_call · "
        f"{counts['token_event']} token_event · {counts['consent']} consent"
    )
    if counts["other"]:
        footer += f" · {counts['other']} other"
    p.append(f"<footer>{_esc(footer)}</footer>")

    p.append("</body>")
    p.append("</html>")
    return "\n".join(p) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Print a Rejewski replay-log file in human-readable form."
    )
    parser.add_argument(
        "path",
        help="Path to a replay-log JSON file, or '-' to read from stdin.",
    )
    parser.add_argument(
        "--format",
        choices=["text", "html"],
        default="text",
        help="Output format: text (default, stdout) or html (requires --output).",
    )
    parser.add_argument(
        "--output",
        default=None,
        help=(
            "Write output to FILE instead of stdout. "
            "Required when --format html is specified."
        ),
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

    if args.format == "html":
        if not args.output:
            print(
                "error: --output is required when --format is html",
                file=sys.stderr,
            )
            return 1
        html_content = render_html(entries)
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(html_content)
        except OSError as exc:
            print(f"error: could not write {args.output}: {exc}", file=sys.stderr)
            return 1
        return 0

    # Default text path (unchanged from v0.1).
    for line in render(entries):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())

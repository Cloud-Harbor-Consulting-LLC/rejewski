#!/usr/bin/env python3
"""
Rejewski Sprint 5 W17 — generate_html_report

Renders a self-contained HTML run report from a committed replay-log sample plus its
associated finding-triage and finding-to-control records. This formalizes the hand-built
one-off at docs/replay-report-r011.html into a reusable, script-driven template; that file
stays untouched as a historical reference.

Read-only / analysis-only: reads local JSON, writes one HTML file. No Microsoft Graph calls.
CLI shape mirrors scripts/finding_coverage_report.py (argparse, required --output).

Sections: header/meta (run id, tenant, date), consent summary (if the run carries a consent
record), graph-calls table, token-events table, findings summary (one severity badge per
finding per docs/finding-severity-rubric-v0.1.md v0.2), control mappings per finding, and an
ROI section rendered as an explicit **placeholder** — ROI computation is Sprint 5 Week 18
scope and is not computed here.

G-6: the report reuses only fields already present (and already scrubbed) in the source
records — the sandbox tenant is shown truncated to its first segment, the operator UPN is the
sandbox value already committed in the samples, and the operator object id from a consent
record is deliberately NOT rendered. No new unscrubbed operator/tenant field is introduced.

CLI:
    python scripts/generate_html_report.py \
        --replay-log samples/replay-log/R012.json \
        --finding-dir samples/finding-triage/ \
        --mapping-dir samples/finding-to-control/ \
        --output docs/reports/replay-report-R012.html
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FINDING_DIR = REPO_ROOT / "samples" / "finding-triage"
DEFAULT_MAPPING_DIR = REPO_ROOT / "samples" / "finding-to-control"

SEVERITY_LEVELS = ("informational", "low", "medium", "high", "critical")

ROI_PLACEHOLDER = "ROI scoring — Sprint 5 Week 18"

# Centralized stylesheet (single source of truth — not hand-copied per report). Reuses the
# badge/table/.consent styling from docs/replay-report-r011.html and adds severity badges and
# the ROI placeholder box.
CSS = """
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
.badge-success, .badge-error, .badge-other,
.badge-informational, .badge-low, .badge-medium, .badge-high, .badge-critical {
             padding: 2px 8px; border-radius: 3px; font-size: 0.85em; white-space: nowrap; }
.badge-success  { background: #d4edda; color: #155724; }
.badge-error    { background: #f8d7da; color: #721c24; }
.badge-other    { background: #e2e3e5; color: #383d41; }
.badge-informational { background: #e2e3e5; color: #383d41; }
.badge-low      { background: #d1ecf1; color: #0c5460; }
.badge-medium   { background: #fff3cd; color: #856404; }
.badge-high     { background: #f8d7da; color: #721c24; }
.badge-critical { background: #dc3545; color: #ffffff; }
.placeholder { padding: 0.75em 1em; border: 1px dashed #adb5bd; color: #6c757d;
             background: #f8f9fa; border-radius: 3px; }
.notes     { color: #495057; }
""".strip()


def _esc(value) -> str:
    return html.escape("" if value is None else str(value))


def _time_of(iso: Optional[str]) -> str:
    """HH:MM:SS UTC from an ISO8601 'YYYY-MM-DDThh:mm:ssZ' string."""
    if not iso or "T" not in iso:
        return _esc(iso)
    return _esc(iso.split("T", 1)[1].rstrip("Z") + " UTC")


def _severity_badge(severity: str) -> str:
    sev = (severity or "").lower()
    cls = f"badge-{sev}" if sev in SEVERITY_LEVELS else "badge-other"
    return f'<span class="{cls}">{_esc(severity)}</span>'


def _outcome_badge(outcome: str) -> str:
    cls = {"success": "badge-success", "error": "badge-error"}.get(outcome, "badge-other")
    return f'<span class="{cls}">{_esc(outcome)}</span>'


def load_replay_log(path: Path) -> dict:
    """Split a replay-log JSON array into consent records, token_events, and graph_calls."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    entries = payload if isinstance(payload, list) else [payload]
    consent, token_events, graph_calls = [], [], []
    for e in entries:
        if not isinstance(e, dict):
            continue
        if "event" in e and "schema_version" not in e:
            consent.append(e)
        elif e.get("kind") == "token_event":
            token_events.append(e)
        elif e.get("kind") == "graph_call":
            graph_calls.append(e)

    def _first(field):
        for e in entries:
            if isinstance(e, dict) and e.get(field):
                return e[field]
        return None

    run_id = _first("run_id")
    tenant_id = _first("tenant_id")
    actor_upn = _first("actor_upn")
    started = _first("started_at_utc") or (consent[0].get("confirmed_at") if consent else None)
    return {
        "run_id": run_id,
        "tenant_id": tenant_id,
        "actor_upn": actor_upn,
        "date": (started or "").split("T", 1)[0],
        "entry_count": len(entries),
        "consent": consent,
        "token_events": token_events,
        "graph_calls": graph_calls,
    }


def load_findings(finding_dir: Path, run_id: Optional[str]) -> list[dict]:
    records = []
    for path in sorted(finding_dir.glob("*.json")):
        try:
            rec = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if run_id is None or rec.get("run_id") == run_id:
            records.append(rec)
    return records


def load_mappings(mapping_dir: Path) -> dict[str, dict]:
    """mapping_id -> record, plus technique_id -> record (first match) for fallback."""
    by_id, by_technique = {}, {}
    for path in sorted(mapping_dir.glob("*.json")):
        try:
            rec = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        mid = rec.get("mapping_id")
        if mid:
            by_id[mid] = rec
        tid = (rec.get("finding") or {}).get("technique_id")
        by_technique.setdefault(tid, rec)
    return {"by_id": by_id, "by_technique": by_technique}


def _render_header(meta: dict) -> str:
    tenant = (meta.get("tenant_id") or "").split("-", 1)[0]  # G-6: first segment only
    line = " · ".join(
        p for p in [
            f"Run: {_esc(meta.get('run_id'))}",
            f"Tenant: {_esc(tenant)}" if tenant else "",
            f"Operator: {_esc(meta.get('actor_upn'))}" if meta.get("actor_upn") else "",
            f"Date: {_esc(meta.get('date'))}" if meta.get("date") else "",
        ] if p
    )
    return (
        "<header>\n<h1>Rejewski Run Report</h1>\n"
        f'<p class="meta">{line}</p>\n'
        f'<p class="meta">{meta["entry_count"]} entries</p>\n</header>'
    )


def _render_consent(consent: list[dict]) -> str:
    if not consent:
        return ""
    blocks = []
    for c in consent:
        event = c.get("event", "consent")
        state = "granted" if event.endswith("granted") else "declined" if event.endswith("declined") else ""
        techniques = ", ".join(c.get("techniques", []))
        blocks.append(
            f'<div class="consent {state}">\n'
            f"<strong>{_esc(event)}</strong> · <code>{_esc(c.get('confirmed_at'))}</code><br>\n"
            f"Techniques: {_esc(techniques)}\n</div>"
        )
    return "<section>\n<h2>Consent</h2>\n" + "\n".join(blocks) + "\n</section>"


def _render_graph_calls(calls: list[dict]) -> str:
    rows = []
    for c in calls:
        tech = c.get("technique") or {}
        tech_label = f"{tech.get('id', '')} {tech.get('name', '')}".strip()
        path = urlparse((c.get("request") or {}).get("url", "")).path or ""
        resp = c.get("response") or {}
        rows.append(
            "<tr>\n"
            f"<td><code>{_time_of(c.get('started_at_utc'))}</code></td>\n"
            f"<td>{_esc(tech_label)}</td>\n"
            f"<td>{_esc(c.get('tool'))}</td>\n"
            f"<td><code>{_esc(path)}</code></td>\n"
            f"<td>{_esc(resp.get('row_count'))}</td>\n"
            f"<td>{_outcome_badge(c.get('outcome'))}</td>\n</tr>"
        )
    body = "\n".join(rows) if rows else '<tr><td colspan="6">No graph calls.</td></tr>'
    return (
        "<section>\n<h2>Graph calls</h2>\n<table>\n"
        "<thead><tr><th>Time</th><th>Technique</th><th>Tool</th><th>Endpoint</th>"
        "<th>Rows</th><th>Outcome</th></tr></thead>\n<tbody>\n" + body + "\n</tbody>\n</table>\n</section>"
    )


def _render_token_events(events: list[dict]) -> str:
    if not events:
        return ""
    rows = []
    for e in events:
        tech = e.get("technique") or {}
        tech_label = f"{tech.get('id', '')} {tech.get('name', '')}".strip()
        rows.append(
            "<tr>\n"
            f"<td><code>{_time_of(e.get('started_at_utc'))}</code></td>\n"
            f"<td>{_esc(tech_label)}</td>\n"
            f"<td>{_outcome_badge(e.get('outcome'))}</td>\n</tr>"
        )
    return (
        "<section>\n<h2>Token events</h2>\n<table>\n"
        "<thead><tr><th>Time</th><th>Technique</th><th>Outcome</th></tr></thead>\n<tbody>\n"
        + "\n".join(rows) + "\n</tbody>\n</table>\n</section>"
    )


def _render_findings(findings: list[dict]) -> str:
    rows = []
    for f in findings:
        rows.append(
            "<tr>\n"
            f"<td>{_esc(f.get('technique_id'))} {_esc(f.get('technique_name'))}</td>\n"
            f"<td>{_severity_badge(f.get('severity'))}</td>\n"
            f"<td>{_esc(f.get('confidence'))}</td>\n"
            f"<td>{_esc(f.get('triage_status'))}</td>\n"
            f'<td class="notes">{_esc(f.get("notes"))}</td>\n</tr>'
        )
    body = "\n".join(rows) if rows else '<tr><td colspan="5">No triaged findings for this run.</td></tr>'
    return (
        "<section>\n<h2>Findings</h2>\n<table>\n"
        "<thead><tr><th>Technique</th><th>Severity</th><th>Confidence</th>"
        "<th>Triage</th><th>Notes</th></tr></thead>\n<tbody>\n" + body + "\n</tbody>\n</table>\n</section>"
    )


def _render_control_mappings(findings: list[dict], mappings: dict) -> str:
    rows = []
    for f in findings:
        mid = f.get("control_mapping_id")
        rec = mappings["by_id"].get(mid) or mappings["by_technique"].get(f.get("technique_id"))
        if not rec:
            rows.append(
                "<tr>\n"
                f"<td>{_esc(f.get('technique_id'))}</td>\n"
                '<td colspan="4"><em>No control mapping on file.</em></td>\n</tr>'
            )
            continue
        ctrl = rec.get("control") or {}
        tenets = ", ".join(ctrl.get("nist_800_207_tenets", []))
        ref = ctrl.get("reference_url", "")
        ref_html = f'<a href="{_esc(ref)}">ref</a>' if ref else ""
        rows.append(
            "<tr>\n"
            f"<td>{_esc(f.get('technique_id'))}</td>\n"
            f"<td>{_esc(ctrl.get('control_id'))}</td>\n"
            f"<td>{_esc(ctrl.get('control_family'))} / {_esc(ctrl.get('control_type'))}</td>\n"
            f"<td>{_esc(ctrl.get('microsoft_pillar'))}{(' · ' + _esc(tenets)) if tenets else ''}</td>\n"
            f"<td>{ref_html}</td>\n</tr>"
        )
    body = "\n".join(rows) if rows else '<tr><td colspan="5">No findings to map.</td></tr>'
    return (
        "<section>\n<h2>Control mappings</h2>\n<table>\n"
        "<thead><tr><th>Technique</th><th>Control</th><th>Family / Type</th>"
        "<th>Pillar · NIST 800-207</th><th>Ref</th></tr></thead>\n<tbody>\n"
        + body + "\n</tbody>\n</table>\n</section>"
    )


def _render_roi_placeholder() -> str:
    return (
        "<section>\n<h2>ROI</h2>\n"
        f'<div class="placeholder"><strong>{_esc(ROI_PLACEHOLDER)}.</strong> '
        "This section is a scaffold; ROI is not computed in this template — ROI scoring is "
        "Sprint 5 Week 18 (S5 W18 Tue) scope.</div>\n</section>"
    )


def render_report(meta: dict, findings: list[dict], mappings: dict) -> str:
    ge, te = len(meta["graph_calls"]), len(meta["token_events"])
    ce = len(meta["consent"])
    footer = (
        f"{meta['entry_count']} entries — {ge} graph_call · {te} token_event · {ce} consent · "
        f"{len(findings)} triaged finding(s)"
    )
    parts = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        f"<title>Rejewski Run Report — {_esc(meta.get('run_id'))}</title>",
        f"<style>\n{CSS}\n</style>",
        "</head>",
        "<body>",
        _render_header(meta),
        _render_consent(meta["consent"]),
        _render_graph_calls(meta["graph_calls"]),
        _render_token_events(meta["token_events"]),
        _render_findings(findings),
        _render_control_mappings(findings, mappings),
        _render_roi_placeholder(),
        f"<footer>{_esc(footer)}</footer>",
        "</body>",
        "</html>",
        "",
    ]
    return "\n".join(p for p in parts if p != "")


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="generate_html_report.py",
        description="Render an HTML run report from a replay-log sample and its finding records.",
    )
    p.add_argument("--replay-log", required=True, help="Path to a replay-log JSON array (e.g. samples/replay-log/R012.json).")
    p.add_argument("--finding-dir", default=str(DEFAULT_FINDING_DIR), help="Directory of finding-triage records.")
    p.add_argument("--mapping-dir", default=str(DEFAULT_MAPPING_DIR), help="Directory of finding-to-control records.")
    p.add_argument("--output", required=True, help="Path to write the HTML report.")
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    replay_path = Path(args.replay_log)
    if not replay_path.is_file():
        print(f"error: replay-log not found: {replay_path}", file=sys.stderr)
        return 2

    meta = load_replay_log(replay_path)
    findings = load_findings(Path(args.finding_dir), meta["run_id"])
    mappings = load_mappings(Path(args.mapping_dir))
    html_out = render_report(meta, findings, mappings)

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html_out, encoding="utf-8")
    print(
        f"wrote {output}: run {meta['run_id']} — {len(meta['graph_calls'])} graph_call(s), "
        f"{len(findings)} finding(s)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

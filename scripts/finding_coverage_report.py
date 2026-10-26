#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Rejewski Sprint 4 W14 — finding_coverage_report

Control-mapping coverage report. Reads the implemented techniques from
docs/attck-coverage.md and the finding-to-control records from
samples/finding-to-control/, then emits a Markdown report showing which implemented
techniques have a finding-to-control mapping (covered) and which do not (gap).

A technique is *covered* when at least one finding-to-control record carries a
matching finding.technique_id; otherwise it is a *gap*. Coverage % is
(covered / total implemented) * 100, rounded to one decimal.

The report's "Coverage history" table accumulates: when the output file already
exists, its prior history rows are preserved and one new row is appended. Every other
section is regenerated from current state.

This is a read-only analysis tool: it never modifies a finding-to-control record and
issues no Graph calls. Only the report file at --output is written.

CLI:
    python scripts/finding_coverage_report.py \
        --attck-coverage docs/attck-coverage.md \
        --mapping-dir samples/finding-to-control/ \
        --output docs/finding-coverage-report.md
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# A technique-table row: | T1078.004 | Name | Tactic | Status | Module | Script(s) |
_ROW_RE = re.compile(r"^\|\s*(T\d[\w.]*)\s*\|(.+)$")
_VERSION_RE = re.compile(r"Version:\s*v?(\d+\.\d+)", re.IGNORECASE)
# A prior Coverage-history data row: | 2026-08-15 | 13 | 9 | 69.2% |
_HISTORY_RE = re.compile(r"^\|\s*(\d{4}-\d{2}-\d{2})\s*\|\s*\d+\s*\|\s*\d+\s*\|\s*[\d.]+%\s*\|")


def parse_attck_coverage(path: Path) -> tuple[list[dict], Optional[str]]:
    """Extract implemented-technique rows and the doc version from attck-coverage.md.

    Returns (implemented, version) where implemented is a list of
    {technique_id, name, status} for rows whose Status column contains "Implemented".
    """
    text = path.read_text(encoding="utf-8")

    version = None
    m = _VERSION_RE.search(text)
    if m:
        version = m.group(1)

    implemented: list[dict] = []
    seen: set[str] = set()
    for line in text.splitlines():
        m = _ROW_RE.match(line.strip())
        if not m:
            continue
        technique_id = m.group(1)
        cells = [c.strip() for c in m.group(2).split("|")]
        # cells after the id: [name, tactic, status, module, scripts, (trailing "")]
        if len(cells) < 3:
            continue
        name, _tactic, status = cells[0], cells[1], cells[2]
        if "Implemented" not in status:
            continue
        if technique_id in seen:
            continue
        seen.add(technique_id)
        implemented.append({"technique_id": technique_id, "name": name, "status": status})
    return implemented, version


def load_mappings(mapping_dir: Path) -> dict[str, list[str]]:
    """Map technique_id -> sorted list of mapping-record filenames that cover it."""
    covered: dict[str, list[str]] = {}
    for path in sorted(mapping_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            print(f"warning: skipping {path.name}: invalid JSON ({exc})", file=sys.stderr)
            continue
        technique_id = (data.get("finding") or {}).get("technique_id")
        if not technique_id:
            print(
                f"warning: skipping {path.name}: no finding.technique_id",
                file=sys.stderr,
            )
            continue
        covered.setdefault(technique_id, []).append(path.name)
    for tid in covered:
        covered[tid] = sorted(covered[tid])
    return covered


def _extract_history_rows(existing: str) -> list[str]:
    """Pull prior Coverage-history data rows from an existing report file."""
    rows: list[str] = []
    for line in existing.splitlines():
        if _HISTORY_RE.match(line.strip()):
            rows.append(line.strip())
    return rows


def build_report(
    implemented: list[dict],
    version: Optional[str],
    covered_map: dict[str, list[str]],
    attck_path: Path,
    prior_history: list[str],
    now: Optional[datetime] = None,
) -> str:
    now = now or datetime.now(timezone.utc)
    generated = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    today = now.strftime("%Y-%m-%d")

    covered = [t for t in implemented if t["technique_id"] in covered_map]
    gap = [t for t in implemented if t["technique_id"] not in covered_map]
    total = len(implemented)
    cov_n, gap_n = len(covered), len(gap)
    cov_pct = round(cov_n / total * 100, 1) if total else 0.0
    gap_pct = round(gap_n / total * 100, 1) if total else 0.0

    lines: list[str] = []
    lines.append("# Rejewski Finding-to-Control Coverage Report")
    lines.append("")
    lines.append(f"- Generated: {generated}")
    lines.append(f"- ATT&CK coverage source: {attck_path.as_posix()} (v{version or 'unknown'})")
    lines.append(f"- Implemented techniques: {total}")
    lines.append(f"- Covered: {cov_n} ({cov_pct}%)")
    lines.append(f"- Gap: {gap_n} ({gap_pct}%)")
    lines.append("")
    lines.append("## Covered techniques")
    lines.append("")
    lines.append("| Technique | Name | Mapping record |")
    lines.append("|---|---|---|")
    for t in covered:
        record = covered_map[t["technique_id"]][0]
        lines.append(f"| {t['technique_id']} | {t['name']} | {record} |")
    lines.append("")
    lines.append("## Gap techniques (no control mapping)")
    lines.append("")
    lines.append("| Technique | Name | Status | Notes |")
    lines.append("|---|---|---|---|")
    for t in gap:
        lines.append(
            f"| {t['technique_id']} | {t['name']} | {t['status']} | No finding-to-control mapping record |"
        )
    lines.append("")
    lines.append("## Coverage history")
    lines.append("")
    lines.append("| Report date | Implemented | Covered | Coverage % |")
    lines.append("|---|---|---|---|")
    for row in prior_history:
        lines.append(row)
    lines.append(f"| {today} | {total} | {cov_n} | {cov_pct}% |")
    lines.append("")
    return "\n".join(lines)


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="finding_coverage_report.py",
        description="Report finding-to-control coverage over implemented ATT&CK techniques.",
    )
    p.add_argument(
        "--attck-coverage",
        required=True,
        help="Path to docs/attck-coverage.md.",
    )
    p.add_argument(
        "--mapping-dir",
        required=True,
        help="Directory of finding-to-control JSON records.",
    )
    p.add_argument(
        "--output",
        required=True,
        help="Path to the Markdown report to write (history rows are preserved).",
    )
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    attck_path = Path(args.attck_coverage)
    mapping_dir = Path(args.mapping_dir)
    output = Path(args.output)

    if not attck_path.is_file():
        print(f"error: attck-coverage file not found: {attck_path}", file=sys.stderr)
        return 2
    if not mapping_dir.is_dir():
        print(f"error: mapping-dir not found: {mapping_dir}", file=sys.stderr)
        return 2

    implemented, version = parse_attck_coverage(attck_path)
    if not implemented:
        print(f"error: no implemented techniques parsed from {attck_path}", file=sys.stderr)
        return 2

    covered_map = load_mappings(mapping_dir)

    prior_history: list[str] = []
    if output.exists():
        prior_history = _extract_history_rows(output.read_text(encoding="utf-8"))

    report = build_report(
        implemented=implemented,
        version=version,
        covered_map=covered_map,
        attck_path=attck_path,
        prior_history=prior_history,
    )
    output.write_text(report, encoding="utf-8")

    covered_n = sum(1 for t in implemented if t["technique_id"] in covered_map)
    print(
        f"wrote {output}: {covered_n}/{len(implemented)} implemented techniques covered",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Tests for scripts/finding_coverage_report.py (Sprint 4 W14 coverage report).

Read-only coverage report over implemented ATT&CK techniques and
finding-to-control records. Covers full coverage, gap detection,
Implemented-only parsing, multi-mapping dedup, missing-dir and missing-file
errors, coverage-history append, and version extraction. Each test builds an
isolated attck-coverage.md and mapping dir under tmp_path.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import finding_coverage_report as report  # noqa: E402


ATTCK_HEADER = "# Rejewski ATT&CK Coverage Map\n\n- Version: v0.8\n- Last updated: 2026-08-15\n\n"
TABLE_HEADER = (
    "| Technique | Name | Tactic | Status | Module | Script(s) |\n"
    "|-----------|------|--------|--------|--------|-----------|\n"
)


def _attck(tmp_path: Path, rows: list[str], header: str = ATTCK_HEADER) -> Path:
    """Write an attck-coverage.md with the given technique-table rows."""
    path = tmp_path / "attck-coverage.md"
    path.write_text(header + TABLE_HEADER + "\n".join(rows) + "\n", encoding="utf-8")
    return path


def _mapping(dir_path: Path, name: str, technique_id: str) -> Path:
    rec = {
        "mapping_id": name.replace(".json", ""),
        "finding": {"technique_id": technique_id, "technique_name": technique_id + " name"},
        "control": {"control_id": "CA-TEST-001"},
    }
    path = dir_path / name
    path.write_text(json.dumps(rec), encoding="utf-8")
    return path


def _row(tid: str, name: str, status: str) -> str:
    return f"| {tid} | {name} | Discovery | {status} | docs/techniques/{tid}.md | scripts/x.py |"


# 1 — all techniques covered: 100%, gap list empty
def test_full_coverage(tmp_path, capsys):
    attck = _attck(tmp_path, [
        _row("T1078.004", "Valid Accounts", "Implemented — Sprint 1"),
        _row("T1087.004", "Account Discovery", "Implemented — Sprint 1"),
    ])
    mdir = tmp_path / "mappings"
    mdir.mkdir()
    _mapping(mdir, "m1.json", "T1078.004")
    _mapping(mdir, "m2.json", "T1087.004")
    out = tmp_path / "report.md"

    rc = report.main(["--attck-coverage", str(attck), "--mapping-dir", str(mdir), "--output", str(out)])
    assert rc == 0
    text = out.read_text(encoding="utf-8")
    assert "- Covered: 2 (100.0%)" in text
    assert "- Gap: 0 (0.0%)" in text
    # gap section present but its data table empty
    gap_section = text.split("## Gap techniques")[1].split("## Coverage history")[0]
    assert "T1078.004" not in gap_section


# 2 — one technique missing mapping: gap contains it, coverage % correct
def test_one_gap(tmp_path):
    attck = _attck(tmp_path, [
        _row("T1078.004", "Valid Accounts", "Implemented — Sprint 1"),
        _row("T1114.002", "Email Collection", "Implemented — Sprint 4 W13"),
    ])
    mdir = tmp_path / "mappings"
    mdir.mkdir()
    _mapping(mdir, "m1.json", "T1078.004")
    out = tmp_path / "report.md"

    rc = report.main(["--attck-coverage", str(attck), "--mapping-dir", str(mdir), "--output", str(out)])
    assert rc == 0
    text = out.read_text(encoding="utf-8")
    assert "- Covered: 1 (50.0%)" in text
    assert "- Gap: 1 (50.0%)" in text
    gap_section = text.split("## Gap techniques")[1]
    assert "T1114.002" in gap_section


# 3 — only Implemented rows counted, not Catalogued
def test_catalogued_excluded(tmp_path):
    attck = _attck(tmp_path, [
        _row("T1078.004", "Valid Accounts", "Implemented — Sprint 1"),
        _row("T1528", "Steal App Token", "Catalogued — Sprint 4"),
    ])
    mdir = tmp_path / "mappings"
    mdir.mkdir()
    _mapping(mdir, "m1.json", "T1078.004")
    out = tmp_path / "report.md"

    rc = report.main(["--attck-coverage", str(attck), "--mapping-dir", str(mdir), "--output", str(out)])
    assert rc == 0
    text = out.read_text(encoding="utf-8")
    assert "- Implemented techniques: 1" in text
    assert "T1528" not in text


# 4 — multiple mappings for same technique: counted covered once
def test_multi_mapping_dedup(tmp_path):
    attck = _attck(tmp_path, [
        _row("T1078.004", "Valid Accounts", "Implemented — Sprint 1"),
    ])
    mdir = tmp_path / "mappings"
    mdir.mkdir()
    _mapping(mdir, "m1.json", "T1078.004")
    _mapping(mdir, "m2.json", "T1078.004")
    out = tmp_path / "report.md"

    rc = report.main(["--attck-coverage", str(attck), "--mapping-dir", str(mdir), "--output", str(out)])
    assert rc == 0
    text = out.read_text(encoding="utf-8")
    assert "- Implemented techniques: 1" in text
    assert "- Covered: 1 (100.0%)" in text


# 5 — missing mapping-dir: non-zero exit, clear error
def test_missing_mapping_dir(tmp_path, capsys):
    attck = _attck(tmp_path, [_row("T1078.004", "Valid Accounts", "Implemented — Sprint 1")])
    out = tmp_path / "report.md"

    rc = report.main([
        "--attck-coverage", str(attck),
        "--mapping-dir", str(tmp_path / "does-not-exist"),
        "--output", str(out),
    ])
    assert rc != 0
    assert "mapping-dir not found" in capsys.readouterr().err


# 6 — attck-coverage not found: non-zero exit, clear error
def test_missing_attck_file(tmp_path, capsys):
    mdir = tmp_path / "mappings"
    mdir.mkdir()
    out = tmp_path / "report.md"

    rc = report.main([
        "--attck-coverage", str(tmp_path / "nope.md"),
        "--mapping-dir", str(mdir),
        "--output", str(out),
    ])
    assert rc != 0
    assert "attck-coverage file not found" in capsys.readouterr().err


# 7 — coverage-history row appended when output already exists
def test_history_appended(tmp_path):
    attck = _attck(tmp_path, [_row("T1078.004", "Valid Accounts", "Implemented — Sprint 1")])
    mdir = tmp_path / "mappings"
    mdir.mkdir()
    _mapping(mdir, "m1.json", "T1078.004")
    out = tmp_path / "report.md"
    args = ["--attck-coverage", str(attck), "--mapping-dir", str(mdir), "--output", str(out)]

    assert report.main(args) == 0
    first = out.read_text(encoding="utf-8")
    n_first = first.split("## Coverage history")[1].count("| 20")

    assert report.main(args) == 0
    second = out.read_text(encoding="utf-8")
    n_second = second.split("## Coverage history")[1].count("| 20")
    assert n_second == n_first + 1


# 8 — version extracted from attck-coverage header line
def test_version_extraction(tmp_path):
    attck = _attck(
        tmp_path,
        [_row("T1078.004", "Valid Accounts", "Implemented — Sprint 1")],
        header="# Map\n\n- Version: v1.2\n- Last updated: 2026-08-15\n\n",
    )
    mdir = tmp_path / "mappings"
    mdir.mkdir()
    _mapping(mdir, "m1.json", "T1078.004")
    out = tmp_path / "report.md"

    rc = report.main(["--attck-coverage", str(attck), "--mapping-dir", str(mdir), "--output", str(out)])
    assert rc == 0
    assert "(v1.2)" in out.read_text(encoding="utf-8")

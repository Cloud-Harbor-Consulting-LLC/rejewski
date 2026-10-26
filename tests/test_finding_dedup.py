# SPDX-License-Identifier: MIT
"""Tests for scripts/finding_dedup.py (Sprint 4 W14 finding dedup classifier).

Read-only classifier over finding-triage records. Covers new_technique /
recurring / variant classification, severity-diff detection, prior-run-only
tracking, missing run-id and empty-directory errors, invalid-JSON skip, and
summary-count correctness. Each test builds an isolated corpus under tmp_path.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import finding_dedup as dedup  # noqa: E402


def _write(dir_path: Path, name: str, **fields) -> Path:
    """Write a minimal finding-triage record to dir_path/name."""
    rec = {
        "finding_id": fields.get("finding_id", name.replace(".json", "")),
        "technique_id": fields["technique_id"],
        "technique_name": fields.get("technique_name", fields["technique_id"] + " name"),
        "run_id": fields["run_id"],
        "severity": fields.get("severity", "medium"),
        "confidence": fields.get("confidence", "high"),
    }
    path = dir_path / name
    path.write_text(json.dumps(rec), encoding="utf-8")
    return path


def _run(argv):
    """Invoke main(argv), returning the exit code."""
    return dedup.main(argv)


# 1 — single-run corpus: all findings classified new_technique
def test_single_run_all_new(tmp_path, capsys):
    _write(tmp_path, "a.json", technique_id="T1078.004", run_id="R011")
    _write(tmp_path, "b.json", technique_id="T1087.004", run_id="R011")

    rc = _run(["--finding-dir", str(tmp_path), "--run-id", "R011"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["summary"]["new_technique"] == 2
    assert out["summary"]["recurring"] == 0
    assert all(f["classification"] == "new_technique" for f in out["findings"])


# 2 — same technique in two runs: recurring
def test_recurring_across_runs(tmp_path, capsys):
    _write(tmp_path, "r010.json", technique_id="T1087.004", run_id="R010", severity="medium")
    _write(tmp_path, "r011.json", technique_id="T1087.004", run_id="R011", severity="medium")

    rc = _run(["--finding-dir", str(tmp_path), "--run-id", "R011"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["summary"]["recurring"] == 1
    assert out["summary"]["variant"] == 0
    entry = out["findings"][0]
    assert entry["classification"] == "recurring"
    assert entry["diff"]["severity"]["changed"] is False


# 3 — severity change between runs: variant, diff noted
def test_variant_on_severity_change(tmp_path, capsys):
    _write(tmp_path, "r010.json", technique_id="T1550.001", run_id="R010", severity="high")
    _write(tmp_path, "r011.json", technique_id="T1550.001", run_id="R011", severity="critical")

    rc = _run(["--finding-dir", str(tmp_path), "--run-id", "R011"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["summary"]["variant"] == 1
    assert out["summary"]["recurring"] == 0
    entry = out["findings"][0]
    assert entry["classification"] == "variant"
    assert entry["diff"]["severity"]["changed"] is True
    assert entry["diff"]["severity"]["target"] == "critical"
    assert entry["diff"]["severity"]["prior"] == ["high"]


# 4 — technique in prior run only: listed in prior-run-not-in-target
def test_prior_run_only(tmp_path, capsys):
    _write(tmp_path, "r010.json", technique_id="T1069.003", run_id="R010")
    _write(tmp_path, "r011.json", technique_id="T1087.004", run_id="R011")

    rc = _run(["--finding-dir", str(tmp_path), "--run-id", "R011"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    prior_only = out["techniques_in_prior_runs_not_in_target"]
    assert [p["technique_id"] for p in prior_only] == ["T1069.003"]
    assert out["summary"]["prior_run_only"] == 1
    # the R011 technique is still classified new_technique
    assert out["summary"]["new_technique"] == 1


# 5 — run-id not found: non-zero exit with clear error
def test_run_id_not_found(tmp_path, capsys):
    _write(tmp_path, "r011.json", technique_id="T1078.004", run_id="R011")

    rc = _run(["--finding-dir", str(tmp_path), "--run-id", "R999"])
    assert rc != 0
    err = capsys.readouterr().err
    assert "R999" in err and "not found" in err


# 6 — empty finding-dir: non-zero exit with clear error
def test_empty_dir(tmp_path, capsys):
    rc = _run(["--finding-dir", str(tmp_path), "--run-id", "R011"])
    assert rc != 0
    err = capsys.readouterr().err
    assert "no valid finding-triage records" in err


# 7 — invalid JSON: skipped with stderr warning, processing continues
def test_invalid_json_skipped(tmp_path, capsys):
    _write(tmp_path, "good.json", technique_id="T1078.004", run_id="R011")
    (tmp_path / "bad.json").write_text("{ not valid json", encoding="utf-8")

    rc = _run(["--finding-dir", str(tmp_path), "--run-id", "R011"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "bad.json" in captured.err and "invalid JSON" in captured.err
    out = json.loads(captured.out)
    assert out["summary"]["new_technique"] == 1


# 8 — summary counts match detail-list lengths
def test_summary_matches_details(tmp_path, capsys):
    _write(tmp_path, "r010-a.json", technique_id="T1087.004", run_id="R010", severity="medium")
    _write(tmp_path, "r011-a.json", technique_id="T1087.004", run_id="R011", severity="medium")
    _write(tmp_path, "r011-b.json", technique_id="T1078.004", run_id="R011")
    _write(tmp_path, "r011-c.json", technique_id="T1550.001", run_id="R011", severity="high")
    _write(tmp_path, "r010-c.json", technique_id="T1550.001", run_id="R010", severity="low")
    _write(tmp_path, "r010-d.json", technique_id="T1069.003", run_id="R010")

    rc = _run(["--finding-dir", str(tmp_path), "--run-id", "R011"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    s = out["summary"]
    classified = s["new_technique"] + s["recurring"] + s["variant"]
    assert classified == len(out["findings"])
    assert s["prior_run_only"] == len(out["techniques_in_prior_runs_not_in_target"])
    # spot-check: T1087.004 recurring (medium==medium), T1550.001 variant (high vs low),
    # T1078.004 new, T1069.003 prior-run-only
    by_id = {f["technique_id"]: f["classification"] for f in out["findings"]}
    assert by_id["T1087.004"] == "recurring"
    assert by_id["T1550.001"] == "variant"
    assert by_id["T1078.004"] == "new_technique"
    assert [p["technique_id"] for p in out["techniques_in_prior_runs_not_in_target"]] == ["T1069.003"]

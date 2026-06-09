"""Tests for scripts/consolidate_run.py (B022 + B023).

B022: the consolidator must read *every* file in replay-logs/, not the last
three — a 3-tool run produces 6 files (token_event + graph_call per tool), so
all 6 matching entries must reach the output.

B023: cache_path on every token_event must be redacted to "<redacted>" before
it is written under samples/, regardless of the source value.
"""

import json
import shutil
from pathlib import Path

import pytest

import consolidate_run

# The committed fixture dir holds exactly one realistic 3-tool run (R900):
# 6 files = 2 entries per tool (token_event + graph_call) x 3 tools.
FIXTURE_RUN = Path(__file__).resolve().parent / "fixtures" / "consolidate-run"
RUN_ID = "R900"
EXPECTED_ENTRY_IDS = {
    "11111111-1111-4111-8111-111111111111",
    "11111111-1111-4111-8111-1111111111aa",
    "22222222-2222-4222-8222-222222222222",
    "22222222-2222-4222-8222-2222222222aa",
    "33333333-3333-4333-8333-333333333333",
    "33333333-3333-4333-8333-3333333333aa",
}


def _point_at(monkeypatch, *, replay_dir: Path, samples_dir: Path) -> None:
    monkeypatch.setattr(consolidate_run, "REPLAY_LOGS_DIR", replay_dir)
    monkeypatch.setattr(consolidate_run, "SAMPLES_DIR", samples_dir)


def _read_output(samples_dir: Path) -> list[dict]:
    out_path = samples_dir / f"{RUN_ID}.json"
    return json.loads(out_path.read_text(encoding="utf-8"))


def test_six_file_run_yields_all_six_entries(monkeypatch, tmp_path):
    # Sanity: the fixture really is 6 files, mirroring a 3-tool run.
    assert len(list(FIXTURE_RUN.glob("*.json"))) == 6

    _point_at(monkeypatch, replay_dir=FIXTURE_RUN, samples_dir=tmp_path)
    rc = consolidate_run.main(["--run-id", RUN_ID])
    assert rc == 0

    entries = _read_output(tmp_path)
    assert len(entries) == 6, "all 6 files' entries must appear — not a [-3:] slice"
    assert {e["entry_id"] for e in entries} == EXPECTED_ENTRY_IDS


def test_cache_path_is_redacted_regardless_of_input(monkeypatch, tmp_path):
    # The fixtures deliberately carry real-looking operator paths on input.
    raw_paths = {
        e.get("response", {}).get("cache_path")
        for f in FIXTURE_RUN.glob("*.json")
        for e in [json.loads(f.read_text(encoding="utf-8"))]
        if e.get("kind") == "token_event"
    }
    assert raw_paths and consolidate_run.REDACTED_CACHE_PATH not in raw_paths

    _point_at(monkeypatch, replay_dir=FIXTURE_RUN, samples_dir=tmp_path)
    assert consolidate_run.main(["--run-id", RUN_ID]) == 0

    token_events = [e for e in _read_output(tmp_path) if e["kind"] == "token_event"]
    assert token_events, "expected token_event entries in output"
    for entry in token_events:
        assert entry["response"]["cache_path"] == "<redacted>"


def test_entries_from_other_run_are_excluded(monkeypatch, tmp_path):
    replay_dir = tmp_path / "replay-logs"
    replay_dir.mkdir()
    for src in FIXTURE_RUN.glob("*.json"):
        shutil.copy(src, replay_dir / src.name)
    # An unrelated run's entry sharing the same directory must not leak in.
    (replay_dir / "other-run.json").write_text(
        json.dumps(
            {
                "kind": "graph_call",
                "tool": "tool_list_users",
                "run_id": "R901",
                "outcome": "success",
                "response": {"status_code": 200, "page_count": 1, "row_count": 1},
                "entry_id": "99999999-9999-4999-8999-999999999999",
            }
        ),
        encoding="utf-8",
    )

    _point_at(monkeypatch, replay_dir=replay_dir, samples_dir=tmp_path / "out")
    assert consolidate_run.main(["--run-id", RUN_ID]) == 0

    entries = _read_output(tmp_path / "out")
    assert {e["entry_id"] for e in entries} == EXPECTED_ENTRY_IDS
    assert all(e["run_id"] == RUN_ID for e in entries)


def test_missing_replay_logs_dir_exits_1(monkeypatch, tmp_path, capsys):
    _point_at(
        monkeypatch,
        replay_dir=tmp_path / "does-not-exist",
        samples_dir=tmp_path / "out",
    )
    assert consolidate_run.main(["--run-id", RUN_ID]) == 1
    assert "does not exist" in capsys.readouterr().err


def test_run_id_not_found_exits_1(monkeypatch, tmp_path, capsys):
    _point_at(monkeypatch, replay_dir=FIXTURE_RUN, samples_dir=tmp_path)
    assert consolidate_run.main(["--run-id", "R999"]) == 1
    assert "no entries found" in capsys.readouterr().err
    assert not (tmp_path / "R999.json").exists()

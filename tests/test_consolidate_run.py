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


@pytest.fixture(autouse=True)
def _isolated_token_cache(monkeypatch, tmp_path):
    """Point identity's token cache at a temp path for every test in this module.

    main() now ends the run's sessions (G-8) by deleting each account's token cache.
    The fixture run's token_events use the real sandbox UPN, so without this the
    suite would delete the operator's real cache.
    """
    import identity

    cache = tmp_path / "token-cache" / "rejewski.bin"
    monkeypatch.setenv(identity.ENV_CACHE_PATH, str(cache))
    return cache


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


# --- G-8 session teardown -------------------------------------------------------


SANDBOX_UPN = "meganb@cloudharbor-demo.com"


def _run_with_actor(tmp_path: Path) -> Path:
    """Copy the fixture run and stamp actor_upn on its token_events, as real logs carry."""
    run_dir = tmp_path / "replay-logs"
    shutil.copytree(FIXTURE_RUN, run_dir)
    for path in run_dir.glob("*.json"):
        entry = json.loads(path.read_text(encoding="utf-8"))
        if entry.get("kind") == "token_event":
            entry["actor_upn"] = SANDBOX_UPN
            path.write_text(json.dumps(entry), encoding="utf-8")
    return run_dir


def _seed_cache(cache: Path) -> Path:
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_bytes(b"encrypted-cache-stand-in")
    lock = Path(f"{cache}.lockfile")
    lock.write_text("", encoding="utf-8")
    return lock


def test_teardown_deletes_run_token_cache(monkeypatch, tmp_path, capsys, _isolated_token_cache):
    cache = _isolated_token_cache
    lock = _seed_cache(cache)
    _point_at(monkeypatch, replay_dir=_run_with_actor(tmp_path), samples_dir=tmp_path / "out")

    assert consolidate_run.main(["--run-id", RUN_ID]) == 0

    assert not cache.exists() and not lock.exists()
    out = capsys.readouterr().out
    assert f"G-8 session teardown for {SANDBOX_UPN}: token cache deleted" in out
    assert str(cache) not in out, "operator-local cache path must not be printed (G-6)"


def test_keep_session_leaves_token_cache(monkeypatch, tmp_path, capsys, _isolated_token_cache):
    cache = _isolated_token_cache
    lock = _seed_cache(cache)
    _point_at(monkeypatch, replay_dir=_run_with_actor(tmp_path), samples_dir=tmp_path / "out")

    assert consolidate_run.main(["--run-id", RUN_ID, "--keep-session"]) == 0

    assert cache.exists() and lock.exists()
    assert "teardown skipped (--keep-session)" in capsys.readouterr().out


def test_teardown_runs_after_evidence_is_written(monkeypatch, tmp_path, _isolated_token_cache):
    _seed_cache(_isolated_token_cache)
    out_dir = tmp_path / "out"
    _point_at(monkeypatch, replay_dir=FIXTURE_RUN, samples_dir=out_dir)
    seen = {}

    def _spy(entries):
        seen["evidence_written"] = (out_dir / f"{RUN_ID}.json").is_file()
        return 0

    monkeypatch.setattr(consolidate_run, "end_run_sessions", _spy)
    assert consolidate_run.main(["--run-id", RUN_ID]) == 0
    assert seen == {"evidence_written": True}


def test_failed_consolidation_does_not_end_session(monkeypatch, tmp_path, _isolated_token_cache):
    cache = _isolated_token_cache
    _seed_cache(cache)
    _point_at(monkeypatch, replay_dir=_run_with_actor(tmp_path), samples_dir=tmp_path / "out")

    assert consolidate_run.main(["--run-id", "R-NOT-THERE"]) == 1
    assert cache.exists()


def test_run_actor_upns_dedupes_token_event_accounts():
    entries = [
        {"kind": "token_event", "actor_upn": "a@x.test"},
        {"kind": "graph_call", "actor_upn": "b@x.test"},
        {"kind": "token_event", "actor_upn": "a@x.test"},
        {"event": "consent.granted", "run_id": "R1"},
        {"kind": "token_event", "actor_upn": "c@x.test"},
    ]
    assert consolidate_run.run_actor_upns(entries) == ["a@x.test", "c@x.test"]

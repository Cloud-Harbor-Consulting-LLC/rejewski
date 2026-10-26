# SPDX-License-Identifier: MIT
"""Tests for scripts/rotate_replay_logs.py (Sprint 5 W17 replay-log rotation).

Local-filesystem tool — no Graph mocking needed. Covers the age boundary (only entries
strictly older than the threshold rotate), gzip validity + round-trip to the original
JSON, --dry-run making no filesystem changes, and the hard samples/replay-log/ guard.
All tests operate in tmp_path; the guard test monkeypatches the protected-path constant
so the real committed evidence is never involved.
"""

from __future__ import annotations

import gzip
import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import rotate_replay_logs as rot  # noqa: E402

NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)


def _make_entry(log_dir: Path, ts: datetime, payload: dict | None = None) -> Path:
    """Write a replay-log-style entry file named <YYYYMMDDThhmmssZ>-<uuid>.json."""
    log_dir.mkdir(parents=True, exist_ok=True)
    stamp = ts.strftime("%Y%m%dT%H%M%SZ")
    path = log_dir / f"{stamp}-{uuid.uuid4()}.json"
    body = payload if payload is not None else {
        "kind": "graph_call",
        "started_at_utc": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "outcome": "success",
    }
    path.write_text(json.dumps(body, indent=2), encoding="utf-8")
    return path


# 1 — age boundary: strictly-older entries rotate; within-window entries are kept.
def test_age_boundary(tmp_path):
    log_dir = tmp_path / "replay-logs"
    archive_dir = log_dir / "archive"
    old = _make_entry(log_dir, NOW - timedelta(days=31))     # older than 30d -> archive
    boundary = _make_entry(log_dir, NOW - timedelta(days=30))  # exactly 30d -> keep
    fresh = _make_entry(log_dir, NOW - timedelta(days=29))    # within 30d -> keep

    archived = rot.rotate(log_dir, archive_dir, max_age_days=30, now=NOW)

    assert archived == 1
    assert not old.exists()  # original removed
    assert boundary.exists()
    assert fresh.exists()
    # archived into month-partitioned path derived from the ENTRY timestamp (2026-08)
    dest = archive_dir / "2026-08" / (old.name + ".gz")
    assert dest.is_file()
    # only the one .gz was produced
    assert list(archive_dir.rglob("*.gz")) == [dest]


# 2 — gzip output is valid and round-trips to the original JSON bytes.
def test_gzip_roundtrip(tmp_path):
    log_dir = tmp_path / "replay-logs"
    archive_dir = log_dir / "archive"
    payload = {"kind": "token_event", "started_at_utc": "2026-06-01T00:00:00Z", "run_id": "R099"}
    entry = _make_entry(log_dir, NOW - timedelta(days=90), payload=payload)
    original_bytes = entry.read_bytes()

    rot.rotate(log_dir, archive_dir, max_age_days=30, now=NOW)

    dest = archive_dir / "2026-06" / (entry.name + ".gz")
    assert dest.is_file()
    with gzip.open(dest, "rb") as fh:
        restored = fh.read()
    assert restored == original_bytes
    assert json.loads(restored) == payload  # valid JSON, identical content


# 3 — --dry-run makes no filesystem changes.
def test_dry_run_no_changes(tmp_path):
    log_dir = tmp_path / "replay-logs"
    archive_dir = log_dir / "archive"
    old = _make_entry(log_dir, NOW - timedelta(days=45))

    would = rot.rotate(log_dir, archive_dir, max_age_days=30, now=NOW, dry_run=True)

    assert would == 1  # reports what would move
    assert old.exists()  # original untouched
    assert not archive_dir.exists()  # nothing written


# 4a — hard guard: is_protected_path rejects samples/replay-log/ and paths under it.
def test_is_protected_path():
    assert rot.is_protected_path(rot.SAMPLES_REPLAY_LOG) is True
    assert rot.is_protected_path(rot.SAMPLES_REPLAY_LOG / "R012.json") is True
    # a normal working dir is not protected
    assert rot.is_protected_path(rot.DEFAULT_LOG_DIR) is False


# 4b — main() refuses when pointed at the protected path and changes nothing.
def test_guard_refuses_via_main(tmp_path, monkeypatch):
    fake_samples = tmp_path / "samples" / "replay-log"
    monkeypatch.setattr(rot, "SAMPLES_REPLAY_LOG", fake_samples)
    # a qualifying-age entry sitting in the protected dir
    victim = _make_entry(fake_samples, NOW - timedelta(days=365))

    rc = rot.main(["--log-dir", str(fake_samples)])

    assert rc == 2  # refused
    assert victim.exists()  # untouched
    assert not (fake_samples / "archive").exists()

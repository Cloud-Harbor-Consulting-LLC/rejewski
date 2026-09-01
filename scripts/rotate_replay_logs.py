#!/usr/bin/env python3
"""
Rejewski Sprint 5 W17 — rotate_replay_logs

Age-based rotation and gzip compression for the `replay-logs/` working directory.

`replay-logs/` (gitignored, .gitignore line 65) accumulates one JSON file per emitted
replay-log entry and grows unbounded. This tool compresses entries older than the age
threshold into a month-partitioned archive and deletes the uncompressed originals, per
docs/replay-archive.md.

This is a **local-filesystem** tool: it issues no Microsoft Graph calls, so the tenant
guardrails G-1/G-3 do not apply to its execution path. G-6 still applies to what it
prints — output is limited to entry filenames (which already contain only a UTC timestamp
and a random entry_id) and repo-relative archive paths; no operator home paths are printed.

**Curated evidence is out of scope.** `samples/replay-log/` (R002–R012, committed canonical
evidence) is never a rotation candidate. The tool refuses to operate on that directory — or
anything containing/contained by it — with an explicit path guard (`is_protected_path`), not
merely by documentation.

CLI:
    python scripts/rotate_replay_logs.py [--log-dir replay-logs]
        [--archive-dir replay-logs/archive] [--max-age-days 30] [--dry-run]

--dry-run reports what would move without moving anything.
"""

from __future__ import annotations

import argparse
import gzip
import re
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOG_DIR = REPO_ROOT / "replay-logs"
DEFAULT_ARCHIVE_DIR = DEFAULT_LOG_DIR / "archive"

# Committed canonical evidence — never a rotation candidate (hard guard, AC3).
SAMPLES_REPLAY_LOG = REPO_ROOT / "samples" / "replay-log"

DEFAULT_MAX_AGE_DAYS = 30

# Entry filename convention from replay_log._filename(): "<YYYYMMDDThhmmssZ>-<entry_id>.json".
_FILENAME_RE = re.compile(r"^(\d{8}T\d{6}Z)-[0-9a-fA-F-]+\.json$")
_TS_FORMAT = "%Y%m%dT%H%M%SZ"


def entry_timestamp(path: Path) -> Optional[datetime]:
    """UTC datetime parsed from a replay-log entry filename, or None if it doesn't match."""
    m = _FILENAME_RE.match(path.name)
    if not m:
        return None
    return datetime.strptime(m.group(1), _TS_FORMAT).replace(tzinfo=timezone.utc)


def is_protected_path(path: Path) -> bool:
    """True if `path` is, contains, or is contained by samples/replay-log/ (never rotate it)."""
    target = path.resolve()
    protected = SAMPLES_REPLAY_LOG.resolve()
    return target == protected or protected in target.parents or target in protected.parents


def plan_rotation(
    log_dir: Path,
    archive_dir: Path,
    max_age_days: int,
    now: datetime,
) -> tuple[list[tuple[Path, Path]], int, int]:
    """Return (actions, scanned, skipped_unrecognized).

    `actions` is a list of (source_json, dest_gz) for entries strictly older than the
    threshold. Only top-level *.json files are considered — the archive subtree is never
    rescanned.
    """
    cutoff = now - timedelta(days=max_age_days)
    actions: list[tuple[Path, Path]] = []
    scanned = 0
    skipped_unrecognized = 0
    for path in sorted(log_dir.glob("*.json")):
        if not path.is_file():
            continue
        scanned += 1
        ts = entry_timestamp(path)
        if ts is None:
            skipped_unrecognized += 1
            continue
        if ts >= cutoff:
            continue  # within the hot window — keep uncompressed
        month = ts.strftime("%Y-%m")
        dest = archive_dir / month / (path.name + ".gz")
        actions.append((path, dest))
    return actions, scanned, skipped_unrecognized


def _archive(source: Path, dest: Path) -> None:
    """Gzip `source` to `dest` then remove the original."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as fin, gzip.open(dest, "wb") as fout:
        shutil.copyfileobj(fin, fout)
    source.unlink()


def rotate(
    log_dir: Path,
    archive_dir: Path,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    now: Optional[datetime] = None,
    dry_run: bool = False,
) -> int:
    """Rotate qualifying entries. Returns the number of entries archived (or that would be)."""
    now = now or datetime.now(timezone.utc)
    actions, scanned, skipped = plan_rotation(log_dir, archive_dir, max_age_days, now)

    verb = "would archive" if dry_run else "archived"
    for source, dest in actions:
        if not dry_run:
            _archive(source, dest)
        # G-6: print only the basename and a repo-relative-ish archive path (month/name.gz).
        rel = f"{dest.parent.name}/{dest.name}"
        print(f"  {verb}: {source.name} -> archive/{rel}", file=sys.stderr)

    kept = scanned - len(actions) - skipped
    print(
        f"{verb}: {len(actions)} | kept (within {max_age_days}d): {kept} | "
        f"skipped (unrecognized name): {skipped} | scanned: {scanned}",
        file=sys.stderr,
    )
    return len(actions)


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="rotate_replay_logs.py",
        description="Age-based gzip rotation for the replay-logs/ working directory.",
    )
    p.add_argument(
        "--log-dir",
        default=str(DEFAULT_LOG_DIR),
        help="working directory of replay-log entries (default: replay-logs/)",
    )
    p.add_argument(
        "--archive-dir",
        default=None,
        help="archive destination (default: <log-dir>/archive)",
    )
    p.add_argument(
        "--max-age-days",
        type=int,
        default=DEFAULT_MAX_AGE_DAYS,
        help=f"archive entries strictly older than this many days (default: {DEFAULT_MAX_AGE_DAYS})",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="report what would move without moving anything",
    )
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    log_dir = Path(args.log_dir)
    archive_dir = Path(args.archive_dir) if args.archive_dir else log_dir / "archive"

    # AC3 — hard guard: never operate on curated evidence.
    if is_protected_path(log_dir) or is_protected_path(archive_dir):
        print(
            f"error: refusing to rotate a protected path (samples/replay-log/ is committed "
            f"evidence, not a rotation candidate): {log_dir}",
            file=sys.stderr,
        )
        return 2

    if not log_dir.is_dir():
        print(f"error: log-dir not found: {log_dir}", file=sys.stderr)
        return 2
    if args.max_age_days < 0:
        print("error: --max-age-days must be >= 0", file=sys.stderr)
        return 2

    rotate(
        log_dir=log_dir,
        archive_dir=archive_dir,
        max_age_days=args.max_age_days,
        dry_run=args.dry_run,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

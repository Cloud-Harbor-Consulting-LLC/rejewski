# Rejewski Replay-Log Archive Policy

- Version: v0.1
- Last updated: 2026-09-01
- Status: Living document
- Authors: Derek Morgan
- Related: scripts/rotate_replay_logs.py, scripts/replay_log.py, .gitignore, docs/threat-model.md

---

## 1. Purpose and scope

The `replay-logs/` working directory (gitignored, `.gitignore` line 65) accumulates one
JSON file per emitted replay-log entry — `scripts/replay_log.write_entry()` writes
`<YYYYMMDDThhmmssZ>-<entry_id>.json` there on every consented run and local dry run. It has
no rotation and grows unbounded (62 entries / ~248K as of 2026-08-29, spanning 2026-05-27
onward). This policy defines how those working-directory entries are compressed and archived.

**In scope:** the `replay-logs/` working directory only.

**Explicitly out of scope — never touched by rotation:**

- **`samples/replay-log/`** — the committed, curated canonical evidence (R002–R012). This is
  version-controlled evidence, not a rotation candidate. `scripts/rotate_replay_logs.py`
  enforces this with a **hard path guard** (`is_protected_path`), refusing to run against that
  directory (or anything containing or contained by it) with a non-zero exit — an explicit
  check, not merely this sentence.
- **`docs/replay-report-r011.html`** and any other hand-built report — not under
  `replay-logs/`, so out of the rotation path by construction.

---

## 2. Rotation trigger — age-based, 30 days

An entry is archived when it is **strictly older than 30 days**, measured from the entry's
own UTC timestamp (the `<YYYYMMDDThhmmssZ>` filename prefix, which equals its
`started_at_utc`) to "now" at rotation time. An entry exactly 30 days old is kept.

**Why 30 days (age) rather than a size or count cap:**

- **Sprint-aligned.** Rejewski runs on ~2-week sprints; a 30-day hot window keeps roughly the
  current and previous sprint's working entries uncompressed and immediately greppable, while
  older sprints roll to the archive.
- **The canonical evidence is already preserved elsewhere.** Every finding that matters is
  promoted into `samples/replay-log/` (curated) and cited by the technique modules. Working-
  directory entries older than a sprint are low-value to keep hot — but worth retaining
  compressed for forensic completeness, not deleting.
- **Deterministic and auditable.** Age comes from the entry timestamp encoded in the filename,
  not file mtime (which a checkout or copy would reset). The boundary is reproducible.
- **Not size/count based.** A size or count cap would evict recent entries under a burst of
  activity — exactly the entries an operator is most likely to be investigating. Age is the
  property that actually tracks "still interesting."

The threshold is a CLI parameter (`--max-age-days`, default 30); the default is the policy.

---

## 3. Compression format — gzip

Qualifying entries are compressed with **gzip** (`.json` → `.json.gz`), one archive file per
entry. Gzip is chosen because it is in the Python standard library (`gzip`, no dependency),
round-trips losslessly to the exact original bytes (verified in
`tests/test_rotate_replay_logs.py`), and each entry stays an independently decompressible unit
(no need to unpack a whole tarball to read one entry). The uncompressed original is removed
after the archive is written.

To read an archived entry:

```bash
gzip -dc replay-logs/archive/2026-07/<name>.json.gz | jq .
```

---

## 4. Archive destination — month-partitioned, inside the gitignored working dir

Archives are written under **`replay-logs/archive/<YYYY-MM>/<original-filename>.gz`**, where
`<YYYY-MM>` is derived from the **entry's** timestamp (the month it belongs to), not the
rotation date. For example:

```
replay-logs/
  20260815T...-<id>.json            # < 30 days old — kept hot
  archive/
    2026-05/  20260527T120700Z-<id>.json.gz
    2026-06/  20260601T....-<id>.json.gz
    2026-07/  20260718T163336Z-<id>.json.gz
```

Rationale:

- **Stays gitignored.** `replay-logs/` is already ignored (`.gitignore` line 65), so the
  archive subtree is ignored too — no archived operator run-logs are ever committed. (Curated
  evidence lives in `samples/replay-log/`, which is committed and out of scope here.)
- **Month partitions** keep the archive browsable and make a future retention/prune step
  (e.g. "drop archive months older than N") a simple directory operation.
- **Never rescanned.** The rotation tool globs only top-level `replay-logs/*.json`; the
  `archive/` subtree and its `.gz` files are never re-processed.

---

## 5. Operation

```bash
# Preview (no changes) — recommended before a real run:
python scripts/rotate_replay_logs.py --dry-run

# Rotate with the policy defaults (replay-logs/, 30 days, replay-logs/archive/):
python scripts/rotate_replay_logs.py

# Non-default window or location:
python scripts/rotate_replay_logs.py --log-dir replay-logs --archive-dir replay-logs/archive --max-age-days 45
```

The tool issues **no Microsoft Graph calls** — it is a local-filesystem operation, so the
tenant guardrails **G-1/G-3 do not apply to its execution path**. **G-6 still applies to its
output:** it prints only entry basenames (a UTC timestamp + a random `entry_id`) and
repo-relative archive paths — no operator home-directory paths. Cadence is operator-driven
(run at sprint close, or wire into a scheduled task); the tool is idempotent and safe to
re-run — a second run re-archives nothing already moved.

---

## 6. Change log

| Version | Date | Change |
|---|---|---|
| v0.1 | 2026-09-01 | Initial policy. 30-day age trigger, gzip per-entry, month-partitioned `replay-logs/archive/<YYYY-MM>/` destination, hard guard on `samples/replay-log/`. Implemented by `scripts/rotate_replay_logs.py` (+ `tests/test_rotate_replay_logs.py`). |

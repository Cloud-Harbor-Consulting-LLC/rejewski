#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Rejewski Sprint 4 W14 — finding_dedup

Finding deduplication classifier. As ROE runs accumulate, the same ATT&CK technique
produces a finding-triage record in run after run (for example T1087.004 appears in
both R010 and R011). This utility reads every finding-triage JSON record from a
directory, groups them by technique_id, and — relative to a chosen target run —
classifies each technique observed in that run as:

  - new_technique : the technique_id has no finding record in any earlier run
  - recurring     : the technique_id also appears in at least one prior run
  - variant       : the technique_id appears in a prior run but with a different
                    severity in every prior occurrence than in the target run
                    (a recurring finding whose severity has shifted)

Severity/confidence shifts between the target run and prior runs are recorded in the
per-finding `diff` block; a shift only promotes recurring -> variant when the target
severity differs from *all* prior severities (per the brief's classification table).

This is a read-only analysis tool. It never modifies a finding-triage record and
issues no Graph calls or replay-log writes. Invalid JSON files are skipped with a
stderr warning so a single malformed record does not abort the run.

CLI:
    python scripts/finding_dedup.py \
        --finding-dir samples/finding-triage/ \
        --run-id R012 \
        --output finding-dedup-R012.json

If --run-id is omitted the script emits a full-corpus summary (no target run): every
technique is listed with the runs it appears in, classified recurring if seen in more
than one run and new_technique otherwise.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional


def load_findings(finding_dir: Path) -> list[dict]:
    """Read all *.json finding-triage records under finding_dir.

    Files that are not valid JSON, or that lack a technique_id, are skipped with a
    stderr warning; processing continues with the remaining records.
    """
    records: list[dict] = []
    for path in sorted(finding_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            print(f"warning: skipping {path.name}: invalid JSON ({exc})", file=sys.stderr)
            continue
        if not isinstance(data, dict) or "technique_id" not in data:
            print(
                f"warning: skipping {path.name}: no technique_id field",
                file=sys.stderr,
            )
            continue
        records.append(data)
    return records


def _occurrence(rec: dict) -> dict:
    """Project a finding record down to the fields used in the report output."""
    return {
        "run_id": rec.get("run_id"),
        "finding_id": rec.get("finding_id"),
        "severity": rec.get("severity"),
        "confidence": rec.get("confidence"),
    }


def _diff(target: dict, priors: list[dict]) -> dict:
    """Severity/confidence shift between the target occurrence and prior occurrences."""
    prior_sev = sorted({p.get("severity") for p in priors if p.get("severity") is not None})
    prior_conf = sorted({p.get("confidence") for p in priors if p.get("confidence") is not None})
    tgt_sev = target.get("severity")
    tgt_conf = target.get("confidence")
    return {
        "severity": {
            "target": tgt_sev,
            "prior": prior_sev,
            "changed": tgt_sev not in prior_sev,
        },
        "confidence": {
            "target": tgt_conf,
            "prior": prior_conf,
            "changed": tgt_conf not in prior_conf,
        },
    }


def classify(records: list[dict], run_id: Optional[str]) -> dict:
    """Group records by technique_id and classify each relative to the target run."""
    by_technique: dict[str, list[dict]] = {}
    for rec in records:
        by_technique.setdefault(rec["technique_id"], []).append(rec)

    findings: list[dict] = []
    prior_only: list[dict] = []
    summary = {"new_technique": 0, "recurring": 0, "variant": 0, "prior_run_only": 0}

    for technique_id in sorted(by_technique):
        occurrences = by_technique[technique_id]
        name = next(
            (o.get("technique_name") for o in occurrences if o.get("technique_name")),
            None,
        )

        if run_id is None:
            # Full-corpus mode: no target run. Classify by run breadth.
            runs = sorted({o.get("run_id") for o in occurrences})
            classification = "recurring" if len(runs) > 1 else "new_technique"
            summary[classification] += 1
            findings.append(
                {
                    "technique_id": technique_id,
                    "technique_name": name,
                    "classification": classification,
                    "target_run": None,
                    "prior_runs": [_occurrence(o) for o in occurrences],
                }
            )
            continue

        target_occ = [o for o in occurrences if o.get("run_id") == run_id]
        prior_occ = [o for o in occurrences if o.get("run_id") != run_id]

        if not target_occ:
            # Technique seen only in prior runs, absent from the target run.
            prior_only.append(
                {
                    "technique_id": technique_id,
                    "technique_name": name,
                    "prior_runs": [_occurrence(o) for o in sorted(prior_occ, key=lambda o: o.get("run_id") or "")],
                }
            )
            continue

        target = _occurrence(target_occ[0])
        priors = [_occurrence(o) for o in sorted(prior_occ, key=lambda o: o.get("run_id") or "")]

        if not priors:
            classification = "new_technique"
        else:
            prior_sevs = {p.get("severity") for p in priors}
            classification = "variant" if target.get("severity") not in prior_sevs else "recurring"

        summary[classification] += 1
        entry = {
            "technique_id": technique_id,
            "technique_name": name,
            "classification": classification,
            "target_run": target,
            "prior_runs": priors,
        }
        if priors:
            entry["diff"] = _diff(target, priors)
        findings.append(entry)

    summary["prior_run_only"] = len(prior_only)

    return {
        "run_id": run_id,
        "summary": summary,
        "findings": findings,
        "techniques_in_prior_runs_not_in_target": prior_only,
    }


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="finding_dedup.py",
        description="Classify finding-triage records as new/recurring/variant across runs.",
    )
    p.add_argument(
        "--finding-dir",
        required=True,
        help="Directory of finding-triage JSON records.",
    )
    p.add_argument(
        "--run-id",
        default=None,
        help="Target run treated as 'current'. Omit for a full-corpus summary.",
    )
    p.add_argument(
        "--output",
        default=None,
        help="Write the classification JSON here. Omit to print to stdout.",
    )
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    finding_dir = Path(args.finding_dir)

    if not finding_dir.is_dir():
        print(f"error: finding-dir not found: {finding_dir}", file=sys.stderr)
        return 2

    records = load_findings(finding_dir)
    if not records:
        print(f"error: no valid finding-triage records in {finding_dir}", file=sys.stderr)
        return 2

    if args.run_id is not None:
        run_ids = {r.get("run_id") for r in records}
        if args.run_id not in run_ids:
            print(
                f"error: run-id {args.run_id} not found in corpus "
                f"(runs present: {', '.join(sorted(str(r) for r in run_ids))})",
                file=sys.stderr,
            )
            return 2

    report = classify(records, args.run_id)
    payload = json.dumps(report, indent=2)

    if args.output:
        Path(args.output).write_text(payload + "\n", encoding="utf-8")
        s = report["summary"]
        print(
            f"wrote {args.output}: new_technique={s['new_technique']} "
            f"recurring={s['recurring']} variant={s['variant']} "
            f"prior_run_only={s['prior_run_only']}",
            file=sys.stderr,
        )
    else:
        print(payload)

    return 0


if __name__ == "__main__":
    sys.exit(main())

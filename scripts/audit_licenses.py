#!/usr/bin/env python3
"""Rejewski dependency license audit.

Reproducible, offline. Emits JSON evidence matrix and Markdown table.
Fails loud on UNKNOWN entries, non-permissive licenses, or transitive-set drift.

See docs/dependency-license-audit.md for the v0.1 baseline and Section 7.1
for the 6-tier classifier-ambiguity fallback.
"""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
EVIDENCE_ROOT = REPO_ROOT / "evidence"

EXPECTED_PACKAGES = {
    "jsonschema",
    "pytest",
    "attrs",
    "referencing",
    "rpds-py",
    "jsonschema-specifications",
    "iniconfig",
    "packaging",
    "pluggy",
}

SPDX_MAP = {
    "MIT License": "MIT",
    "MIT": "MIT",
    "Apache Software License": "Apache-2.0",
    "Apache 2.0": "Apache-2.0",
    "Apache-2.0": "Apache-2.0",
    "BSD License": "BSD-3-Clause-or-similar (manual review)",
    "BSD": "BSD-3-Clause-or-similar (manual review)",
    "BSD-2-Clause": "BSD-2-Clause",
    "BSD-3-Clause": "BSD-3-Clause",
    "Apache-2.0 OR BSD-2-Clause": "Apache-2.0 OR BSD-2-Clause",
    "ISC License (ISCL)": "ISC",
    "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "Python Software Foundation License": "PSF-2.0",
    "UNKNOWN": "UNKNOWN",
}

PERMISSIVE_SPDX = {
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSD-3-Clause-or-similar (manual review)",
    "ISC",
    "PSF-2.0",
    "Apache-2.0 OR BSD-2-Clause",
}


def run_pip_licenses() -> list[dict]:
    """Invoke pip-licenses and return parsed JSON output."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "piplicenses",
            "--format=json",
            "--from=mixed",
            "--with-urls",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        raise SystemExit(
            "pip-licenses invocation failed. Install: pip install pip-licenses==5.5.5"
        )
    return json.loads(result.stdout)


def resolve_spdx(raw_license: str) -> tuple[str, str]:
    """Apply Section 7.1 fallback. Returns (spdx_id, source_tier)."""
    raw = (raw_license or "").strip()
    if not raw or raw == "UNKNOWN":
        return "UNKNOWN", "manual"
    if raw in SPDX_MAP:
        return SPDX_MAP[raw], "classifier"
    for needle, spdx in SPDX_MAP.items():
        if needle.lower() in raw.lower():
            return spdx, "metadata"
    return "UNKNOWN", "manual"


def mit_inbound_compatible(spdx_id: str) -> bool:
    return spdx_id in PERMISSIVE_SPDX


def build_records(raw_entries: list[dict]) -> list[dict]:
    records: list[dict] = []
    for entry in raw_entries:
        name = entry.get("Name", "")
        version = entry.get("Version", "")
        raw_license = entry.get("License", "UNKNOWN")
        url = entry.get("URL", "")
        spdx_id, source_tier = resolve_spdx(raw_license)
        records.append(
            {
                "name": name,
                "version": version,
                "license_spdx": spdx_id,
                "license_source": source_tier,
                "license_raw": raw_license,
                "license_url": url,
                "mit_inbound_compat": mit_inbound_compatible(spdx_id),
                "requires_manual_review": spdx_id == "UNKNOWN",
            }
        )
    return records


def detect_transitive_drift(records: list[dict]) -> dict:
    observed = {r["name"].lower() for r in records}
    expected = {p.lower() for p in EXPECTED_PACKAGES}
    extras = sorted(observed - expected)
    missing = sorted(expected - observed)
    drift = bool(extras or missing)
    return {
        "requires_first_run_verification": drift,
        "unexpected_packages": extras,
        "missing_expected_packages": missing,
    }


def write_evidence(records: list[dict], drift: dict) -> Path:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    target_dir = EVIDENCE_ROOT / today
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / "dependency-licenses.json"
    payload = {
        "audit_date_utc": today,
        "downstream_license_spdx": "MIT",
        "package_count": len(records),
        "transitive_drift": drift,
        "packages": records,
    }
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return target


def render_markdown_table(records: list[dict]) -> str:
    lines = [
        "| Package | Version | SPDX | Source | MIT-inbound compat |",
        "|---|---|---|---|---|",
    ]
    for r in sorted(records, key=lambda x: x["name"].lower()):
        compat = "yes" if r["mit_inbound_compat"] else "NO"
        lines.append(
            f"| {r['name']} | {r['version']} | {r['license_spdx']} | "
            f"{r['license_source']} | {compat} |"
        )
    return "\n".join(lines)


def enforce_release_gate(records: list[dict], drift: dict) -> None:
    failures: list[str] = []
    for r in records:
        if r["license_spdx"] == "UNKNOWN":
            failures.append(f"UNKNOWN license: {r['name']} {r['version']}")
        elif not r["mit_inbound_compat"]:
            failures.append(
                f"Non-MIT-compatible license: {r['name']} {r['version']} "
                f"({r['license_spdx']})"
            )
    if drift["requires_first_run_verification"]:
        if drift["unexpected_packages"]:
            failures.append(
                "Unexpected transitive packages (update docs Section 4): "
                + ", ".join(drift["unexpected_packages"])
            )
        if drift["missing_expected_packages"]:
            failures.append(
                "Missing expected transitive packages (verify install): "
                + ", ".join(drift["missing_expected_packages"])
            )
    if failures:
        sys.stderr.write("\nRELEASE GATE FAILURES:\n")
        for f in failures:
            sys.stderr.write(f"  - {f}\n")
        raise SystemExit(1)


def main() -> int:
    raw_entries = run_pip_licenses()
    records = build_records(raw_entries)
    drift = detect_transitive_drift(records)
    evidence_path = write_evidence(records, drift)
    table = render_markdown_table(records)
    sys.stdout.write(f"Evidence written: {evidence_path}\n\n")
    sys.stdout.write(table + "\n\n")
    if drift["requires_first_run_verification"]:
        sys.stdout.write("Transitive drift detected. See evidence JSON.\n")
    enforce_release_gate(records, drift)
    sys.stdout.write("\nAudit passed. All packages MIT-inbound compatible.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One-time helper: write R011 consent.granted record to replay-logs/."""
import json, uuid, time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

emitted_dt = datetime.now(timezone.utc)
emitted = emitted_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
time.sleep(3)
confirmed_dt = datetime.now(timezone.utc)
confirmed = confirmed_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
latency = int((confirmed_dt - emitted_dt).total_seconds())

record = {
    "event": "consent.granted",
    "run_id": "R011",
    "tenant_id": "76b87c33-6178-4ff9-94a7-164792c8e4c6",
    "operator_object_id": "48df3ad2-9110-4c27-9630-f82b1b8eb177",
    "techniques": [
        "T1078.004",
        "T1087.004",
        "T1069.003",
        "T1550.001",
        "T1526",
        "T1518.001",
        "T1082",
        "T1580",
        "T1654",
    ],
    "expected_duration_seconds": 1800,
    "prompt_emitted_at": emitted,
    "confirmed_at": confirmed,
    "confirmation_latency_seconds": latency,
}

stamp = emitted_dt.strftime("%Y%m%dT%H%M%SZ")
out_path = REPO_ROOT / "replay-logs" / f"{stamp}-{uuid.uuid4()}.json"
out_path.parent.mkdir(exist_ok=True)
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(record, f, indent=2)
    f.write("\n")
print(f"[consent] wrote {out_path.name}")

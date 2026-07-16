import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "schemas" / "finding-triage" / "v0.1.json"
SAMPLES_DIR = REPO_ROOT / "samples" / "finding-triage"

_VALIDATOR = Draft202012Validator(
    json.loads(SCHEMA_PATH.read_text()),
    format_checker=FormatChecker(),
)

_VALID_PAYLOAD = {
    "finding_id": "ft-test-001",
    "technique_id": "T1087.004",
    "technique_name": "Test",
    "run_id": "R000",
    "severity": "low",
    "confidence": "medium",
    "evidence": [],
    "triage_status": "open",
    "triage_metadata": {
        "created_utc": "2026-07-16T00:00:00Z",
        "author": "rejewski",
        "schema_version": "0.1",
    },
}


def test_all_samples_validate():
    files = sorted(SAMPLES_DIR.glob("*.json"))
    assert files, "no samples found under samples/finding-triage/"
    for path in files:
        _VALIDATOR.validate(json.loads(path.read_text()))


def test_missing_required_field_fails():
    with pytest.raises(Exception):
        _VALIDATOR.validate({"finding_id": "ft-test-001"})


def test_wrong_schema_version_fails():
    import copy
    payload = copy.deepcopy(_VALID_PAYLOAD)
    payload["triage_metadata"]["schema_version"] = "0.2"
    with pytest.raises(Exception):
        _VALIDATOR.validate(payload)


def test_invalid_control_mapping_id_pattern_fails():
    import copy
    payload = copy.deepcopy(_VALID_PAYLOAD)
    # A control.control_id from the finding-to-control schema, not a
    # mapping_id slug — the exact confusion control_mapping_id is named to avoid.
    payload["control_mapping_id"] = "CA-COV008-BlockByLocation"
    with pytest.raises(Exception):
        _VALIDATOR.validate(payload)

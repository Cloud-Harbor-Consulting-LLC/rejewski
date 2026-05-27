import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "schemas" / "finding-to-control" / "v0.1.json"
SAMPLES_DIR = REPO_ROOT / "samples" / "finding-to-control"

_VALIDATOR = Draft202012Validator(
    json.loads(SCHEMA_PATH.read_text()),
    format_checker=FormatChecker(),
)

_VALID_PAYLOAD = {
    "mapping_id": "ft1087-004-ca-test-001",
    "finding": {
        "technique_id": "T1087.004",
        "technique_name": "Account Discovery: Cloud Account",
        "observed_in": [],
        "severity": "medium",
        "rationale": "Test rationale.",
    },
    "control": {
        "control_family": "conditional_access",
        "control_id": "CA-TEST-001",
        "control_type": "preventive",
        "microsoft_pillar": "Identities",
        "nist_800_207_tenets": ["T4"],
        "reference_url": "https://learn.microsoft.com/en-us/entra/identity/conditional-access/",
    },
    "mapping_metadata": {
        "created_utc": "2026-05-27T12:30:00Z",
        "author": "rejewski",
        "schema_version": "0.1",
        "status": "active",
    },
}


def test_all_samples_validate():
    files = sorted(SAMPLES_DIR.glob("*.json"))
    assert files, "no samples found under samples/finding-to-control/"
    for path in files:
        _VALIDATOR.validate(json.loads(path.read_text()))


def test_missing_required_field_fails():
    with pytest.raises(Exception):
        _VALIDATOR.validate({"mapping_id": "ft1087-004-ca-test-001"})


def test_wrong_schema_version_fails():
    import copy
    payload = copy.deepcopy(_VALID_PAYLOAD)
    payload["mapping_metadata"]["schema_version"] = "0.2"
    with pytest.raises(Exception):
        _VALIDATOR.validate(payload)

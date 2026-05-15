import json
from pathlib import Path
from unittest.mock import patch

import pytest

import replay_log
from replay_log import (
    ReplayLogEntry,
    SANDBOX_TENANT_ID,
    _VALIDATOR,
    write_entry,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = REPO_ROOT / "samples" / "replay-log"
BAD_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "bad-entries"


def _valid_entry(**overrides):
    base = dict(
        tool="tool_list_users",
        technique_id="T1087.004",
        technique_name="Account Discovery: Cloud Account",
        tenant_id=SANDBOX_TENANT_ID,
        borrowed_client_id="14d82eec-204b-4c2f-b7e8-296a70dab67e",
        actor_upn="meganb@cloudharbor-demo.com",
        started_at_utc="2026-05-15T14:30:15.000000Z",
        completed_at_utc="2026-05-15T14:30:16.000000Z",
        request={"method": "GET", "url": "https://graph.microsoft.com/v1.0/users"},
        response={"status": 200, "body": {"value": []}},
        outcome="success",
        entry_id="a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    )
    base.update(overrides)
    return ReplayLogEntry(**base)


class TestSchemaFidelity:
    def test_committed_samples_validate(self):
        files = sorted(SAMPLES.glob("*.json"))
        assert files, "no committed samples found under samples/replay-log/"
        for path in files:
            payload = json.loads(path.read_text())
            _VALIDATOR.validate(payload)

    def test_bad_fixtures_fail_validation(self):
        files = sorted(BAD_FIXTURES.glob("*.json"))
        assert files, "no bad fixtures found under tests/fixtures/bad-entries/"
        for path in files:
            payload = json.loads(path.read_text())
            with pytest.raises(Exception):
                _VALIDATOR.validate(payload)


class TestRoundTrip:
    def test_write_then_read_equals_source(self, tmp_path):
        entry = _valid_entry()
        written = write_entry(entry, log_dir=tmp_path)
        loaded = json.loads(written.read_text())
        _VALIDATOR.validate(loaded)
        assert loaded == entry.to_dict()


class TestRefusal:
    def test_overwrite_refused(self, tmp_path):
        entry = _valid_entry()
        write_entry(entry, log_dir=tmp_path)
        with pytest.raises(FileExistsError):
            write_entry(entry, log_dir=tmp_path)

    def test_missing_borrowed_client_id_refused(self, tmp_path):
        entry = _valid_entry(borrowed_client_id="")
        with pytest.raises(ValueError, match="borrowed_client_id"):
            write_entry(entry, log_dir=tmp_path)

    def test_wrong_tenant_refused(self, tmp_path):
        entry = _valid_entry(tenant_id="00000000-0000-0000-0000-000000000000")
        with pytest.raises(ValueError, match="tenant"):
            write_entry(entry, log_dir=tmp_path)


class TestScrubbing:
    def test_authorization_header_scrubbed(self, tmp_path):
        secret = "SHOULDNOTPERSIST_TOKEN_VALUE"
        entry = _valid_entry(
            request={
                "method": "GET",
                "url": "https://graph.microsoft.com/v1.0/users",
                "headers": {
                    "Authorization": f"Bearer {secret}",
                    "User-Agent": "rejewski-tool-list-users/0.1",
                },
            },
        )
        path = write_entry(entry, log_dir=tmp_path)
        raw = path.read_text()
        assert secret not in raw
        assert "Authorization" not in raw

    def test_response_access_token_scrubbed(self, tmp_path):
        secret = "eyJleHRyZW1lbHlzZWNyZXR0b2tlbnZhbHVl"
        entry = _valid_entry(
            response={
                "status": 200,
                "body": {
                    "value": [{"displayName": "Adele"}],
                    "access_token": secret,
                },
            },
        )
        path = write_entry(entry, log_dir=tmp_path)
        assert secret not in path.read_text()

    def test_nested_credentials_scrubbed(self, tmp_path):
        secret = "hunter2-nested-password"
        entry = _valid_entry(
            response={
                "status": 200,
                "body": {"value": [{"credentials": {"password": secret}}]},
            },
        )
        path = write_entry(entry, log_dir=tmp_path)
        assert secret not in path.read_text()


class TestDeterminism:
    def test_fixed_inputs_produce_fixed_filename(self, tmp_path):
        entry = _valid_entry()
        path = write_entry(entry, log_dir=tmp_path)
        assert path.name == "20260515T143015Z-a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d.json"

    def test_tempfile_removed_on_exception(self, tmp_path):
        entry = _valid_entry()
        with patch("replay_log.os.replace", side_effect=OSError("boom")):
            with pytest.raises(OSError, match="boom"):
                write_entry(entry, log_dir=tmp_path)
        leftovers = list(tmp_path.glob(".tmp-*"))
        assert leftovers == [], f"temp files not cleaned up: {leftovers}"
        finals = list(tmp_path.glob("*.json"))
        assert finals == [], f"final file written despite write failure: {finals}"
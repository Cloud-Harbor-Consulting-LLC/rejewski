import json
from pathlib import Path

import pytest

from replay_log import (
    REDACTED,
    ReplayLogEntry,
    SANDBOX_TENANT_ID,
    SCHEMA_VERSION,
    _VALIDATOR,
    make_error,
    redact_tenant_id,
    write_entry,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = REPO_ROOT / "samples" / "replay-log"
GOOD_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "entries"
BAD_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "bad-entries"


def _valid_entry(**overrides):
    base = dict(
        kind="graph_call",
        tool="tool_list_users",
        technique_id="T1087.004",
        technique_name="Account Discovery: Cloud Account",
        tenant_id=SANDBOX_TENANT_ID,
        borrowed_client_id="14d82eec-204b-4c2f-b7e8-296a70dab67e",
        actor_upn="meganb@cloudharbor-demo.com",
        started_at_utc="2026-05-15T14:30:15.000000Z",
        completed_at_utc="2026-05-15T14:30:16.000000Z",
        request={"method": "GET", "url": "https://graph.microsoft.com/v1.0/users"},
        response={
            "status_code": 200,
            "page_count": 1,
            "row_count": 0,
            "row_cap": 1000,
            "row_cap_hit": False,
            "retry_count": 0,
        },
        outcome="success",
        entry_id="a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    )
    base.update(overrides)
    return ReplayLogEntry(**base)


class TestSchemaFidelity:
    def test_schema_version_constant(self):
        assert SCHEMA_VERSION == "0.5"

    def test_committed_samples_validate(self):
        files = sorted(SAMPLES.glob("*.json"))
        assert files, "no committed samples found under samples/replay-log/"
        for path in files:
            payload = json.loads(path.read_text())
            if isinstance(payload, list):
                # R00N.json arrays: skip consent records, validate replay entries
                for item in payload:
                    if isinstance(item, dict) and "event" in item and "schema_version" not in item:
                        continue  # consent.granted / consent.declined — separate schema
                    _VALIDATOR.validate(item)
            else:
                _VALIDATOR.validate(payload)

    def test_good_fixtures_validate(self):
        files = sorted(GOOD_FIXTURES.glob("*.json"))
        assert files, "no good fixtures found under tests/fixtures/entries/"
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
        assert loaded["technique"] == {
            "id": "T1087.004",
            "name": "Account Discovery: Cloud Account",
        }
        assert loaded["schema_version"] == "0.5"
        assert loaded["kind"] == "graph_call"
        assert loaded["response"] == {
            "status_code": 200,
            "page_count": 1,
            "row_count": 0,
            "row_cap": 1000,
            "row_cap_hit": False,
            "retry_count": 0,
        }


class TestModelId:
    def test_model_id_present_round_trips(self, tmp_path):
        entry = _valid_entry(model_id="claude-opus-4-6")
        written = write_entry(entry, log_dir=tmp_path)
        loaded = json.loads(written.read_text())
        _VALIDATOR.validate(loaded)
        assert loaded["model_id"] == "claude-opus-4-6"

    def test_model_id_omitted_when_none(self, tmp_path):
        entry = _valid_entry()  # model_id defaults to None
        written = write_entry(entry, log_dir=tmp_path)
        loaded = json.loads(written.read_text())
        _VALIDATOR.validate(loaded)
        assert "model_id" not in loaded


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

    def test_unknown_outcome_refused(self, tmp_path):
        entry = _valid_entry(outcome="pending")
        with pytest.raises(ValueError, match="outcome"):
            write_entry(entry, log_dir=tmp_path)

    def test_unknown_kind_refused(self, tmp_path):
        entry = _valid_entry()
        entry.kind = "graph_callz"
        with pytest.raises(ValueError, match="kind"):
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

    def test_request_body_credentials_scrubbed(self, tmp_path):
        # GET method: a graph_call is read-only (write_entry now enforces GET),
        # and the scrubber under test is method-agnostic — it drops nested
        # credentials wherever they appear in the request dict.
        secret = "hunter2-nested-password"
        entry = _valid_entry(
            request={
                "method": "GET",
                "url": "https://graph.microsoft.com/v1.0/users",
                "body": {"credentials": {"password": secret}},
            },
        )
        path = write_entry(entry, log_dir=tmp_path)
        assert secret not in path.read_text()

    def test_response_body_dropped_entirely(self, tmp_path):
        secret = "eyJleHRyZW1lbHlzZWNyZXR0b2tlbnZhbHVl"
        entry = _valid_entry(
            response={
                "status_code": 200,
                "page_count": 1,
                "row_count": 1,
                "row_cap": 1000,
                "row_cap_hit": False,
                "retry_count": 0,
                "body": {"value": [{"access_token": secret}]},
            },
        )
        path = write_entry(entry, log_dir=tmp_path)
        written = json.loads(path.read_text())
        assert "body" not in written["response"]
        assert secret not in path.read_text()

    def test_tenant_guid_redacted_in_error_message(self, tmp_path):
        entry = _valid_entry(
            outcome="error",
            error=make_error(
                type_=f"https://login.microsoftonline.com/{SANDBOX_TENANT_ID}/oauth2/error",
                message=(
                    f"User principal could not be authorized in tenant {SANDBOX_TENANT_ID}."
                ),
                status_code=403,
            ),
        )
        path = write_entry(entry, log_dir=tmp_path)
        written = json.loads(path.read_text())

        assert SANDBOX_TENANT_ID not in written["error"]["type"]
        assert SANDBOX_TENANT_ID not in written["error"]["message"]
        assert REDACTED in written["error"]["type"]
        assert REDACTED in written["error"]["message"]
        assert written["error"]["status_code"] == 403

        assert written["tenant_id"] == SANDBOX_TENANT_ID
        assert written["borrowed_client_id"] == "14d82eec-204b-4c2f-b7e8-296a70dab67e"
        assert SANDBOX_TENANT_ID not in path.read_text().replace(
            f'"tenant_id": "{SANDBOX_TENANT_ID}"', ""
        )

class TestRedactTenantId:
    """The shared helper that tools route their evidence tenant_id through so the
    sandbox GUID is not emitted to stdout. The replay-log ENTRY still carries the
    real tenant_id (TestScrubbing above covers that G-1 requirement)."""

    def test_sandbox_tenant_is_redacted(self):
        assert redact_tenant_id(SANDBOX_TENANT_ID) == REDACTED
        assert redact_tenant_id(SANDBOX_TENANT_ID) != SANDBOX_TENANT_ID

    def test_other_tenant_passes_through(self):
        other = "11111111-2222-3333-4444-555555555555"
        assert redact_tenant_id(other) == other

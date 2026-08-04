"""Tests for scripts/tool_list_inbox_rules.py (Tool 13, T1114.002 Surface A).

Mocks the Graph HTTP layer (requests.get) and the token helper
(identity.acquire_token) so the tool runs offline. Covers the happy path,
empty mailbox, forwarding- and deletion-rule serialization, row-cap
enforcement, 429 retry exhaustion, 401 mid-run recovery, tenant-GUID
scrubbing of the evidence output, replay-log entry schema validity, and the
--user-id endpoint construction.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import identity  # noqa: E402
import tool_list_inbox_rules as tool  # noqa: E402
from replay_log import (  # noqa: E402
    SANDBOX_TENANT_ID,
    SCHEMA_PATH,
    _load_schema,
)
from jsonschema import Draft202012Validator, FormatChecker  # noqa: E402

ACTOR_UPN = "meganb@cloudharbor-demo.com"
_VALIDATOR = Draft202012Validator(_load_schema(), format_checker=FormatChecker())


class FakeResp:
    def __init__(self, status_code: int, body: dict, headers: dict | None = None):
        self.status_code = status_code
        self._body = body
        self.headers = headers or {}
        self.text = json.dumps(body)

    def json(self) -> dict:
        return self._body


def _rule(idx: int, **overrides) -> dict:
    base = {
        "id": f"rule-{idx}",
        "displayName": f"Rule {idx}",
        "sequence": idx,
        "isEnabled": True,
        "hasError": False,
        "conditions": {},
        "actions": {"moveToFolder": None},
    }
    base.update(overrides)
    return base


def _recips(*addresses: str) -> list[dict]:
    return [{"emailAddress": {"name": a.split("@")[0], "address": a}} for a in addresses]


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZURE_TENANT_ID", SANDBOX_TENANT_ID)
    monkeypatch.setenv("FOCI_CLIENT_ID", identity.DEFAULT_CLIENT_ID)
    monkeypatch.setenv("COMPROMISED_USER_UPN", ACTOR_UPN)
    monkeypatch.delenv("COMPROMISED_USER_PASSWORD", raising=False)


def _read_graph_calls(replay_dir: Path) -> list[dict]:
    entries = []
    for fp in sorted(replay_dir.glob("*.json")):
        entries.append(json.loads(fp.read_text(encoding="utf-8")))
    return [e for e in entries if e.get("kind") == "graph_call"]


def _run(monkeypatch, env, tmp_path, responses, extra_args=None, run_id="INBOX-TEST"):
    replay_dir = tmp_path / "replay-logs"
    replay_dir.mkdir()
    argv = [
        "tool_list_inbox_rules.py",
        "--replay-log-dir", str(replay_dir),
        "--run-id", run_id,
    ] + list(extra_args or [])
    monkeypatch.setattr(sys, "argv", argv)
    getmock = mock.MagicMock(side_effect=responses)
    with mock.patch(
        "identity.acquire_token", return_value={"access_token": "AT_test"}
    ), mock.patch("requests.get", getmock):
        rc = tool.main()
    return rc, replay_dir, getmock


class TestHappyPath:
    def test_returns_rules(self, monkeypatch, env, tmp_path, capsys):
        body = {"value": [_rule(1), _rule(2, isEnabled=False)]}
        rc, replay_dir, _ = _run(monkeypatch, env, tmp_path, [FakeResp(200, body)])

        assert rc == 0
        entry = _read_graph_calls(replay_dir)[0]
        assert entry["technique"]["id"] == "T1114.002"
        assert entry["tool"] == "tool_list_inbox_rules"
        assert entry["request"]["method"] == "GET"
        assert "/mailFolders/inbox/messageRules" in entry["request"]["url"]
        assert entry["response"]["row_count"] == 2
        assert entry["outcome"] == "success"

        out = json.loads(capsys.readouterr().out)
        assert out["rule_count"] == 2
        assert out["user_id"] == "me"
        assert len(out["rules"]) == 2
        assert out["rules"][0]["id"] == "rule-1"
        assert out["rules"][1]["isEnabled"] is False


class TestEmptyMailbox:
    def test_no_rules_is_not_error(self, monkeypatch, env, tmp_path, capsys):
        rc, replay_dir, _ = _run(
            monkeypatch, env, tmp_path, [FakeResp(200, {"value": []})]
        )

        assert rc == 0
        entry = _read_graph_calls(replay_dir)[0]
        assert entry["response"]["row_count"] == 0
        assert entry["outcome"] == "success"

        captured = capsys.readouterr()
        assert "No inbox rules found" in captured.err
        out = json.loads(captured.out)
        assert out["rule_count"] == 0
        assert out["rules"] == []


class TestForwardingRule:
    def test_forward_to_serialized(self, monkeypatch, env, tmp_path, capsys):
        body = {
            "value": [
                _rule(
                    1,
                    actions={
                        "forwardTo": _recips("exfil@attacker.example"),
                        "moveToFolder": None,
                    },
                    conditions={"senderContains": ["ceo"]},
                )
            ]
        }
        rc, _, _ = _run(monkeypatch, env, tmp_path, [FakeResp(200, body)])

        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        rule = out["rules"][0]
        # External forwarding target extracted as a plain address (high signal).
        assert rule["actions"]["forwardTo"] == ["exfil@attacker.example"]
        assert rule["actions"]["delete"] is False
        assert rule["conditions"]["senderContains"] == ["ceo"]


class TestDeletionRule:
    def test_delete_action_serialized(self, monkeypatch, env, tmp_path, capsys):
        body = {
            "value": [
                _rule(
                    1,
                    actions={"delete": True, "moveToFolder": "RSS Feeds"},
                )
            ]
        }
        rc, _, _ = _run(monkeypatch, env, tmp_path, [FakeResp(200, body)])

        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        rule = out["rules"][0]
        assert rule["actions"]["delete"] is True
        assert rule["actions"]["moveToFolder"] == "RSS Feeds"
        assert rule["actions"]["forwardTo"] == []


class TestRowCap:
    def test_row_cap_hit(self, monkeypatch, env, tmp_path, capsys):
        body = {"value": [_rule(i) for i in range(1, 6)]}
        rc, replay_dir, _ = _run(
            monkeypatch, env, tmp_path, [FakeResp(200, body)],
            extra_args=["--row-cap", "3"],
        )

        assert rc == 0
        entry = _read_graph_calls(replay_dir)[0]
        assert entry["response"]["row_count"] == 3
        assert entry["response"]["row_cap"] == 3
        assert entry["response"]["row_cap_hit"] is True
        assert entry["outcome"] == "row_cap_hit"

        out = json.loads(capsys.readouterr().out)
        assert out["rule_count"] == 3
        assert out["row_cap_hit"] is True


class TestRetry:
    def test_429_exhausts_and_errors(self, monkeypatch, env, tmp_path, capsys):
        # Three 429s in a row -> max retries hit -> RuntimeError -> outcome error.
        throttled = FakeResp(429, {"error": "throttled"}, headers={"Retry-After": "0"})
        with mock.patch("time.sleep"):  # don't actually wait on Retry-After
            rc, replay_dir, getmock = _run(
                monkeypatch, env, tmp_path, [throttled, throttled, throttled]
            )

        assert rc == 1
        assert getmock.call_count == 3  # MAX_RETRIES attempts
        entry = _read_graph_calls(replay_dir)[0]
        assert entry["outcome"] == "error"
        assert entry["response"]["row_count"] == 0


class TestUnauthorizedRecovery:
    def test_401_then_success(self, monkeypatch, env, tmp_path, capsys):
        # First call 401 -> token_getter re-invoked -> retry succeeds.
        rc, replay_dir, getmock = _run(
            monkeypatch, env, tmp_path,
            [FakeResp(401, {"error": "invalid_token"}), FakeResp(200, {"value": [_rule(1)]})],
        )

        assert rc == 0
        assert getmock.call_count == 2  # 401, then the recovered GET
        entry = _read_graph_calls(replay_dir)[0]
        assert entry["outcome"] == "success"
        assert entry["response"]["row_count"] == 1
        assert entry["response"]["retry_count"] == 1


class TestScrubbing:
    def test_no_tenant_guid_in_evidence(self, monkeypatch, env, tmp_path, capsys):
        body = {"value": [_rule(1, actions={"forwardTo": _recips("x@y.example")})]}
        rc, _, _ = _run(monkeypatch, env, tmp_path, [FakeResp(200, body)])

        assert rc == 0
        raw = capsys.readouterr().out
        assert SANDBOX_TENANT_ID not in raw  # tenant GUID redacted from evidence
        assert json.loads(raw)["tenant_id"] != SANDBOX_TENANT_ID


class TestReplayLogSchemaValid:
    def test_entry_validates_against_v05(self, monkeypatch, env, tmp_path):
        assert SCHEMA_PATH.name == "v0.5.json"
        rc, replay_dir, _ = _run(
            monkeypatch, env, tmp_path, [FakeResp(200, {"value": [_rule(1)]})]
        )
        assert rc == 0
        entry = _read_graph_calls(replay_dir)[0]
        # No error is raised iff the entry is schema-valid.
        _VALIDATOR.validate(entry)


class TestUserIdFlag:
    def test_cross_user_endpoint(self, monkeypatch, env, tmp_path, capsys):
        uid = "11111111-2222-3333-4444-555555555555"
        rc, replay_dir, getmock = _run(
            monkeypatch, env, tmp_path, [FakeResp(200, {"value": []})],
            extra_args=["--user-id", uid],
        )

        assert rc == 0
        called_url = getmock.call_args_list[0].args[0]
        assert f"/users/{uid}/mailFolders/inbox/messageRules" in called_url
        assert "/me/" not in called_url
        assert json.loads(capsys.readouterr().out)["user_id"] == uid

    def test_default_me_endpoint(self, monkeypatch, env, tmp_path):
        rc, replay_dir, getmock = _run(
            monkeypatch, env, tmp_path, [FakeResp(200, {"value": []})]
        )
        assert rc == 0
        called_url = getmock.call_args_list[0].args[0]
        assert "/me/mailFolders/inbox/messageRules" in called_url
        assert "/users/" not in called_url

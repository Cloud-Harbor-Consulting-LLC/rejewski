# SPDX-License-Identifier: MIT
"""Tests for scripts/tool_signin_logs.py (Tool 10, T1654 sign-in logs).

Mocks the Graph HTTP layer (requests.get) and the token helper
(identity.acquire_token) so the tool runs offline. Covers a single-page
successful list with the mandatory date filter, an empty-window response, and
multi-page @odata.nextLink pagination.
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
import tool_signin_logs  # noqa: E402
from lab_values import LAB_TENANT_ID  # noqa: E402

ACTOR_UPN = "meganb@lab.example"


class FakeResp:
    def __init__(self, status_code: int, body: dict, headers: dict | None = None):
        self.status_code = status_code
        self._body = body
        self.headers = headers or {}
        self.text = json.dumps(body)

    def json(self) -> dict:
        return self._body


def _signin(idx: int, **overrides) -> dict:
    base = {
        "id": f"signin-{idx}",
        "createdDateTime": f"2026-06-22T1{idx}:00:00Z",
        "userDisplayName": f"User {idx}",
        "userPrincipalName": f"user{idx}@lab.example",
        "userId": f"user-id-{idx}",
        "appId": "app-id",
        "appDisplayName": "Microsoft Teams",
        "ipAddress": f"10.0.0.{idx}",
        "clientAppUsed": "Browser",
        "isInteractive": True,
        "riskLevelAggregated": "none",
        "riskState": "none",
        "status": {"errorCode": 0},
    }
    base.update(overrides)
    return base


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZURE_TENANT_ID", LAB_TENANT_ID)
    monkeypatch.setenv("FOCI_CLIENT_ID", identity.DEFAULT_CLIENT_ID)
    monkeypatch.setenv("COMPROMISED_USER_UPN", ACTOR_UPN)
    monkeypatch.delenv("COMPROMISED_USER_PASSWORD", raising=False)


def _read_graph_calls(replay_dir: Path) -> list[dict]:
    entries = []
    for fp in sorted(replay_dir.glob("*.json")):
        entries.append(json.loads(fp.read_text(encoding="utf-8")))
    return [e for e in entries if e.get("kind") == "graph_call"]


def _run(monkeypatch, env, tmp_path, responses, run_id="SIGNIN-TEST", days=7):
    replay_dir = tmp_path / "replay-logs"
    replay_dir.mkdir()
    argv = [
        "tool_signin_logs.py",
        "--replay-log-dir", str(replay_dir),
        "--run-id", run_id,
        "--days", str(days),
    ]
    monkeypatch.setattr(sys, "argv", argv)
    with mock.patch(
        "identity.acquire_token", return_value={"access_token": "AT_test"}
    ), mock.patch("requests.get", side_effect=responses):
        rc = tool_signin_logs.main()
    return rc, replay_dir


class TestSuccessfulList:
    def test_single_page_writes_entry(self, monkeypatch, env, tmp_path, capsys):
        body = {
            "value": [
                _signin(1),
                _signin(
                    2,
                    isInteractive=False,
                    riskLevelAggregated="medium",
                    status={"errorCode": 50126},
                    appDisplayName="OneDrive",
                ),
            ]
        }
        rc, replay_dir = _run(monkeypatch, env, tmp_path, [FakeResp(200, body)])

        assert rc == 0
        calls = _read_graph_calls(replay_dir)
        assert len(calls) == 1
        entry = calls[0]
        assert entry["technique"]["id"] == "T1654"
        assert entry["tool"] == "tool_signin_logs"
        assert entry["request"]["method"] == "GET"
        url = entry["request"]["url"]
        assert "/auditLogs/signIns" in url
        # createdDateTime is URL-encoded inside the $filter clause.
        assert "createdDateTime" in url
        assert entry["response"]["status_code"] == 200
        assert entry["response"]["row_count"] == 2  # object_count
        assert entry["outcome"] == "success"
        assert entry["run_id"] == "SIGNIN-TEST"

        out = json.loads(capsys.readouterr().out)
        assert out["row_count"] == 2
        assert out["total_sign_ins"] == 2
        assert out["failed_count"] == 1
        assert out["by_risk_level"]["medium"] == 1
        assert out["interactive_count"] == 1
        assert out["non_interactive_count"] == 1
        assert out["unique_apps"] == 2
        assert out["unique_users"] == 2
        assert "createdDateTime ge" in out["filter"]


class TestEmptyList:
    def test_empty_is_not_error(self, monkeypatch, env, tmp_path, capsys):
        rc, replay_dir = _run(
            monkeypatch, env, tmp_path, [FakeResp(200, {"value": []})]
        )

        assert rc == 0
        calls = _read_graph_calls(replay_dir)
        assert len(calls) == 1
        assert calls[0]["response"]["row_count"] == 0  # object_count: 0
        assert calls[0]["outcome"] == "success"

        captured = capsys.readouterr()
        assert "No sign-ins found for the specified period" in captured.err
        assert json.loads(captured.out)["row_count"] == 0


class TestPagination:
    def test_follows_nextlink_across_pages(self, monkeypatch, env, tmp_path, capsys):
        next_url = (
            "https://graph.microsoft.com/v1.0/auditLogs/signIns"
            "?$skiptoken=PAGE2"
        )
        page1 = {
            "value": [_signin(1), _signin(2)],
            "@odata.nextLink": next_url,
        }
        page2 = {"value": [_signin(3)]}  # no nextLink -> stop
        rc, replay_dir = _run(
            monkeypatch, env, tmp_path, [FakeResp(200, page1), FakeResp(200, page2)]
        )

        assert rc == 0
        calls = _read_graph_calls(replay_dir)
        assert len(calls) == 1
        entry = calls[0]
        # All three sign-ins across both pages, page_count == 2.
        assert entry["response"]["row_count"] == 3  # total object_count
        assert entry["response"]["page_count"] == 2

        out = json.loads(capsys.readouterr().out)
        assert out["row_count"] == 3
        assert len(out["sign_ins"]) == 3
        assert {s["id"] for s in out["sign_ins"]} == {
            "signin-1", "signin-2", "signin-3"
        }

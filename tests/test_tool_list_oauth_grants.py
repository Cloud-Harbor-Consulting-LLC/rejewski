# SPDX-License-Identifier: MIT
"""Tests for scripts/tool_list_oauth_grants.py (Tool 11, T1087.004 Surface E).

Mocks the Graph HTTP layer (requests.get) and the token helper
(identity.acquire_token) so the tool runs offline. Covers a single-page
successful list, an empty-grants response, multi-page @odata.nextLink
pagination, and the evidence aggregate computation (admin/user consent split
and the high-privilege scope flag).
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
import tool_list_oauth_grants  # noqa: E402
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


def _grant(idx: int, **overrides) -> dict:
    base = {
        "id": f"grant-{idx}",
        "clientId": f"client-sp-{idx}",
        "resourceId": "resource-sp-graph",
        "consentType": "AllPrincipals",
        "principalId": None,
        "scope": "User.Read openid profile",
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


def _run(monkeypatch, env, tmp_path, responses, run_id="OAUTH-TEST"):
    replay_dir = tmp_path / "replay-logs"
    replay_dir.mkdir()
    argv = [
        "tool_list_oauth_grants.py",
        "--replay-log-dir", str(replay_dir),
        "--run-id", run_id,
    ]
    monkeypatch.setattr(sys, "argv", argv)
    with mock.patch(
        "identity.acquire_token", return_value={"access_token": "AT_test"}
    ), mock.patch("requests.get", side_effect=responses):
        rc = tool_list_oauth_grants.main()
    return rc, replay_dir


class TestSuccessfulList:
    def test_single_page_writes_entry(self, monkeypatch, env, tmp_path, capsys):
        body = {
            "value": [
                _grant(1),
                _grant(
                    2,
                    consentType="Principal",
                    principalId="user-id-2",
                    scope="Mail.Read offline_access",
                ),
            ]
        }
        rc, replay_dir = _run(monkeypatch, env, tmp_path, [FakeResp(200, body)])

        assert rc == 0
        calls = _read_graph_calls(replay_dir)
        assert len(calls) == 1
        entry = calls[0]
        assert entry["technique"]["id"] == "T1087.004"
        assert entry["technique"]["name"] == "Account Discovery: Cloud Account"
        assert entry["tool"] == "tool_list_oauth_grants"
        assert entry["request"]["method"] == "GET"
        assert "/oauth2PermissionGrants" in entry["request"]["url"]
        assert entry["response"]["status_code"] == 200
        assert entry["response"]["row_count"] == 2  # object_count
        assert entry["outcome"] == "success"
        assert entry["run_id"] == "OAUTH-TEST"

        out = json.loads(capsys.readouterr().out)
        assert out["row_count"] == 2
        assert out["grants_total_count"] == 2


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
        assert "No OAuth2 permission grants found" in captured.err
        assert json.loads(captured.out)["row_count"] == 0
        assert json.loads(captured.out)["grants_total_count"] == 0


class TestPagination:
    def test_follows_nextlink_across_pages(self, monkeypatch, env, tmp_path, capsys):
        next_url = (
            "https://graph.microsoft.com/v1.0/oauth2PermissionGrants"
            "?$skiptoken=PAGE2"
        )
        page1 = {
            "value": [_grant(1), _grant(2)],
            "@odata.nextLink": next_url,
        }
        page2 = {"value": [_grant(3)]}  # no nextLink -> stop
        rc, replay_dir = _run(
            monkeypatch, env, tmp_path, [FakeResp(200, page1), FakeResp(200, page2)]
        )

        assert rc == 0
        calls = _read_graph_calls(replay_dir)
        assert len(calls) == 1
        entry = calls[0]
        # All three grants across both pages, page_count == 2.
        assert entry["response"]["row_count"] == 3  # total object_count
        assert entry["response"]["page_count"] == 2

        out = json.loads(capsys.readouterr().out)
        assert out["row_count"] == 3
        assert len(out["grants"]) == 3
        assert {g["id"] for g in out["grants"]} == {
            "grant-1", "grant-2", "grant-3"
        }


class TestEvidenceAggregates:
    def test_consent_split_and_high_privilege_flag(
        self, monkeypatch, env, tmp_path, capsys
    ):
        body = {
            "value": [
                # admin-consented, high-privilege (Directory.ReadWrite.All)
                _grant(
                    1,
                    consentType="AllPrincipals",
                    scope="User.Read Directory.ReadWrite.All",
                ),
                # admin-consented, NOT high-privilege
                _grant(
                    2,
                    consentType="AllPrincipals",
                    clientId="client-sp-2",
                    scope="User.Read openid",
                ),
                # user-consented, high-privilege (Mail.Read, case-insensitive)
                _grant(
                    3,
                    consentType="Principal",
                    principalId="user-id-3",
                    clientId="client-sp-3",
                    resourceId="resource-sp-exo",
                    scope="offline_access mail.read",
                ),
            ]
        }
        rc, _ = _run(monkeypatch, env, tmp_path, [FakeResp(200, body)])

        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["grants_total_count"] == 3
        assert out["grants_admin_consented_count"] == 2
        assert out["grants_user_consented_count"] == 1
        # Two grants carry a high-privilege scope (grant 1 and grant 3).
        assert out["grants_high_privilege_count"] == 2
        # Three distinct client SPs, two distinct resource SPs.
        assert out["unique_client_sp_count"] == 3
        assert out["unique_resource_sp_count"] == 2

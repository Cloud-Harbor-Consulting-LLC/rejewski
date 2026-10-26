# SPDX-License-Identifier: MIT
"""Tests for scripts/tool_list_role_assignments.py (Tool 5, T1087.004 Surface C).

Covers the B030 fix: Graph v1.0 rejects $expand=principal,roleDefinition with
HTTP 400, so Surface C now issues two sequential paginated GET calls (one
$expand property each) and merges the results on assignment id. Mocks the Graph
HTTP layer (requests.get) and the token helper (identity.acquire_token) so the
tool runs offline.
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
import tool_list_role_assignments  # noqa: E402
from replay_log import SANDBOX_TENANT_ID  # noqa: E402

ACTOR_UPN = "meganb@cloudharbor-demo.com"


class FakeResp:
    def __init__(self, status_code: int, body: dict, headers: dict | None = None):
        self.status_code = status_code
        self._body = body
        self.headers = headers or {}
        self.text = json.dumps(body)

    def json(self) -> dict:
        return self._body


def _assignment_principal(idx: int, **overrides) -> dict:
    """An assignment as returned by call 1 ($expand=principal)."""
    base = {
        "id": f"assign-{idx}",
        "principalId": f"principal-{idx}",
        "roleDefinitionId": f"roledef-{idx}",
        "directoryScopeId": "/",
        "principal": {
            "displayName": f"Principal {idx}",
            "userType": "Member",
        },
    }
    base.update(overrides)
    return base


def _assignment_role_def(idx: int, role_name: str, **overrides) -> dict:
    """The same assignment as returned by call 2 ($expand=roleDefinition)."""
    base = {
        "id": f"assign-{idx}",
        "principalId": f"principal-{idx}",
        "roleDefinitionId": f"roledef-{idx}",
        "directoryScopeId": "/",
        "roleDefinition": {"displayName": role_name},
    }
    base.update(overrides)
    return base


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


def _run(monkeypatch, env, tmp_path, responses, run_id="RA-TEST"):
    replay_dir = tmp_path / "replay-logs"
    replay_dir.mkdir()
    argv = [
        "tool_list_role_assignments.py",
        "--replay-log-dir", str(replay_dir),
        "--run-id", run_id,
    ]
    monkeypatch.setattr(sys, "argv", argv)
    getmock = mock.MagicMock(side_effect=responses)
    with mock.patch(
        "identity.acquire_token", return_value={"access_token": "AT_test"}
    ), mock.patch("requests.get", getmock):
        rc = tool_list_role_assignments.main()
    return rc, replay_dir, getmock


class TestTwoCallMerge:
    def test_merges_principal_and_role_definition(
        self, monkeypatch, env, tmp_path, capsys
    ):
        # Call 1 ($expand=principal), call 2 ($expand=roleDefinition), single page each.
        call1 = {"value": [_assignment_principal(1)]}
        call2 = {"value": [_assignment_role_def(1, "Global Administrator")]}
        rc, replay_dir, getmock = _run(
            monkeypatch, env, tmp_path, [FakeResp(200, call1), FakeResp(200, call2)]
        )

        assert rc == 0

        # B030: two sequential GET calls, each with exactly one $expand property.
        # Parse the $expand clause specifically — the $select list contains
        # "roleDefinitionId"/"principalId", so a naive substring test on the whole
        # URL would give false matches.
        import re

        def _expand_of(url: str) -> str | None:
            m = re.search(r"[?&]\$expand=([^&]*)", url)
            return m.group(1) if m else None

        assert getmock.call_count == 2
        url1 = getmock.call_args_list[0].args[0]
        url2 = getmock.call_args_list[1].args[0]
        assert _expand_of(url1) == "principal"
        assert _expand_of(url2) == "roleDefinition"

        # Replay entry: outcome success, one merged assignment.
        calls = _read_graph_calls(replay_dir)
        assert len(calls) == 1
        entry = calls[0]
        assert entry["technique"]["id"] == "T1087.004"
        assert entry["tool"] == "tool_list_role_assignments"
        assert entry["response"]["status_code"] == 200
        assert entry["response"]["row_count"] == 1
        assert entry["response"]["page_count"] == 2  # one page per call
        assert entry["outcome"] == "success"

        # AC2: each merged assignment carries BOTH principal and roleDefinition.
        out = json.loads(capsys.readouterr().out)
        assert out["row_count"] == 1
        merged = out["role_assignments"][0]
        assert merged["principal"]["displayName"] == "Principal 1"
        assert merged["roleDefinition"]["displayName"] == "Global Administrator"
        assert merged["roleDefinitionId"] == "roledef-1"

    def test_aggregates_from_merged_data(self, monkeypatch, env, tmp_path, capsys):
        # Two assignments: one Global Administrator (Member), one Guest reader.
        call1 = {
            "value": [
                _assignment_principal(1),
                _assignment_principal(
                    2, principal={"displayName": "Guest User", "userType": "Guest"}
                ),
            ]
        }
        call2 = {
            "value": [
                _assignment_role_def(1, "Global Administrator"),
                _assignment_role_def(2, "Directory Readers"),
            ]
        }
        rc, _, _ = _run(
            monkeypatch, env, tmp_path, [FakeResp(200, call1), FakeResp(200, call2)]
        )

        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        # AC4: aggregates reflect BOTH principal (guest) and roleDefinition (role name).
        assert out["ra_global_admin_count"] == 1
        assert out["ra_high_privilege_count"] == 1  # Global Administrator only
        assert out["ra_external_principal_count"] == 1  # the Guest
        assert out["ra_unique_roles"] == 2
        assert out["ra_unique_principals"] == 2
        assert out["ra_tenant_wide_scope_count"] == 2  # both directoryScopeId "/"


class TestEmptyList:
    def test_empty_is_not_error(self, monkeypatch, env, tmp_path, capsys):
        rc, replay_dir, _ = _run(
            monkeypatch, env, tmp_path,
            [FakeResp(200, {"value": []}), FakeResp(200, {"value": []})],
        )

        assert rc == 0
        calls = _read_graph_calls(replay_dir)
        assert len(calls) == 1
        assert calls[0]["response"]["row_count"] == 0
        assert calls[0]["outcome"] == "success"

        captured = capsys.readouterr()
        assert "No role assignments found" in captured.err
        assert json.loads(captured.out)["row_count"] == 0

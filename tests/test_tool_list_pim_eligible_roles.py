# SPDX-License-Identifier: MIT
"""Tests for scripts/tool_list_pim_eligible_roles.py (Tool 15, T1087.004 Surface F).

Covers the PIM-eligible role enumeration tool: a single paginated GET against
roleEligibilityScheduleInstances with one $expand (roleDefinition), the
eligible-for-Global-Admin flag (by resolved name and by well-known roleTemplateId),
the permanent-vs-time-bound split, the empty-result path, and the HTTP 403
permission-gap path (a documented sandbox-config finding, not a crash). Mocks the
Graph HTTP layer (requests.get) and the token helper (identity.acquire_token) so
the tool runs offline.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import identity  # noqa: E402
import tool_list_pim_eligible_roles as pim  # noqa: E402
from lab_values import LAB_TENANT_ID  # noqa: E402

ACTOR_UPN = "meganb@lab.example"
GA_ID = pim.GLOBAL_ADMIN_ROLE_ID


class FakeResp:
    def __init__(self, status_code: int, body: dict, headers: dict | None = None):
        self.status_code = status_code
        self._body = body
        self.headers = headers or {}
        self.text = json.dumps(body)

    def json(self) -> dict:
        return self._body


def _instance(idx, role_name=None, role_id=None, end="2027-01-01T00:00:00Z", scope="/"):
    """A roleEligibilityScheduleInstance. role_name=None + role_id set exercises
    the GA-by-GUID fallback (no expanded roleDefinition)."""
    inst = {
        "id": f"elig-{idx}",
        "principalId": f"principal-{idx}",
        "roleDefinitionId": role_id or f"roledef-{idx}",
        "directoryScopeId": scope,
        "startDateTime": "2026-01-01T00:00:00Z",
        "endDateTime": end,
        "memberType": "Direct",
    }
    if role_name is not None:
        inst["roleDefinition"] = {"displayName": role_name}
    return inst


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZURE_TENANT_ID", LAB_TENANT_ID)
    monkeypatch.setenv("FOCI_CLIENT_ID", identity.DEFAULT_CLIENT_ID)
    monkeypatch.setenv("COMPROMISED_USER_UPN", ACTOR_UPN)
    monkeypatch.delenv("COMPROMISED_USER_PASSWORD", raising=False)


def _read_graph_calls(replay_dir: Path) -> list[dict]:
    entries = [json.loads(fp.read_text(encoding="utf-8")) for fp in sorted(replay_dir.glob("*.json"))]
    return [e for e in entries if e.get("kind") == "graph_call"]


def _run(monkeypatch, env, tmp_path, responses, run_id="PIM-TEST"):
    replay_dir = tmp_path / "replay-logs"
    replay_dir.mkdir()
    argv = [
        "tool_list_pim_eligible_roles.py",
        "--replay-log-dir", str(replay_dir),
        "--run-id", run_id,
    ]
    monkeypatch.setattr(sys, "argv", argv)
    getmock = mock.MagicMock(side_effect=responses)
    with mock.patch(
        "identity.acquire_token", return_value={"access_token": "AT_test"}
    ), mock.patch("requests.get", getmock):
        rc = pim.main()
    return rc, replay_dir, getmock


def _expand_of(url: str) -> str | None:
    m = re.search(r"[?&]\$expand=([^&]*)", url)
    return m.group(1) if m else None


class TestSingleCall:
    def test_single_expand_and_ga_flag(self, monkeypatch, env, tmp_path, capsys):
        body = {"value": [_instance(1, "Global Administrator")]}
        rc, replay_dir, getmock = _run(monkeypatch, env, tmp_path, [FakeResp(200, body)])

        assert rc == 0
        # One GET, one $expand property (roleDefinition) — within the Graph v1.0
        # single-property limit, so no two-call merge.
        assert getmock.call_count == 1
        assert _expand_of(getmock.call_args_list[0].args[0]) == "roleDefinition"

        calls = _read_graph_calls(replay_dir)
        assert len(calls) == 1
        entry = calls[0]
        assert entry["technique"]["id"] == "T1087.004"
        assert entry["tool"] == "tool_list_pim_eligible_roles"
        assert entry["response"]["status_code"] == 200
        assert entry["response"]["row_count"] == 1
        assert entry["response"]["page_count"] == 1
        assert entry["outcome"] == "success"

        out = json.loads(capsys.readouterr().out)
        assert out["pim_eligible_total"] == 1
        assert out["pim_eligible_global_admin_count"] == 1
        assert out["pim_time_bound_eligible_count"] == 1
        assert out["pim_permanent_eligible_count"] == 0


class TestAggregates:
    def test_aggregates_and_permanent_split(self, monkeypatch, env, tmp_path, capsys):
        body = {
            "value": [
                _instance(1, "Global Administrator", end=None),        # permanent GA
                _instance(2, "Security Administrator"),                 # time-bound high-priv
            ]
        }
        rc, _, _ = _run(monkeypatch, env, tmp_path, [FakeResp(200, body)])
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["pim_eligible_global_admin_count"] == 1
        assert out["pim_eligible_high_privilege_count"] == 2  # GA + Security Admin
        assert out["pim_permanent_eligible_count"] == 1       # GA has no endDateTime
        assert out["pim_time_bound_eligible_count"] == 1
        assert out["pim_unique_principals"] == 2
        assert out["pim_unique_roles"] == 2
        assert out["pim_tenant_wide_scope_count"] == 2

    def test_ga_flagged_by_well_known_guid_without_expand(self, monkeypatch, env, tmp_path, capsys):
        # No roleDefinition expanded; GA must still be flagged via roleDefinitionId.
        body = {"value": [_instance(1, role_name=None, role_id=GA_ID)]}
        rc, _, _ = _run(monkeypatch, env, tmp_path, [FakeResp(200, body)])
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["pim_eligible_global_admin_count"] == 1


class TestEmptyAndError:
    def test_empty_is_not_error(self, monkeypatch, env, tmp_path, capsys):
        rc, replay_dir, _ = _run(monkeypatch, env, tmp_path, [FakeResp(200, {"value": []})])
        assert rc == 0
        calls = _read_graph_calls(replay_dir)
        assert len(calls) == 1
        assert calls[0]["response"]["row_count"] == 0
        assert calls[0]["outcome"] == "success"
        captured = capsys.readouterr()
        assert "No PIM-eligible role assignments found" in captured.err
        assert json.loads(captured.out)["row_count"] == 0

    def test_403_permission_gap_is_error(self, monkeypatch, env, tmp_path, capsys):
        # Operator lacks a supported role, or scope not consented: HTTP 403.
        # Recorded as outcome=error (a documented sandbox-config finding), rc 1.
        rc, replay_dir, _ = _run(
            monkeypatch, env, tmp_path,
            [FakeResp(403, {"error": {"code": "Authorization_RequestDenied"}})],
        )
        assert rc == 1
        calls = _read_graph_calls(replay_dir)
        assert len(calls) == 1
        assert calls[0]["outcome"] == "error"
        # The empty-result notice must NOT fire on an error path.
        assert "No PIM-eligible role assignments found" not in capsys.readouterr().err

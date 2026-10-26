# SPDX-License-Identifier: MIT
"""Tests for scripts/tool_intune_devices.py (Tool 8, T1082 Intune devices).

Mocks the Graph HTTP layer (requests.get) and the token helper
(identity.acquire_token) so the tool runs offline. Covers a single-page
success, an empty inventory, and multi-page @odata.nextLink pagination.
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
import tool_intune_devices  # noqa: E402
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


def _device(idx: int, **overrides) -> dict:
    base = {
        "id": f"device-{idx}",
        "deviceName": f"LAPTOP-{idx}",
        "managedDeviceOwnerType": "company",
        "operatingSystem": "Windows",
        "osVersion": "10.0.22631",
        "complianceState": "compliant",
        "managementState": "managed",
        "lastSyncDateTime": "2026-06-15T00:00:00Z",
        "enrolledDateTime": "2026-01-01T00:00:00Z",
        "azureADDeviceId": f"aad-{idx}",
        "userPrincipalName": "user@cloudharbor-demo.com",
        "userDisplayName": "Test User",
        "manufacturer": "Contoso",
        "model": "Model X",
        "isEncrypted": True,
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


def _run(monkeypatch, env, tmp_path, responses, run_id="INTUNE-TEST"):
    replay_dir = tmp_path / "replay-logs"
    replay_dir.mkdir()
    argv = [
        "tool_intune_devices.py",
        "--replay-log-dir", str(replay_dir),
        "--run-id", run_id,
    ]
    monkeypatch.setattr(sys, "argv", argv)
    with mock.patch(
        "identity.acquire_token", return_value={"access_token": "AT_test"}
    ), mock.patch("requests.get", side_effect=responses):
        rc = tool_intune_devices.main()
    return rc, replay_dir


class TestSuccessfulList:
    def test_single_page_writes_entry(self, monkeypatch, env, tmp_path, capsys):
        body = {"value": [_device(1), _device(2, complianceState="noncompliant",
                                              isEncrypted=False)]}
        rc, replay_dir = _run(monkeypatch, env, tmp_path, [FakeResp(200, body)])

        assert rc == 0
        calls = _read_graph_calls(replay_dir)
        assert len(calls) == 1
        entry = calls[0]
        assert entry["technique"]["id"] == "T1082"
        assert entry["tool"] == "tool_intune_devices"
        assert entry["request"]["method"] == "GET"
        assert "/deviceManagement/managedDevices" in entry["request"]["url"]
        assert entry["response"]["status_code"] == 200
        assert entry["response"]["row_count"] == 2  # object_count
        assert entry["outcome"] == "success"
        assert entry["run_id"] == "INTUNE-TEST"

        out = json.loads(capsys.readouterr().out)
        assert out["row_count"] == 2
        assert out["devices_compliant"] == 1
        assert out["devices_not_encrypted"] == 1


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
        assert "No managed devices found" in captured.err
        assert json.loads(captured.out)["row_count"] == 0


class TestPagination:
    def test_follows_nextlink_across_pages(self, monkeypatch, env, tmp_path, capsys):
        next_url = (
            "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"
            "?$skiptoken=PAGE2"
        )
        page1 = {
            "value": [_device(1), _device(2)],
            "@odata.nextLink": next_url,
        }
        page2 = {"value": [_device(3)]}  # no nextLink -> stop
        rc, replay_dir = _run(
            monkeypatch, env, tmp_path, [FakeResp(200, page1), FakeResp(200, page2)]
        )

        assert rc == 0
        calls = _read_graph_calls(replay_dir)
        assert len(calls) == 1
        entry = calls[0]
        # All three devices across both pages, page_count == 2.
        assert entry["response"]["row_count"] == 3  # total object_count
        assert entry["response"]["page_count"] == 2

        out = json.loads(capsys.readouterr().out)
        assert out["row_count"] == 3
        assert len(out["managed_devices"]) == 3
        assert {d["id"] for d in out["managed_devices"]} == {
            "device-1", "device-2", "device-3"
        }

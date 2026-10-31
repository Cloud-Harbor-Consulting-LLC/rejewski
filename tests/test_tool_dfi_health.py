# SPDX-License-Identifier: MIT
"""Tests for scripts/tool_dfi_health.py (Tool 7, T1518.001 DfI sensor health).

Mocks the Graph HTTP layer (requests.get) and the token helper
(identity.acquire_token) so the tool runs offline. Each test drives main()
through argv + env and then reads the emitted replay-log entry back from a
tmp_path replay-log directory.
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
import tool_dfi_health  # noqa: E402
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


def _sensor(idx: int, **overrides) -> dict:
    base = {
        "id": f"sensor-{idx}",
        "displayName": f"DC0{idx}",
        "sensorType": "domainControllerIntegrated",
        "version": "2.0.0",
        "deploymentStatus": "upToDate",
        "healthStatus": "healthy",
        "openHealthIssuesCount": 0,
        "domainName": "corp.lab.example",
        "serviceStatus": "running",
        "createdDateTime": "2026-01-01T00:00:00Z",
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


def _run(monkeypatch, env, tmp_path, responses, run_id="DFI-TEST"):
    replay_dir = tmp_path / "replay-logs"
    replay_dir.mkdir()
    argv = [
        "tool_dfi_health.py",
        "--replay-log-dir", str(replay_dir),
        "--run-id", run_id,
    ]
    monkeypatch.setattr(sys, "argv", argv)
    fake_token = {"access_token": "AT_test"}
    with mock.patch("identity.acquire_token", return_value=fake_token), mock.patch(
        "requests.get", side_effect=responses
    ):
        rc = tool_dfi_health.main()
    return rc, replay_dir


class TestSuccessfulList:
    def test_single_page_writes_entry(self, monkeypatch, env, tmp_path, capsys):
        body = {"value": [_sensor(1), _sensor(2, healthStatus="notHealthyHigh",
                                            openHealthIssuesCount=3)]}
        rc, replay_dir = _run(monkeypatch, env, tmp_path, [FakeResp(200, body)])

        assert rc == 0
        calls = _read_graph_calls(replay_dir)
        assert len(calls) == 1
        entry = calls[0]
        assert entry["technique"]["id"] == "T1518.001"
        assert entry["tool"] == "tool_dfi_health"
        assert entry["request"]["method"] == "GET"
        assert "/security/identities/sensors" in entry["request"]["url"]
        assert entry["response"]["status_code"] == 200
        assert entry["response"]["row_count"] == 2  # object_count
        assert entry["outcome"] == "success"
        assert entry["run_id"] == "DFI-TEST"

        out = json.loads(capsys.readouterr().out)
        assert out["row_count"] == 2
        assert out["sensors_healthy"] == 1
        assert out["open_health_issues_total"] == 3


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
        assert "No DfI sensors found" in captured.err
        assert json.loads(captured.out)["row_count"] == 0


class TestNoEmitDryRun:
    def test_no_emit_skips_replay_entry(self, monkeypatch, env, tmp_path, capsys):
        replay_dir = tmp_path / "replay-logs"
        replay_dir.mkdir()
        argv = [
            "tool_dfi_health.py",
            "--replay-log-dir", str(replay_dir),
            "--no-emit",
        ]
        monkeypatch.setattr(sys, "argv", argv)
        with mock.patch(
            "identity.acquire_token", return_value={"access_token": "AT_test"}
        ), mock.patch("requests.get", side_effect=[FakeResp(200, {"value": [_sensor(1)]})]):
            rc = tool_dfi_health.main()

        assert rc == 0
        assert _read_graph_calls(replay_dir) == []
        assert json.loads(capsys.readouterr().out)["replay_log_entry"] is None

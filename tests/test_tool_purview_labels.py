# SPDX-License-Identifier: MIT
"""Tests for scripts/tool_purview_labels.py (Tool 9, T1580 Purview labels).

Mocks the Graph HTTP layer (requests.get) and the token helper
(identity.acquire_token) so the tool runs offline. Covers a single-page
successful list and an empty-labels response.
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
import tool_purview_labels  # noqa: E402
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


def _label(idx: int, **overrides) -> dict:
    base = {
        "id": f"label-{idx}",
        "name": f"Confidential L{idx}",
        "description": f"Confidential label tier {idx}",
        "priority": idx,
        "isEnabled": True,
        "isEndpointProtectionEnabled": True,
        "actionSource": "manual",
        # Live API returns applicableTo as a comma-delimited string.
        "applicableTo": "file,email",
        "sublabels": [],
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


def _run(monkeypatch, env, tmp_path, responses, run_id="PURVIEW-TEST"):
    replay_dir = tmp_path / "replay-logs"
    replay_dir.mkdir()
    argv = [
        "tool_purview_labels.py",
        "--replay-log-dir", str(replay_dir),
        "--run-id", run_id,
    ]
    monkeypatch.setattr(sys, "argv", argv)
    with mock.patch(
        "identity.acquire_token", return_value={"access_token": "AT_test"}
    ), mock.patch("requests.get", side_effect=responses):
        rc = tool_purview_labels.main()
    return rc, replay_dir


class TestSuccessfulList:
    def test_single_page_writes_entry(self, monkeypatch, env, tmp_path, capsys):
        body = {
            "value": [
                _label(1),
                _label(
                    2,
                    isEnabled=False,
                    actionSource="automatic",
                    applicableTo="teamwork",
                    sublabels=[{"id": "sub-2a", "name": "Tier-2A"}],
                ),
            ]
        }
        rc, replay_dir = _run(monkeypatch, env, tmp_path, [FakeResp(200, body)])

        assert rc == 0
        calls = _read_graph_calls(replay_dir)
        assert len(calls) == 1
        entry = calls[0]
        assert entry["technique"]["id"] == "T1580"
        assert entry["tool"] == "tool_purview_labels"
        assert entry["request"]["method"] == "GET"
        assert (
            "/security/dataSecurityAndGovernance/sensitivityLabels"
            in entry["request"]["url"]
        )
        assert entry["response"]["status_code"] == 200
        assert entry["response"]["row_count"] == 2  # object_count
        assert entry["outcome"] == "success"
        assert entry["run_id"] == "PURVIEW-TEST"

        out = json.loads(capsys.readouterr().out)
        assert out["row_count"] == 2
        assert out["total_labels"] == 2
        assert out["enabled_count"] == 1
        assert out["disabled_count"] == 1
        assert out["labels_with_sublabels"] == 1
        assert out["action_source_breakdown"]["manual"] == 1
        assert out["action_source_breakdown"]["automatic"] == 1
        # applicableTo: label 1 -> "file,email"; label 2 -> "teamwork".
        # The breakdown counts per-scope, splitting the comma-delimited string.
        assert out["applicable_to_breakdown"]["file"] == 1
        assert out["applicable_to_breakdown"]["email"] == 1
        assert out["applicable_to_breakdown"]["teamwork"] == 1


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
        assert "No sensitivity labels found" in captured.err
        assert json.loads(captured.out)["row_count"] == 0

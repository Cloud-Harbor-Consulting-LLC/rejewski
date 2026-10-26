# SPDX-License-Identifier: MIT
"""Tests for scripts/tool_list_sharepoint_sites.py (Tool 14, T1213.002 Surface A).

Mocks the Graph HTTP layer (requests.get) and the token helper (identity.acquire_token)
so the tool runs offline. Covers site enumeration (happy path), optional per-site
drives/lists enumeration and their default-off behavior, row-cap truncation, empty result,
429 retry, 401 mid-pagination recovery, webUrl tenant-GUID scrubbing, replay-log entry
shape, the Sites.Read.All 403 error path, and the fleet CLI conventions.

Note (W17): the `sharingCapability` external-sharing-risk classification was removed —
`sharingCapability` is not a property of `microsoft.graph.site` in Graph v1.0 (the R013
real-tenant run returned HTTP 400 for it). The tool now enumerates the site inventory; the
`--include-drives` / `--include-lists` flags apply to every enumerated site.
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
import tool_list_sharepoint_sites as tool  # noqa: E402
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


def _site(idx: int, **ov) -> dict:
    base = {
        "id": f"site-{idx}",
        "displayName": f"Site {idx}",
        "webUrl": f"https://cloudharbordemo.sharepoint.com/sites/site{idx}",
        "description": "",
        "createdDateTime": "2026-01-01T00:00:00Z",
        "lastModifiedDateTime": "2026-08-01T00:00:00Z",
    }
    base.update(ov)
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


def _run(monkeypatch, env, tmp_path, responses, extra_args=None, run_id="R012", capsys=None):
    replay_dir = tmp_path / "replay-logs"
    replay_dir.mkdir()
    argv = [
        "tool_list_sharepoint_sites.py",
        "--replay-log-dir", str(replay_dir),
    ]
    if run_id is not None:  # run_id=None omits the flag (optional, matching the fleet)
        argv += ["--run-id", run_id]
    argv += list(extra_args or [])
    monkeypatch.setattr(sys, "argv", argv)
    getmock = mock.MagicMock(side_effect=responses)
    with mock.patch(
        "identity.acquire_token", return_value={"access_token": "AT_test"}
    ), mock.patch("requests.get", getmock), mock.patch("time.sleep"):
        rc = tool.main()
    captured = capsys.readouterr() if capsys else None
    out = json.loads(captured.out) if captured and captured.out.strip() else None
    err = captured.err if captured else ""
    return rc, replay_dir, getmock, out, err


class TestHappyPath:
    def test_enumerates_sites(self, monkeypatch, env, tmp_path, capsys):
        body = {"value": [_site(1), _site(2), _site(3)]}
        rc, replay_dir, getmock, out, err = _run(
            monkeypatch, env, tmp_path, [FakeResp(200, body)], capsys=capsys
        )
        assert rc == 0
        assert out["total_sites"] == 3
        assert [s["displayName"] for s in out["sites"]] == ["Site 1", "Site 2", "Site 3"]
        assert getmock.call_count == 1  # only the sites call (no include flags)
        # the removed sharing-risk classification must not reappear
        assert "sharing_risk" not in out["sites"][0]
        assert "sharingCapability" not in out["sites"][0]
        assert "sharing_risk_summary" not in out
        assert "flagged_sites" not in out

    def test_select_omits_sharingcapability(self):
        # Regression: sharingCapability is not a microsoft.graph.site property (R013 -> HTTP 400).
        assert "sharingCapability" not in tool.SITES_SELECT


class TestDriveEnumeration:
    def test_include_drives_enumerates_every_site(self, monkeypatch, env, tmp_path, capsys):
        sites = {"value": [_site(1), _site(2)]}
        drives1 = {"value": [
            {"id": "d1", "name": "Documents", "driveType": "documentLibrary",
             "quota": {"total": 100, "used": 40}},
        ]}
        drives2 = {"value": [{"id": "d2", "name": "Shared", "driveType": "documentLibrary"}]}
        rc, replay_dir, getmock, out, err = _run(
            monkeypatch, env, tmp_path,
            [FakeResp(200, sites), FakeResp(200, drives1), FakeResp(200, drives2)],
            extra_args=["--include-drives"], capsys=capsys,
        )
        assert rc == 0
        assert getmock.call_count == 3  # sites + a drives call for EACH site
        assert "/sites/site-1/drives" in getmock.call_args_list[1].args[0]
        assert "/sites/site-2/drives" in getmock.call_args_list[2].args[0]
        assert out["sites"][0]["drives"][0]["name"] == "Documents"
        assert out["sites"][1]["drives"][0]["name"] == "Shared"
        assert len(_read_graph_calls(replay_dir)) == 3


class TestRowCap:
    def test_row_cap_truncates(self, monkeypatch, env, tmp_path, capsys):
        body = {"value": [_site(i) for i in range(1, 1002)]}  # 1001 sites, one page
        rc, replay_dir, _, out, err = _run(
            monkeypatch, env, tmp_path, [FakeResp(200, body)], capsys=capsys
        )
        assert rc == 0
        assert out["total_sites"] == 1000  # capped from 1001
        assert out["row_cap_hit"] is True
        entry = _read_graph_calls(replay_dir)[0]
        assert entry["response"]["row_count"] == 1000
        assert entry["response"]["row_cap_hit"] is True
        assert entry["outcome"] == "row_cap_hit"


class TestEmpty:
    def test_no_sites_is_not_error(self, monkeypatch, env, tmp_path, capsys):
        rc, replay_dir, _, out, err = _run(
            monkeypatch, env, tmp_path, [FakeResp(200, {"value": []})], capsys=capsys
        )
        assert rc == 0
        assert out["total_sites"] == 0
        entry = _read_graph_calls(replay_dir)[0]
        assert entry["response"]["row_count"] == 0
        assert entry["outcome"] == "success"
        assert "No SharePoint sites found" in err


class TestRetry:
    def test_429_then_success(self, monkeypatch, env, tmp_path, capsys):
        throttled = FakeResp(429, {"error": "throttled"}, headers={"Retry-After": "0"})
        ok = FakeResp(200, {"value": [_site(1)]})
        rc, replay_dir, getmock, out, err = _run(
            monkeypatch, env, tmp_path, [throttled, ok], capsys=capsys
        )
        assert rc == 0
        assert getmock.call_count == 2  # first 429, retry succeeds
        assert out["total_sites"] == 1
        assert _read_graph_calls(replay_dir)[0]["response"]["retry_count"] == 1


class TestUnauthorizedRecovery:
    def test_401_mid_run_refreshes_and_resumes(self, monkeypatch, env, tmp_path, capsys):
        unauth = FakeResp(401, {"error": "invalid_token"})
        ok = FakeResp(200, {"value": [_site(1), _site(2)]})
        rc, replay_dir, getmock, out, err = _run(
            monkeypatch, env, tmp_path, [unauth, ok], capsys=capsys
        )
        assert rc == 0
        assert getmock.call_count == 2  # 401, then recovered GET
        assert out["total_sites"] == 2
        assert _read_graph_calls(replay_dir)[0]["response"]["retry_count"] == 1


class TestRedaction:
    def test_weburl_tenant_guid_scrubbed(self, monkeypatch, env, tmp_path, capsys):
        # A webUrl that embeds the sandbox tenant GUID must be scrubbed in output.
        leaky = _site(1, webUrl=f"https://cloudharbordemo.sharepoint.com/sites/{SANDBOX_TENANT_ID}/x")
        rc, _, _, out, err = _run(
            monkeypatch, env, tmp_path, [FakeResp(200, {"value": [leaky]})], capsys=capsys
        )
        assert rc == 0
        raw = json.dumps(out)
        assert SANDBOX_TENANT_ID not in raw  # tenant GUID scrubbed everywhere in evidence
        assert SANDBOX_TENANT_ID not in out["sites"][0]["webUrl"]


class TestReplayLogShape:
    def test_sites_graph_call_entry(self, monkeypatch, env, tmp_path, capsys):
        rc, replay_dir, _, _, err = _run(
            monkeypatch, env, tmp_path,
            [FakeResp(200, {"value": [_site(1), _site(2)]})], capsys=capsys,
        )
        assert rc == 0
        entry = _read_graph_calls(replay_dir)[0]
        assert entry["kind"] == "graph_call"
        assert entry["technique"]["id"] == "T1213.002"
        assert entry["tool"] == "tool_list_sharepoint_sites"
        assert entry["request"]["method"] == "GET"
        assert "/sites?search=*" in entry["request"]["url"]
        assert entry["response"]["row_count"] == 2
        assert entry["run_id"] == "R012"


class TestIncludeFlagsDefaultOff:
    def test_no_drives_calls_by_default(self, monkeypatch, env, tmp_path, capsys):
        # --include-drives NOT passed -> no drives call, even with sites present.
        rc, replay_dir, getmock, out, err = _run(
            monkeypatch, env, tmp_path,
            [FakeResp(200, {"value": [_site(1)]})], capsys=capsys,
        )
        assert rc == 0
        assert getmock.call_count == 1  # sites only
        assert out["sites"][0]["drives"] == []
        assert len(_read_graph_calls(replay_dir)) == 1

    def test_include_drives_only_no_lists(self, monkeypatch, env, tmp_path, capsys):
        # --include-drives on, --include-lists OFF: drives enumerated, lists not.
        sites = {"value": [_site(1)]}
        drives = {"value": [{"id": "d1", "name": "Documents", "driveType": "documentLibrary"}]}
        rc, replay_dir, getmock, out, err = _run(
            monkeypatch, env, tmp_path,
            [FakeResp(200, sites), FakeResp(200, drives)],
            extra_args=["--include-drives"],
            capsys=capsys,
        )
        assert rc == 0
        assert getmock.call_count == 2  # sites + drives only; no lists call
        assert out["sites"][0]["drives"][0]["name"] == "Documents"
        assert out["sites"][0]["lists"] == []
        assert not any("/lists" in c.args[0] for c in getmock.call_args_list)


class TestForbidden:
    def test_sites_403_exits_nonzero_with_scope_message(
        self, monkeypatch, env, tmp_path, capsys
    ):
        body = {"error": {"code": "Forbidden", "message": "Insufficient privileges."}}
        rc, replay_dir, _, out, err = _run(
            monkeypatch, env, tmp_path, [FakeResp(403, body)], capsys=capsys
        )
        assert rc == 1
        assert "HTTP 403" in err
        assert "Sites.Read.All" in err
        # error entry still written (G-5)
        entry = _read_graph_calls(replay_dir)[0]
        assert entry["outcome"] == "error"
        assert entry["response"]["row_count"] == 0


class TestFleetConventions:
    """Tool 14 aligned to the fleet CLI/output conventions (W16 N1 + N2)."""

    def test_default_replay_log_dir_is_replay_logs(self):
        # N1: default replay-log dir matches the other 13 tools, not the old 'logs/'.
        assert tool.DEFAULT_REPLAY_LOG_DIR.name == "replay-logs"

    def test_runs_without_run_id(self, monkeypatch, env, tmp_path, capsys):
        # N2: --run-id is optional (default None), consistent with the fleet.
        body = {"value": [_site(1)]}
        rc, replay_dir, _, out, err = _run(
            monkeypatch, env, tmp_path, [FakeResp(200, body)], run_id=None, capsys=capsys
        )
        assert rc == 0
        assert out["total_sites"] == 1
        entry = _read_graph_calls(replay_dir)[0]
        assert entry.get("run_id") is None

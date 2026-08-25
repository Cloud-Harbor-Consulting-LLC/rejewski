"""Tests for scripts/tool_list_sharepoint_sites.py (Tool 14, T1213.002 Surface A).

Mocks the Graph HTTP layer (requests.get) and the token helper
(identity.acquire_token) so the tool runs offline. Covers the happy path,
sharingCapability classification, drive-enumeration gating, row-cap truncation,
empty result, 429 retry, 401 mid-pagination recovery, webUrl tenant-GUID
scrubbing, replay-log entry shape, include-drives/include-lists default-off, and
the Sites.Read.All 403 error path.
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

CAP_HIGH = "externalUserAndGuestSharing"
CAP_MEDIUM = "externalUserSharingOnly"
CAP_LOW = "existingExternalUserSharingOnly"
CAP_NONE = "disabled"


class FakeResp:
    def __init__(self, status_code: int, body: dict, headers: dict | None = None):
        self.status_code = status_code
        self._body = body
        self.headers = headers or {}
        self.text = json.dumps(body)

    def json(self) -> dict:
        return self._body


def _site(idx: int, cap: str = CAP_NONE, **ov) -> dict:
    base = {
        "id": f"site-{idx}",
        "displayName": f"Site {idx}",
        "webUrl": f"https://cloudharbordemo.sharepoint.com/sites/site{idx}",
        "description": "",
        "sharingCapability": cap,
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
    if run_id is not None:  # run_id=None omits the flag (now optional, matching the fleet)
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
    def test_three_sites_mixed_risk(self, monkeypatch, env, tmp_path, capsys):
        body = {"value": [_site(1, CAP_HIGH), _site(2, CAP_MEDIUM), _site(3, CAP_NONE)]}
        rc, replay_dir, getmock, out, err = _run(
            monkeypatch, env, tmp_path, [FakeResp(200, body)], capsys=capsys
        )
        assert rc == 0
        assert out["total_sites"] == 3
        assert out["flagged_sites"] == 2  # high + medium
        assert out["sharing_risk_summary"] == {"high": 1, "medium": 1, "low": 0, "none": 1}
        assert [s["sharing_risk"] for s in out["sites"]] == ["high", "medium", "none"]
        assert getmock.call_count == 1  # only the sites call (no include flags)


class TestClassification:
    def test_all_four_enum_values(self, monkeypatch, env, tmp_path, capsys):
        body = {"value": [
            _site(1, CAP_HIGH), _site(2, CAP_MEDIUM), _site(3, CAP_LOW), _site(4, CAP_NONE),
        ]}
        rc, _, _, out, err = _run(monkeypatch, env, tmp_path, [FakeResp(200, body)], capsys=capsys)
        assert rc == 0
        risks = {s["displayName"]: s["sharing_risk"] for s in out["sites"]}
        assert risks == {"Site 1": "high", "Site 2": "medium", "Site 3": "low", "Site 4": "none"}
        assert out["sharing_risk_summary"] == {"high": 1, "medium": 1, "low": 1, "none": 1}


class TestDriveEnumeration:
    def test_high_risk_site_enumerates_drives(self, monkeypatch, env, tmp_path, capsys):
        sites = {"value": [_site(1, CAP_HIGH)]}
        drives = {"value": [
            {"id": "d1", "name": "Documents", "driveType": "documentLibrary",
             "quota": {"total": 100, "used": 40}},
        ]}
        rc, replay_dir, getmock, out, err = _run(
            monkeypatch, env, tmp_path,
            [FakeResp(200, sites), FakeResp(200, drives)],
            extra_args=["--include-drives"], capsys=capsys,
        )
        assert rc == 0
        assert getmock.call_count == 2  # sites + drives
        # second call was the drives endpoint for the flagged site
        assert "/sites/site-1/drives" in getmock.call_args_list[1].args[0]
        assert out["sites"][0]["drives"][0]["name"] == "Documents"
        assert out["sites"][0]["drives"][0]["driveType"] == "documentLibrary"
        # two graph_call entries: sites + drives
        assert len(_read_graph_calls(replay_dir)) == 2


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
        ok = FakeResp(200, {"value": [_site(1, CAP_HIGH)]})
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
        leaky = _site(1, CAP_HIGH,
                      webUrl=f"https://cloudharbordemo.sharepoint.com/sites/{SANDBOX_TENANT_ID}/x")
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
        # Flagged (high) site present, but --include-drives NOT passed -> no drives call.
        rc, replay_dir, getmock, out, err = _run(
            monkeypatch, env, tmp_path,
            [FakeResp(200, {"value": [_site(1, CAP_HIGH)]})], capsys=capsys,
        )
        assert rc == 0
        assert getmock.call_count == 1  # sites only
        assert out["sites"][0]["drives"] == []
        assert len(_read_graph_calls(replay_dir)) == 1

    def test_no_lists_calls_by_default(self, monkeypatch, env, tmp_path, capsys):
        # --include-drives on, --include-lists OFF: a flagged site enumerates
        # drives but NOT lists. Responses = sites + drives (no lists response).
        sites = {"value": [_site(1, CAP_HIGH)]}
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
        # no request URL ends in /lists
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
        # N2: --run-id is now optional (default None), consistent with the fleet.
        body = {"value": [_site(1, CAP_NONE)]}
        rc, replay_dir, _, out, err = _run(
            monkeypatch, env, tmp_path, [FakeResp(200, body)], run_id=None, capsys=capsys
        )
        assert rc == 0
        assert out["total_sites"] == 1
        # the emitted entry carries a null run binding rather than aborting on a missing flag
        entry = _read_graph_calls(replay_dir)[0]
        assert entry.get("run_id") is None

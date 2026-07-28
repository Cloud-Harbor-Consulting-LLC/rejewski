"""Tests for scripts/tool_list_security_alerts.py (Tool 12, T1654 Surface B).

Mocks the Graph HTTP layer (requests.get) and the token helper
(identity.acquire_token) so the tool runs offline. Covers single-page success,
multi-page @odata.nextLink pagination, an empty result, HTTP 403 (operator
prerequisite guidance, no crash), G-9 row-cap enforcement, and $filter
construction for --days / --severity / --status individually and combined.
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
import tool_list_security_alerts as tool  # noqa: E402
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


def _alert(idx: int, **overrides) -> dict:
    base = {
        "id": f"alert-{idx}",
        "title": f"Suspicious activity {idx}",
        "severity": "medium",
        "status": "resolved",
        "classification": "truePositive",
        "determination": "multiStagedAttack",
        "category": "InitialAccess",
        "alertType": "builtIn",
        "createdDateTime": f"2026-07-2{idx}T10:00:00Z",
        "lastModifiedDateTime": f"2026-07-2{idx}T11:00:00Z",
        "assignedTo": None,
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


def _run(monkeypatch, env, tmp_path, responses, extra_args=None, run_id="ALERTS-TEST"):
    replay_dir = tmp_path / "replay-logs"
    replay_dir.mkdir()
    argv = [
        "tool_list_security_alerts.py",
        "--replay-log-dir", str(replay_dir),
        "--run-id", run_id,
    ] + list(extra_args or [])
    monkeypatch.setattr(sys, "argv", argv)
    with mock.patch(
        "identity.acquire_token", return_value={"access_token": "AT_test"}
    ), mock.patch("requests.get", side_effect=responses):
        rc = tool.main()
    return rc, replay_dir


class TestSuccessfulList:
    def test_single_page_writes_entry(self, monkeypatch, env, tmp_path, capsys):
        body = {
            "value": [
                _alert(1),
                _alert(
                    2,
                    severity="high",
                    status="new",
                    category="Execution",
                    assignedTo="soc@cloudharbor-demo.com",
                ),
            ]
        }
        rc, replay_dir = _run(monkeypatch, env, tmp_path, [FakeResp(200, body)])

        assert rc == 0
        calls = _read_graph_calls(replay_dir)
        assert len(calls) == 1
        entry = calls[0]
        assert entry["technique"]["id"] == "T1654"
        assert entry["technique"]["name"] == "Log Enumeration"
        assert entry["tool"] == "tool_list_security_alerts"
        assert entry["request"]["method"] == "GET"
        assert "/security/alerts_v2" in entry["request"]["url"]
        assert entry["response"]["status_code"] == 200
        assert entry["response"]["row_count"] == 2  # object_count
        assert entry["outcome"] == "success"
        assert entry["run_id"] == "ALERTS-TEST"

        out = json.loads(capsys.readouterr().out)
        assert out["row_count"] == 2
        assert out["total_alerts"] == 2
        assert out["by_severity"]["medium"] == 1
        assert out["by_severity"]["high"] == 1
        assert out["by_severity"]["low"] == 0  # bucket pre-seeded
        assert out["by_status"]["resolved"] == 1
        assert out["by_status"]["new"] == 1
        assert out["by_category"]["InitialAccess"] == 1
        assert out["by_category"]["Execution"] == 1


class TestPagination:
    def test_follows_nextlink_across_pages(self, monkeypatch, env, tmp_path, capsys):
        next_url = (
            "https://graph.microsoft.com/v1.0/security/alerts_v2?$skiptoken=PAGE2"
        )
        page1 = {"value": [_alert(1), _alert(2)], "@odata.nextLink": next_url}
        page2 = {"value": [_alert(3)]}  # no nextLink -> stop
        rc, replay_dir = _run(
            monkeypatch, env, tmp_path, [FakeResp(200, page1), FakeResp(200, page2)]
        )

        assert rc == 0
        entry = _read_graph_calls(replay_dir)[0]
        assert entry["response"]["row_count"] == 3  # total across both pages
        assert entry["response"]["page_count"] == 2

        out = json.loads(capsys.readouterr().out)
        assert out["total_alerts"] == 3
        assert {a["id"] for a in out["alerts"]} == {"alert-1", "alert-2", "alert-3"}


class TestEmptyList:
    def test_empty_is_not_error(self, monkeypatch, env, tmp_path, capsys):
        rc, replay_dir = _run(
            monkeypatch, env, tmp_path, [FakeResp(200, {"value": []})]
        )

        assert rc == 0
        calls = _read_graph_calls(replay_dir)
        assert len(calls) == 1  # entry still written
        assert calls[0]["response"]["row_count"] == 0  # object_count: 0
        assert calls[0]["outcome"] == "success"

        captured = capsys.readouterr()
        assert "No alerts found for the specified period" in captured.err
        out = json.loads(captured.out)
        assert out["total_alerts"] == 0
        assert out["by_severity"] == {
            "informational": 0, "low": 0, "medium": 0, "high": 0
        }


class TestForbidden:
    def test_403_prints_guidance_and_does_not_crash(
        self, monkeypatch, env, tmp_path, capsys
    ):
        body = {
            "error": {
                "code": "Forbidden",
                "message": "Insufficient privileges to complete the operation.",
            }
        }
        rc, replay_dir = _run(monkeypatch, env, tmp_path, [FakeResp(403, body)])

        # Clean error exit, not a traceback.
        assert rc == 1
        captured = capsys.readouterr()
        assert "HTTP 403" in captured.err
        assert "SecurityAlert.Read.All" in captured.err
        assert "Security Reader" in captured.err

        # Replay-log entry is still written, recording the failure (G-5).
        calls = _read_graph_calls(replay_dir)
        assert len(calls) == 1
        assert calls[0]["outcome"] == "error"
        assert calls[0]["response"]["row_count"] == 0

        # stdout stays machine-readable even on the error path.
        out = json.loads(captured.out)
        assert out["outcome"] == "error"
        assert "error" in out


class TestRowCap:
    def test_row_cap_enforced(self, monkeypatch, env, tmp_path, capsys):
        # Five alerts returned, cap of 2 -> only 2 collected (G-9).
        body = {"value": [_alert(i) for i in range(1, 6)]}
        rc, replay_dir = _run(
            monkeypatch, env, tmp_path, [FakeResp(200, body)],
            extra_args=["--row-cap", "2"],
        )

        assert rc == 0
        entry = _read_graph_calls(replay_dir)[0]
        assert entry["response"]["row_count"] == 2
        assert entry["response"]["row_cap"] == 2
        assert entry["response"]["row_cap_hit"] is True
        assert entry["outcome"] == "row_cap_hit"

        out = json.loads(capsys.readouterr().out)
        assert out["total_alerts"] == 2
        assert len(out["alerts"]) == 2


class TestFilterConstruction:
    """$filter clauses, unit-tested directly and asserted end-to-end on the URL."""

    def test_days_only(self):
        f = tool._build_filter("2026-06-28T00:00:00Z", None, None)
        assert f == "createdDateTime ge 2026-06-28T00:00:00Z"

    def test_severity_only(self):
        assert tool._build_filter(None, "high", None) == "severity eq 'high'"

    def test_status_only(self):
        assert tool._build_filter(None, None, "resolved") == "status eq 'resolved'"

    def test_combined_with_and(self):
        f = tool._build_filter("2026-06-28T00:00:00Z", "high", "resolved")
        assert f == (
            "createdDateTime ge 2026-06-28T00:00:00Z"
            " and severity eq 'high'"
            " and status eq 'resolved'"
        )

    def test_days_zero_disables_date_clause(self):
        assert tool._build_filter(None, None, None) == ""
        # No filter at all -> $filter omitted from the URL entirely.
        url = tool._build_url(tool.DEFAULT_SELECT, "", 100)
        assert "$filter" not in url
        assert "$top=100" in url

    def test_filters_reach_the_request_url(
        self, monkeypatch, env, tmp_path, capsys
    ):
        rc, replay_dir = _run(
            monkeypatch, env, tmp_path, [FakeResp(200, {"value": []})],
            extra_args=["--days", "14", "--severity", "high", "--status", "resolved"],
        )
        assert rc == 0
        url = _read_graph_calls(replay_dir)[0]["request"]["url"]
        assert "createdDateTime%20ge" in url or "createdDateTime ge" in url
        assert "severity%20eq%20'high'" in url or "severity eq 'high'" in url
        assert "status%20eq%20'resolved'" in url or "status eq 'resolved'" in url

        out = json.loads(capsys.readouterr().out)
        assert out["days"] == 14
        assert out["severity_filter"] == "high"
        assert out["status_filter"] == "resolved"
        assert " and " in out["filter"]

    def test_days_zero_end_to_end_omits_filter(
        self, monkeypatch, env, tmp_path, capsys
    ):
        rc, replay_dir = _run(
            monkeypatch, env, tmp_path, [FakeResp(200, {"value": []})],
            extra_args=["--days", "0"],
        )
        assert rc == 0
        url = _read_graph_calls(replay_dir)[0]["request"]["url"]
        assert "$filter" not in url
        assert json.loads(capsys.readouterr().out)["filter"] == ""


class TestStatusEnum:
    """Pins the v1.0 alertStatus enum for /security/alerts_v2.

    `active` is a legacy /security/alerts (v1) value and is NOT valid on v1.0 —
    passing it would return zero rows or HTTP 400. It shipped in the original
    Tool 12 CLI and was corrected to `new` (PR #78). These cases stop the legacy
    value being reintroduced silently.

    parse_args() is exercised directly rather than main(): main() reads env from
    .env and would proceed toward a live Graph call, which the ROE forbids here.
    """

    def test_legacy_active_status_is_rejected(self, monkeypatch):
        monkeypatch.setattr(
            sys, "argv", ["tool_list_security_alerts.py", "--status", "active"]
        )
        with pytest.raises(SystemExit) as exc:
            tool.parse_args()
        assert exc.value.code == 2  # argparse usage error

    def test_v1_enum_status_values_are_accepted(self, monkeypatch):
        for value in ("new", "inProgress", "resolved"):
            monkeypatch.setattr(
                sys, "argv", ["tool_list_security_alerts.py", "--status", value]
            )
            assert tool.parse_args().status == value

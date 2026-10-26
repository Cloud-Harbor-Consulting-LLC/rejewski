# SPDX-License-Identifier: MIT
"""Emit-flag contract tests for the tools that gained --emit/--no-emit in W16 (N3).

The dry-run toggle was backported to the seven tools that lacked it: the Sprint 1
core (users, groups, applications, ca_policies, role_assignments, service_principals)
and Tool 11 (oauth_grants). Five of these have no dedicated suite of their own, so
this shared, parametrized test gives every backported tool offline coverage of the
new flag.

Each tool is driven with a mocked token helper (so no token_event is written) and an
empty Graph page. The contract, matching the tools that already had the flag:
  - `--no-emit` performs the read but writes no graph_call replay-log entry, and the
    evidence JSON's `replay_log_entry` is null.
  - the default (emit on) writes exactly one graph_call entry and reports its path.
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import identity  # noqa: E402
from replay_log import SANDBOX_TENANT_ID  # noqa: E402

# The seven tools that gained --emit/--no-emit in the W16 N3 backport.
BACKPORTED_TOOLS = [
    "tool_list_users",
    "tool_list_groups",
    "tool_list_applications",
    "tool_list_ca_policies",
    "tool_list_role_assignments",
    "tool_list_service_principals",
    "tool_list_oauth_grants",
]


class FakeResp:
    def __init__(self, status_code: int, body: dict, headers: dict | None = None):
        self.status_code = status_code
        self._body = body
        self.headers = headers or {}
        self.text = json.dumps(body)

    def json(self) -> dict:
        return self._body


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZURE_TENANT_ID", SANDBOX_TENANT_ID)
    monkeypatch.setenv("FOCI_CLIENT_ID", identity.DEFAULT_CLIENT_ID)
    monkeypatch.setenv("COMPROMISED_USER_UPN", "meganb@cloudharbor-demo.com")
    monkeypatch.delenv("COMPROMISED_USER_PASSWORD", raising=False)


def _graph_calls(replay_dir: Path) -> list[dict]:
    entries = [json.loads(fp.read_text(encoding="utf-8")) for fp in sorted(replay_dir.glob("*.json"))]
    return [e for e in entries if e.get("kind") == "graph_call"]


def _run(tool_name, monkeypatch, tmp_path, capsys, extra_args):
    mod = importlib.import_module(tool_name)
    replay_dir = tmp_path / "replay-logs"
    replay_dir.mkdir()
    argv = [f"{tool_name}.py", "--replay-log-dir", str(replay_dir), "--run-id", "R012"] + extra_args
    monkeypatch.setattr(sys, "argv", argv)
    with mock.patch(
        "identity.acquire_token", return_value={"access_token": "AT_test"}
    ), mock.patch("requests.get", return_value=FakeResp(200, {"value": []})), mock.patch("time.sleep"):
        rc = mod.main()
    out = capsys.readouterr().out
    evidence = json.loads(out) if out.strip() else None
    return rc, replay_dir, evidence


@pytest.mark.parametrize("tool_name", BACKPORTED_TOOLS)
def test_no_emit_skips_replay_entry(tool_name, env, monkeypatch, tmp_path, capsys):
    rc, replay_dir, evidence = _run(tool_name, monkeypatch, tmp_path, capsys, ["--no-emit"])
    assert rc == 0
    assert _graph_calls(replay_dir) == []
    assert evidence is not None
    assert evidence["replay_log_entry"] is None


@pytest.mark.parametrize("tool_name", BACKPORTED_TOOLS)
def test_emit_default_writes_one_entry(tool_name, env, monkeypatch, tmp_path, capsys):
    rc, replay_dir, evidence = _run(tool_name, monkeypatch, tmp_path, capsys, [])
    assert rc == 0
    assert len(_graph_calls(replay_dir)) == 1
    assert evidence is not None
    assert evidence["replay_log_entry"] is not None

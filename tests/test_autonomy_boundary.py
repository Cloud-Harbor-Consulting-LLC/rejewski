# SPDX-License-Identifier: MIT
"""Agent autonomy boundary tests — verify the G-1..G-9 guardrails hold when the
Rejewski layer is pushed toward write / persistence / lateral-movement / defense-
evasion actions.

Every test here asserts a REAL, deterministic property of the current code — a
raised exception, or a structural fact about the shipped tools/config.

=============================================================================
GAPS — DISCOVERED, THEN CLOSED
=============================================================================
This suite originally surfaced two gaps (the brief expected enforcement that
did not exist). Both are now closed by active guards, and the tests below assert
those guards as real refusals rather than documenting an absence.

GAP-1 (closed) — technique prohibition at config load (Category 2, G-1/G-4).
    Was: `RoutingConfig.is_hard()/select_model()` are model routing only and
    never refuse; `load_config()` did no technique validation, despite ADR 0001
    §3 ("out-of-scope techniques are refused at config load").
    Now: `rejewski_runtime.is_prohibited_technique()` + `PROHIBITED_TECHNIQUES`
    define the permanent out-of-scope set, and `load_config()` raises ValueError
    if the config references any of them. Model routing is unchanged and
    orthogonal — refusal happens at load, not in the routing decision. Prohibited
    techniques remain additionally blocked by ABSENCE (no tool implements them).

GAP-2 (closed) — write-verb guard (Category 1, G-1).
    Was: `replay_log.write_entry()` did not validate `request["method"]`, so a
    graph_call recorded with POST/PATCH/DELETE would be written unchallenged.
    Now: write_entry() raises ValueError when a `graph_call` entry's
    `request.method` is not GET. A `token_event` (the legitimate POST to the
    OAuth token endpoint) is exempt. GET-only also still holds structurally (no
    shipped tool issues a write verb).

WHAT IS ENFORCED (all tested here as real refusals):
    * write_entry() raises on: non-sandbox tenant, empty tenant (G-1/G-3 lock);
      missing borrowed_client_id (G-3 no-app-reg); a graph_call with a non-GET
      method (G-1 read-only).
    * load_config() raises on a config referencing a prohibited technique
      (ADR 0001 §3 / G-4).
    * No shipped tool issues a write HTTP verb (structural + behavioural).
    * No shipped tool implements any prohibited technique (refusal-by-absence).
    * The committed routing config routes none of the prohibited techniques.
=============================================================================
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from unittest import mock

import pytest

import identity
import tool_list_users
from replay_log import SANDBOX_TENANT_ID, ReplayLogEntry, write_entry
from rejewski_runtime import PROHIBITED_TECHNIQUES, load_config

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"
TOOL_SCRIPTS = sorted(SCRIPTS.glob("tool_*.py"))

# Sourced from rejewski_runtime so the tests and the enforcement can never drift.
PROHIBITED = sorted(PROHIBITED_TECHNIQUES)

WRITE_VERB_RE = re.compile(r"requests\.(post|put|patch|delete)\s*\(", re.IGNORECASE)
TECHNIQUE_ID_RE = re.compile(r'^TECHNIQUE_ID\s*=\s*"([^"]+)"', re.MULTILINE)


def _entry(**overrides) -> ReplayLogEntry:
    """A schema-valid graph_call entry; override one field to trip a guard."""
    base = dict(
        kind="graph_call",
        tool="tool_list_users",
        technique_id="T1087.004",
        technique_name="Account Discovery: Cloud Account",
        tenant_id=SANDBOX_TENANT_ID,
        borrowed_client_id="14d82eec-204b-4c2f-b7e8-296a70dab67e",
        actor_upn="meganb@cloudharbor-demo.com",
        started_at_utc="2026-08-06T10:00:00Z",
        completed_at_utc="2026-08-06T10:00:01Z",
        request={"method": "GET", "url": "https://graph.microsoft.com/v1.0/users"},
        response={
            "status_code": 200,
            "page_count": 1,
            "row_count": 0,
            "row_cap": 1000,
            "row_cap_hit": False,
            "retry_count": 0,
        },
        outcome="success",
    )
    base.update(overrides)
    return ReplayLogEntry(**base)


# ---------------------------------------------------------------------------
# Category 1 — Write-operation refusal (G-1)
# ---------------------------------------------------------------------------
class TestWriteOperationRefusal:
    def test_no_tool_script_issues_a_write_verb(self):
        """Structural G-1: no shipped tool contains a write HTTP verb. This is
        the actual GET-only posture (see GAP-2 — it is structural, not guarded)."""
        assert TOOL_SCRIPTS, "no tool_*.py scripts found"
        offenders = {
            p.name: WRITE_VERB_RE.findall(p.read_text(encoding="utf-8"))
            for p in TOOL_SCRIPTS
            if WRITE_VERB_RE.search(p.read_text(encoding="utf-8"))
        }
        assert offenders == {}, f"tool(s) issue write verbs: {offenders}"

    def test_representative_tool_never_calls_a_write_endpoint(
        self, tmp_path, monkeypatch
    ):
        """Behavioural G-1 (POST/PATCH/DELETE attempt): run a representative tool
        end-to-end with every write verb wired to explode if touched. The tool
        completes via GET only, proving 0 passing calls to write Graph endpoints."""
        monkeypatch.setenv("AZURE_TENANT_ID", SANDBOX_TENANT_ID)
        monkeypatch.setenv("FOCI_CLIENT_ID", identity.DEFAULT_CLIENT_ID)
        monkeypatch.setenv("COMPROMISED_USER_UPN", "meganb@cloudharbor-demo.com")
        monkeypatch.delenv("COMPROMISED_USER_PASSWORD", raising=False)
        replay_dir = tmp_path / "replay-logs"
        replay_dir.mkdir()
        monkeypatch.setattr(
            "sys.argv",
            ["tool_list_users.py", "--replay-log-dir", str(replay_dir),
             "--run-id", "BOUNDARY"],
        )

        class _Resp:
            status_code = 200
            headers: dict = {}
            text = "{}"

            def json(self):
                return {"value": []}

        def _boom(*a, **k):
            raise AssertionError("a WRITE HTTP verb was issued — G-1 violation")

        with mock.patch("identity.acquire_token", return_value={"access_token": "AT"}), \
                mock.patch("requests.get", return_value=_Resp()), \
                mock.patch("requests.post", side_effect=_boom), \
                mock.patch("requests.put", side_effect=_boom), \
                mock.patch("requests.patch", side_effect=_boom), \
                mock.patch("requests.delete", side_effect=_boom):
            rc = tool_list_users.main()

        assert rc == 0  # completed on GET alone; no write verb was reached

    @pytest.mark.parametrize("method", ["POST", "PATCH", "PUT", "DELETE"])
    def test_write_entry_refuses_graph_call_write_method(self, method, tmp_path):
        """GAP-2 closed (G-1 read-only): write_entry() refuses to record a
        graph_call whose HTTP method is not GET, so a future write tool cannot
        produce a valid evidence record for a write call."""
        entry = _entry(
            request={"method": method, "url": "https://graph.microsoft.com/v1.0/users"}
        )
        with pytest.raises(ValueError, match="read-only"):
            write_entry(entry, log_dir=tmp_path)

    def test_write_entry_allows_token_event_post(self, tmp_path):
        """The GET-only guard is scoped to graph_call: a token_event carries the
        legitimate POST to the OAuth token endpoint and must still be writable."""
        entry = _entry(
            kind="token_event",
            technique_id="T1550.001",
            technique_name="Application Access Token",
            request={
                "method": "POST",
                "url": "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
            },
            response={"status_code": 200},
        )
        path = write_entry(entry, log_dir=tmp_path)
        assert path.exists()


# ---------------------------------------------------------------------------
# Category 2 — Prohibited technique routing (G-1, G-4)
# ---------------------------------------------------------------------------
class TestProhibitedTechniqueRouting:
    @pytest.mark.parametrize("technique", PROHIBITED)
    def test_prohibited_technique_has_no_implemented_tool(self, technique):
        """Refusal-by-absence: no shipped tool declares a prohibited technique as
        its TECHNIQUE_ID, so there is no code path that could execute it."""
        implemented = {
            m.group(1)
            for p in TOOL_SCRIPTS
            for m in TECHNIQUE_ID_RE.finditer(p.read_text(encoding="utf-8"))
        }
        assert technique not in implemented, (
            f"{technique} is implemented by a tool but is on the prohibited list"
        )

    def test_committed_config_loads_and_routes_no_prohibited_technique(self):
        """The committed rejewski.config.json loads cleanly (it references no
        prohibited technique) and routes none of them."""
        routing = load_config().rejewski.routing
        overlap = set(PROHIBITED) & set(routing.hard_techniques)
        assert overlap == set(), f"prohibited techniques in routing: {overlap}"

    @pytest.mark.parametrize("technique", PROHIBITED)
    def test_load_config_refuses_config_referencing_prohibited(
        self, technique, tmp_path
    ):
        """GAP-1 closed (G-1/G-4, ADR 0001 §3): load_config() raises when the
        config references a permanently out-of-scope technique."""
        bad = {
            "model": "claude-sonnet-4-6",
            "rejewski": {"routing": {"hard_techniques": ["T1550.001", technique]}},
        }
        cfg_path = tmp_path / "rejewski.config.json"
        cfg_path.write_text(json.dumps(bad), encoding="utf-8")
        with pytest.raises(ValueError, match="out-of-scope technique"):
            load_config(cfg_path)


# ---------------------------------------------------------------------------
# Category 3 — Consent-bound tenant lock (G-1, ADR 0008)
# ---------------------------------------------------------------------------
class TestSandboxTenantLock:
    def test_write_entry_rejects_wrong_tenant(self, tmp_path):
        """G-1 consent-bound tenant lock: a replay entry for a tenant other than the
        cloudharbordemo sandbox is refused when the run has no consent record for it."""
        entry = _entry(tenant_id="11111111-2222-3333-4444-555555555555")
        with pytest.raises(ValueError, match="tenant"):
            write_entry(entry, log_dir=tmp_path)

    def test_write_entry_rejects_empty_tenant(self, tmp_path):
        """An empty tenant_id is not a tenant GUID, so it is refused."""
        entry = _entry(tenant_id="")
        with pytest.raises(ValueError, match="tenant"):
            write_entry(entry, log_dir=tmp_path)

    def test_write_entry_rejects_missing_borrowed_client(self, tmp_path):
        """G-3 no-tenant-app-reg posture: an entry without a borrowed_client_id
        is refused (the write path requires the borrowed FOCI client)."""
        entry = _entry(borrowed_client_id="")
        with pytest.raises(ValueError, match="borrowed_client_id"):
            write_entry(entry, log_dir=tmp_path)

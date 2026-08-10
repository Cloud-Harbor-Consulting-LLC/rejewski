"""Agent autonomy boundary tests — verify the G-1..G-9 guardrails hold when the
Rejewski layer is pushed toward write / persistence / lateral-movement / defense-
evasion actions.

Every test here asserts a REAL, deterministic property of the current code — a
raised exception, or a structural fact about the shipped tools/config. Where a
guardrail the brief expected to find is NOT actively enforced, that is recorded
in the GAPS section below and pinned by a clearly-labelled documentation test,
rather than dressed up as enforcement that does not exist.

=============================================================================
GAPS DISCOVERED (honest findings — the enforcement below is weaker than the
brief hypothesised; no production code was changed, per the brief's "document
any gaps" instruction)
=============================================================================

GAP-1 — RoutingConfig does NOT refuse prohibited techniques (Category 2).
    The brief hypothesised `RoutingConfig.hard_techniques` might be the
    enforcement point. It is not. `RoutingConfig.is_hard()` / `select_model()`
    are purely Sonnet-vs-Opus MODEL routing: for ANY technique_id — including
    a prohibited one like T1053 — `select_model()` returns a model string and
    `is_hard()` returns a bool. Neither ever refuses. `load_config()` performs
    no technique-allowlist validation either, despite ADR 0001 §3 stating that
    "out-of-scope techniques are refused at config load, not at runtime."
    -> Prohibited techniques (T1053, T1078.003, T1136, T1098) are blocked only
       by ABSENCE (no scripts/tool_*.py implements them) and, at the agent
       layer, by the SDK config (read-only system_prompt scope + disallowed
       local write tools). There is no Python-unit-testable refusal function.
    -> Remediation option (out of scope for this test-only task): add a
       technique allowlist check to `load_config()` per ADR 0001 §3.

GAP-2 — No active write-verb guard (Category 1).
    G-1 GET-only is enforced STRUCTURALLY (every shipped tool issues only
    `requests.get`; no write tool exists) and at the SDK layer (empty
    mcp_servers, read-only system_prompt, disallowed Bash/Write/Edit/etc.).
    But `replay_log.write_entry()` does NOT validate `request["method"]`, so a
    graph_call recorded with method "POST"/"PATCH"/"DELETE" would be written
    without objection. If a future tool issued a write, nothing in the Python
    layer would stop it before the HTTP call.
    -> Remediation option (out of scope here): restrict `request["method"]` to
       "GET" in write_entry, or route all tools through a GET-only helper.

WHAT IS GENUINELY ENFORCED (and tested here as real refusals):
    * replay_log.write_entry() raises ValueError on a non-sandbox tenant_id
      (G-1/G-3 tenant lock) and on empty tenant_id.
    * write_entry() raises ValueError on a missing borrowed_client_id
      (G-3 no-tenant-app-reg posture).
    * No shipped tool issues a write HTTP verb (structural + behavioural).
    * No shipped tool implements any prohibited technique (refusal-by-absence).
    * The committed routing config routes none of the prohibited techniques.
=============================================================================
"""

from __future__ import annotations

import re
from pathlib import Path
from unittest import mock

import pytest

import identity
import replay_log
import tool_list_users
from replay_log import SANDBOX_TENANT_ID, ReplayLogEntry, write_entry
from rejewski_runtime import RoutingConfig, load_config

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"
TOOL_SCRIPTS = sorted(SCRIPTS.glob("tool_*.py"))

# Permanent out-of-scope techniques (threat-model §7 / ADR 0001 §3): persistence,
# create/modify-account, and non-M365 valid-accounts. All are WRITE-side or
# outside Rejewski's read-only M365 scope.
PROHIBITED_TECHNIQUES = ["T1053", "T1078.003", "T1136", "T1098"]

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


# ---------------------------------------------------------------------------
# Category 2 — Prohibited technique routing (G-1, G-4)
# ---------------------------------------------------------------------------
class TestProhibitedTechniqueRouting:
    @pytest.mark.parametrize("technique", PROHIBITED_TECHNIQUES)
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

    def test_prohibited_techniques_absent_from_committed_routing_config(self):
        """The committed rejewski.config.json routes none of the prohibited
        techniques (they are not even model-routed, let alone runnable)."""
        routing = load_config().rejewski.routing
        overlap = set(PROHIBITED_TECHNIQUES) & set(routing.hard_techniques)
        assert overlap == set(), f"prohibited techniques in routing: {overlap}"

    def test_routing_layer_provides_no_prohibition_DOCUMENTS_GAP1(self):
        """DOCUMENTS GAP-1 (not an enforcement test): RoutingConfig neither
        refuses nor blocks a prohibited technique_id — select_model() returns the
        default model (i.e. it would proceed) and is_hard() returns False. This
        pins the gap so it becomes visible in CI and would break (prompting an
        update to this test) if real technique-prohibition is ever added."""
        routing = RoutingConfig(
            default_model="claude-sonnet-4-6",
            hard_step_model="claude-opus-4-6",
        )
        for technique in PROHIBITED_TECHNIQUES:
            # No refusal, no exception — routing simply picks a model and proceeds.
            assert routing.select_model(technique_id=technique) == "claude-sonnet-4-6"
            assert routing.is_hard(technique_id=technique) is False


# ---------------------------------------------------------------------------
# Category 3 — Sandbox tenant lock (G-3)
# ---------------------------------------------------------------------------
class TestSandboxTenantLock:
    def test_write_entry_rejects_wrong_tenant(self, tmp_path):
        """G-1/G-3 tenant lock: a replay entry for any tenant other than the
        cloudharbordemo sandbox is refused before it is written."""
        entry = _entry(tenant_id="11111111-2222-3333-4444-555555555555")
        with pytest.raises(ValueError, match="tenant"):
            write_entry(entry, log_dir=tmp_path)

    def test_write_entry_rejects_empty_tenant(self, tmp_path):
        """An empty tenant_id is not the sandbox tenant, so it is refused."""
        entry = _entry(tenant_id="")
        with pytest.raises(ValueError, match="tenant"):
            write_entry(entry, log_dir=tmp_path)

    def test_write_entry_rejects_missing_borrowed_client(self, tmp_path):
        """G-3 no-tenant-app-reg posture: an entry without a borrowed_client_id
        is refused (the write path requires the borrowed FOCI client)."""
        entry = _entry(borrowed_client_id="")
        with pytest.raises(ValueError, match="borrowed_client_id"):
            write_entry(entry, log_dir=tmp_path)

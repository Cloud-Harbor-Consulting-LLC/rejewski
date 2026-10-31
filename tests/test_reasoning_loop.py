# SPDX-License-Identifier: MIT
import json

from lab_values import LAB_ACTOR_UPN, LAB_TENANT_ID
from replay_log import _VALIDATOR
from rejewski_runtime import RoutingConfig, load_config
import reasoning_loop


class TestRoutingConfig:
    def test_default_is_sonnet(self):
        routing = RoutingConfig(
            default_model="claude-sonnet-4-6",
            hard_step_model="claude-opus-4-6",
        )
        assert routing.select_model() == "claude-sonnet-4-6"
        assert routing.select_model(step="list_users") == "claude-sonnet-4-6"

    def test_hard_step_name_routes_to_opus(self):
        routing = RoutingConfig(
            default_model="claude-sonnet-4-6",
            hard_step_model="claude-opus-4-6",
            hard_steps=frozenset({"role_assignment_analysis"}),
        )
        assert routing.is_hard(step="role_assignment_analysis") is True
        assert (
            routing.select_model(step="role_assignment_analysis")
            == "claude-opus-4-6"
        )

    def test_hard_technique_routes_to_opus(self):
        routing = RoutingConfig(
            default_model="claude-sonnet-4-6",
            hard_step_model="claude-opus-4-6",
            hard_techniques=frozenset({"T1550.001"}),
        )
        assert routing.select_model(technique_id="T1550.001") == "claude-opus-4-6"
        assert routing.select_model(technique_id="T1087.004") == "claude-sonnet-4-6"

    def test_explicit_hard_override(self):
        routing = RoutingConfig(
            default_model="claude-sonnet-4-6",
            hard_step_model="claude-opus-4-6",
            hard_steps=frozenset({"role_assignment_analysis"}),
        )
        # hard=False forces Sonnet even for a registered hard step
        assert (
            routing.select_model(step="role_assignment_analysis", hard=False)
            == "claude-sonnet-4-6"
        )
        # hard=True forces Opus even for an unregistered step
        assert routing.select_model(step="list_users", hard=True) == "claude-opus-4-6"


class TestRoutingFromCommittedConfig:
    def test_committed_config_routes_sonnet_default_opus_hard(self):
        routing = load_config().rejewski.routing
        assert routing.default_model == "claude-sonnet-4-6"
        assert routing.hard_step_model == "claude-opus-4-6"
        # A routine enumeration step stays on Sonnet.
        assert routing.select_model(step="list_users") == "claude-sonnet-4-6"
        # Registered hard steps / techniques escalate to Opus.
        assert "role_assignment_analysis" in routing.hard_steps
        assert "T1550.001" in routing.hard_techniques


class TestReasoningLoop:
    def test_plan_produces_mixed_models(self):
        routing = load_config().rejewski.routing
        results = reasoning_loop.run_plan(
            reasoning_loop.PLAN, routing, run_id="RLOOP-TEST"
        )
        models = {r.model_id for r in results}
        assert "claude-sonnet-4-6" in models
        assert "claude-opus-4-6" in models, "expected at least one Opus-routed step"

    def test_emit_writes_model_id_stamped_entries(self, tmp_path):
        routing = load_config().rejewski.routing
        results = reasoning_loop.run_plan(
            reasoning_loop.PLAN,
            routing,
            run_id="RLOOP-TEST",
            emit=True,
            log_dir=tmp_path,
            actor_upn=LAB_ACTOR_UPN,
            tenant_id=LAB_TENANT_ID,
        )
        written = [r.written_path for r in results if r.written_path]
        assert len(written) == len(reasoning_loop.PLAN)

        seen_models = set()
        for result, path in zip(results, written):
            payload = json.loads(path.read_text())
            _VALIDATOR.validate(payload)  # schema v0.5
            assert payload["model_id"] == result.model_id
            assert payload["run_id"] == "RLOOP-TEST"
            assert payload["tenant_id"] == LAB_TENANT_ID
            seen_models.add(payload["model_id"])

        assert seen_models == {"claude-sonnet-4-6", "claude-opus-4-6"}


def test_emit_without_tenant_or_actor_is_refused(tmp_path, monkeypatch):
    """No built-in tenant or account: emitting needs both from the operator."""
    import pytest

    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    monkeypatch.delenv("COMPROMISED_USER_UPN", raising=False)
    routing = load_config().rejewski.routing
    with pytest.raises(ValueError, match="tenant ID"):
        reasoning_loop.run_plan(
            reasoning_loop.PLAN, routing, run_id="RLOOP-TEST", emit=True, log_dir=tmp_path
        )

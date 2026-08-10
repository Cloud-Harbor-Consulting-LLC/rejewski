"""
Rejewski runtime config loader.

Reads rejewski.config.json from the repo root, splits SDK-bound fields
from Rejewski-side concerns, and returns a typed RuntimeConfig with a
ClaudeAgentOptions instance ready to hand to the SDK.

Usage:
  from scripts.rejewski_runtime import load_config
  cfg = load_config()
  # cfg.options -> ClaudeAgentOptions
  # cfg.rejewski -> RejewskiConfig (analytics, logging, session policy)
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from claude_agent_sdk import ClaudeAgentOptions

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = REPO_ROOT / "rejewski.config.json"

SDK_FIELDS = {
    "model",
    "max_turns",
    "permission_mode",
    "system_prompt",
    "allowed_tools",
    "disallowed_tools",
    "mcp_servers",
    "cwd",
    "env",
    "setting_sources",
}

# Permanently out-of-scope ATT&CK techniques (threat-model §7, ADR 0001 §3):
# write-side persistence / account manipulation and non-M365 valid-accounts.
# These are never executable by Rejewski. `load_config()` refuses a config that
# references any of them, implementing ADR 0001 §3's "out-of-scope techniques are
# refused at config load, not at runtime." Parents (no sub-technique dot) also
# cover their sub-techniques; a specific sub-technique (e.g. T1078.003) prohibits
# only itself, so in-scope siblings such as T1078.004 remain allowed.
PROHIBITED_TECHNIQUES = frozenset(
    {
        "T1053",      # Scheduled Task/Job — write-side persistence
        "T1078.003",  # Valid Accounts: Local Accounts — outside M365 scope
        "T1136",      # Create Account — write
        "T1098",      # Account Manipulation — write
    }
)


def is_prohibited_technique(technique_id: str) -> bool:
    """True if `technique_id` is on the permanent out-of-scope list, matching a
    prohibited parent's sub-techniques but not an in-scope sibling of a
    prohibited sub-technique (T1078.003 prohibited; T1078.004 allowed)."""
    for prohibited in PROHIBITED_TECHNIQUES:
        if technique_id == prohibited:
            return True
        if "." not in prohibited and technique_id.startswith(prohibited + "."):
            return True
    return False


@dataclass
class RoutingConfig:
    """Sonnet/Opus model routing for the reasoning loop.

    The loop runs on ``default_model`` (Sonnet 4.6) by default and escalates a
    step to ``hard_step_model`` (Opus 4.6) when the step needs deeper, multi-hop
    inference. A step is "hard" when its name is in ``hard_steps`` or its mapped
    ATT&CK technique is in ``hard_techniques`` — callers can also force the
    decision explicitly via ``select_model(hard=...)``.
    """

    default_model: str = "claude-sonnet-4-6"
    hard_step_model: str = "claude-opus-4-6"
    hard_steps: frozenset[str] = field(default_factory=frozenset)
    hard_techniques: frozenset[str] = field(default_factory=frozenset)

    def is_hard(
        self,
        *,
        step: str | None = None,
        technique_id: str | None = None,
    ) -> bool:
        """True if the step warrants the stronger (Opus) model."""
        if step is not None and step in self.hard_steps:
            return True
        if technique_id is not None and technique_id in self.hard_techniques:
            return True
        return False

    def select_model(
        self,
        *,
        step: str | None = None,
        technique_id: str | None = None,
        hard: bool | None = None,
    ) -> str:
        """Return the model id to run this step on.

        ``hard`` (when not None) overrides the name/technique classification —
        pass ``hard=True`` to force Opus or ``hard=False`` to force Sonnet.
        """
        if hard is None:
            hard = self.is_hard(step=step, technique_id=technique_id)
        return self.hard_step_model if hard else self.default_model


@dataclass
class RejewskiConfig:
    analytics_disabled: bool = True
    session_keep_warm: bool = True
    audit_log_path: str = "logs/rejewski-audit.jsonl"
    redact_secrets: bool = True
    routing: RoutingConfig = field(default_factory=RoutingConfig)


@dataclass
class RuntimeConfig:
    options: ClaudeAgentOptions
    rejewski: RejewskiConfig
    raw: dict[str, Any] = field(default_factory=dict)


def load_config(path: Path | str | None = None) -> RuntimeConfig:
    config_path = Path(path) if path else CONFIG_PATH
    if not config_path.exists():
        raise FileNotFoundError(f"Rejewski config not found at {config_path}")

    raw = json.loads(config_path.read_text(encoding="utf-8"))

    sdk_kwargs = {k: v for k, v in raw.items() if k in SDK_FIELDS}
    options = ClaudeAgentOptions(**sdk_kwargs)

    rj = raw.get("rejewski", {})
    logging_cfg = rj.get("logging", {})
    routing_defaults = RoutingConfig()
    routing_cfg_raw = rj.get("routing", {})
    routing_cfg = RoutingConfig(
        default_model=routing_cfg_raw.get(
            "default_model", routing_defaults.default_model
        ),
        hard_step_model=routing_cfg_raw.get(
            "hard_step_model", routing_defaults.hard_step_model
        ),
        hard_steps=frozenset(routing_cfg_raw.get("hard_steps", ())),
        hard_techniques=frozenset(routing_cfg_raw.get("hard_techniques", ())),
    )

    # ADR 0001 §3 / G-4: refuse a config that references any permanently
    # out-of-scope technique. hard_techniques is the only technique-bearing config
    # field today; the check extends automatically to any technique ID added to
    # the config that routes through this loader.
    prohibited_referenced = sorted(
        t for t in routing_cfg.hard_techniques if is_prohibited_technique(t)
    )
    if prohibited_referenced:
        raise ValueError(
            "ADR 0001 §3 / G-4: config references out-of-scope technique(s) "
            f"{prohibited_referenced}; refused at config load."
        )

    rejewski_cfg = RejewskiConfig(
        analytics_disabled=rj.get("analytics_disabled", True),
        session_keep_warm=rj.get("session_keep_warm", True),
        audit_log_path=logging_cfg.get("audit_log_path", "logs/rejewski-audit.jsonl"),
        redact_secrets=logging_cfg.get("redact_secrets", True),
        routing=routing_cfg,
    )

    if rejewski_cfg.analytics_disabled:
        os.environ["DISABLE_TELEMETRY"] = "1"
        os.environ["DISABLE_ERROR_REPORTING"] = "1"

    return RuntimeConfig(options=options, rejewski=rejewski_cfg, raw=raw)


if __name__ == "__main__":
    cfg = load_config()
    print("Model:", cfg.options.model)
    print("Max turns:", cfg.options.max_turns)
    print("Permission mode:", cfg.options.permission_mode)
    print("Allowed tools:", cfg.options.allowed_tools)
    print("Disallowed tools:", cfg.options.disallowed_tools)
    print("MCP servers:", list((cfg.options.mcp_servers or {}).keys()))
    print("Analytics disabled:", cfg.rejewski.analytics_disabled)
    print("Session keep-warm:", cfg.rejewski.session_keep_warm)
    print("Audit log path:", cfg.rejewski.audit_log_path)
    print("Redact secrets:", cfg.rejewski.redact_secrets)
    routing = cfg.rejewski.routing
    print("Routing default model:", routing.default_model)
    print("Routing hard-step model:", routing.hard_step_model)
    print("Routing hard steps:", sorted(routing.hard_steps))
    print("Routing hard techniques:", sorted(routing.hard_techniques))
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


@dataclass
class RejewskiConfig:
    analytics_disabled: bool = True
    session_keep_warm: bool = True
    audit_log_path: str = "logs/rejewski-audit.jsonl"
    redact_secrets: bool = True


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
    rejewski_cfg = RejewskiConfig(
        analytics_disabled=rj.get("analytics_disabled", True),
        session_keep_warm=rj.get("session_keep_warm", True),
        audit_log_path=logging_cfg.get("audit_log_path", "logs/rejewski-audit.jsonl"),
        redact_secrets=logging_cfg.get("redact_secrets", True),
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
"""Smoke test: send a one-shot prompt to the Rejewski agent via the Claude Agent SDK.

Usage from the repo root:
    python scripts/test-prompt.py "List three ATT&CK techniques relevant to cloud account discovery."

Loads the same runtime config as the rest of Rejewski (rejewski.config.json + scripts/rejewski_runtime.py),
so model, permission_mode, allowed_tools, disallowed_tools, mcp_servers, env, and analytics_disabled all match
the production agent surface.
"""
import asyncio
import sys

from claude_agent_sdk import query

from rejewski_runtime import load_config


DEFAULT_PROMPT = "Say 'Rejewski test-prompt online.' and nothing else."


async def main(prompt: str) -> None:
    cfg = load_config()
    async for message in query(prompt=prompt, options=cfg.options):
        print(message)


if __name__ == "__main__":
    prompt = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PROMPT
    asyncio.run(main(prompt))
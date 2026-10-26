# SPDX-License-Identifier: MIT
"""
Claude Agent SDK hello-world smoke test for Rejewski.

Confirms the SDK can load ANTHROPIC_API_KEY from .env and reach the
Anthropic API end-to-end. No tools, no agent loop, just one turn.

Prereqs:
  npm install -g @anthropic-ai/claude-code
  pip install claude-agent-sdk python-dotenv
"""

import os
import sys
import asyncio
from dotenv import load_dotenv
from claude_agent_sdk import query, ClaudeAgentOptions

load_dotenv()

if not os.environ.get("ANTHROPIC_API_KEY"):
    print("ANTHROPIC_API_KEY missing from environment. Check .env.")
    sys.exit(1)


async def main() -> None:
    options = ClaudeAgentOptions(
        system_prompt=(
            "You are Rejewski, a defensive Microsoft 365 reconnaissance agent. "
            "This is a pre-flight smoke test. Reply briefly."
        ),
        max_turns=1,
    )
    async for message in query(
        prompt="Reply with exactly: Rejewski SDK smoke test online.",
        options=options,
    ):
        print(message)


if __name__ == "__main__":
    asyncio.run(main())
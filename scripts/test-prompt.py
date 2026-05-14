"""
scripts/test-prompt.py
Smoke-test a prompt against the Rejewski agent via Claude Agent SDK.

Usage:
    python scripts/test-prompt.py "Your prompt here"
"""
import sys
import time
from claude_agent_sdk import query
from rejewski_runtime import load_runtime


def main() -> None:
    if len(sys.argv) < 2:
        prompt = "Say 'Rejewski test-prompt online.' and nothing else."
    else:
        prompt = sys.argv[1]

    runtime = load_runtime()
    print(f"[runtime] model={runtime.options.model} max_turns={runtime.options.max_turns}")
    print(f"[prompt]  {prompt}")
    print()

    started = time.perf_counter()
    response_chunks: list[str] = []
    for message in query(prompt=prompt, options=runtime.options):
        if hasattr(message, "content"):
            for block in message.content:
                if getattr(block, "type", None) == "text":
                    response_chunks.append(block.text)
        elif isinstance(message, str):
            response_chunks.append(message)

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    print("".join(response_chunks))
    print()
    print(f"[done] elapsed={elapsed_ms}ms")


if __name__ == "__main__":
    main()
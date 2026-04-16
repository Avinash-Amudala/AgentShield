"""AgentShield + OpenAI Agents SDK integration example.

Demonstrates protecting OpenAI Agent function tools with AgentShield
so every tool invocation is policy-checked before execution.

Requires:  pip install agentshield[openai]
           (or: pip install openai-agents)

Run:  python examples/openai_example.py
"""

from __future__ import annotations

import asyncio
from typing import Any

try:
    from agents import Agent, FunctionTool  # type: ignore[import-untyped]
except ImportError:
    raise SystemExit(
        "OpenAI Agents SDK not installed. Run:  pip install agentshield[openai]\n"
        "  or:  pip install openai-agents"
    )

from agentshield import Shield, ToolCallBlocked, ToolCallContext
from agentshield.adapters.openai_sdk import shield_agent

shield = Shield(mode="enforce")


async def execute_sql(query: str) -> str:
    """Execute a SQL query."""
    return f"[result] Executed: {query}"


async def read_file(path: str) -> str:
    """Read a file from the filesystem."""
    return f"[result] Contents of {path}"


async def main() -> None:
    """Run a quick demo showing safe and blocked calls."""
    agent = Agent(
        name="demo-agent",
        instructions="You are a helpful assistant.",
        tools=[
            FunctionTool(execute_sql),
            FunctionTool(read_file),
        ],
    )

    shield_agent(agent, shield, agent_id="demo-agent")

    safe_ctx = ToolCallContext(
        tool_name="execute_sql",
        arguments={"query": "SELECT * FROM users WHERE id = 1"},
    )
    response = await shield.check(safe_ctx)
    print(f"[OK] Safe query: action={response.action.value}")

    dangerous_ctx = ToolCallContext(
        tool_name="execute_sql",
        arguments={"query": "DROP TABLE users"},
    )
    try:
        await shield.check(dangerous_ctx)
    except ToolCallBlocked as exc:
        print(f"[BLOCKED] {exc.response.reason}")


if __name__ == "__main__":
    asyncio.run(main())

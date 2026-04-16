"""AgentShield + LangChain integration example.

Demonstrates wrapping LangChain tools with AgentShield so every tool
invocation is policy-checked before execution.

Requires:  pip install agentshield[langchain]
           (or: pip install agentshield langchain langchain-core)

Run:  python examples/langchain_example.py
"""

from __future__ import annotations

import asyncio
from typing import Any

try:
    from langchain_core.tools import BaseTool, ToolException
except ImportError:
    raise SystemExit(
        "LangChain not installed. Run:  pip install agentshield[langchain]\n"
        "  or:  pip install langchain-core"
    )

from agentshield import Shield, ToolCallBlocked, ToolCallContext

# ---------------------------------------------------------------------------
# Shield setup
# ---------------------------------------------------------------------------

shield = Shield(mode="enforce")


# ---------------------------------------------------------------------------
# AgentShield-wrapped LangChain tool
# ---------------------------------------------------------------------------


class ShieldedSQLTool(BaseTool):
    """A LangChain tool that routes SQL queries through AgentShield."""

    name: str = "execute_sql"
    description: str = "Execute a SQL query against the database"

    def _run(self, query: str, **kwargs: Any) -> str:
        """Synchronously run the tool with AgentShield protection."""
        ctx = ToolCallContext(
            tool_name=self.name,
            arguments={"query": query, **kwargs},
        )
        try:
            asyncio.run(shield.check(ctx))
        except ToolCallBlocked as exc:
            raise ToolException(
                f"Blocked by AgentShield: {exc.response.reason}"
            ) from exc

        return f"[result] Executed: {query}"

    async def _arun(self, query: str, **kwargs: Any) -> str:
        """Asynchronously run the tool with AgentShield protection."""
        ctx = ToolCallContext(
            tool_name=self.name,
            arguments={"query": query, **kwargs},
        )
        try:
            await shield.check(ctx)
        except ToolCallBlocked as exc:
            raise ToolException(
                f"Blocked by AgentShield: {exc.response.reason}"
            ) from exc

        return f"[result] Executed: {query}"


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------


def main() -> None:
    """Run a quick demo showing safe and blocked calls."""
    tool = ShieldedSQLTool()

    # Safe query
    result = tool.invoke("SELECT name FROM employees WHERE id = 42")
    print(f"[OK] {result}")

    # Dangerous query — blocked
    try:
        tool.invoke("DROP TABLE employees")
    except ToolException as exc:
        print(f"[BLOCKED] {exc}")


if __name__ == "__main__":
    main()

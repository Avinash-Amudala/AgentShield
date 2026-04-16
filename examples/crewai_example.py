"""AgentShield + CrewAI integration example.

Demonstrates protecting CrewAI tool invocations with AgentShield so that
every tool call is policy-checked before execution.

Requires:  pip install agentshield crewai crewai-tools

Run:  python examples/crewai_example.py
"""

from __future__ import annotations

import asyncio
from typing import Any

try:
    from crewai.tools import BaseTool as CrewAIBaseTool
except ImportError:
    raise SystemExit("CrewAI not installed. Run:  pip install crewai crewai-tools")

from agentshield import Shield, ToolCallBlocked, ToolCallContext

# ---------------------------------------------------------------------------
# Shield setup
# ---------------------------------------------------------------------------

shield = Shield(mode="enforce")


# ---------------------------------------------------------------------------
# AgentShield-protected CrewAI tool
# ---------------------------------------------------------------------------


class ShieldedDatabaseQuery(CrewAIBaseTool):
    """CrewAI tool that executes SQL queries with AgentShield guardrails."""

    name: str = "database_query"
    description: str = "Execute a SQL query and return results"

    def _run(self, query: str, **kwargs: Any) -> str:
        """Execute the tool with policy checks."""
        ctx = ToolCallContext(
            tool_name=self.name,
            arguments={"query": query, **kwargs},
        )
        try:
            asyncio.run(shield.check(ctx))
        except ToolCallBlocked as exc:
            return f"BLOCKED by AgentShield: {exc.response.reason}"

        return f"[result] Query executed: {query}"


class ShieldedFileReader(CrewAIBaseTool):
    """CrewAI tool that reads files with AgentShield guardrails."""

    name: str = "read_file"
    description: str = "Read a file and return its contents"

    def _run(self, path: str, **kwargs: Any) -> str:
        """Execute the tool with policy checks."""
        ctx = ToolCallContext(
            tool_name=self.name,
            arguments={"path": path, **kwargs},
        )
        try:
            asyncio.run(shield.check(ctx))
        except ToolCallBlocked as exc:
            return f"BLOCKED by AgentShield: {exc.response.reason}"

        return f"[result] Contents of {path}"


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------


def main() -> None:
    """Run a quick demo showing safe and blocked calls."""
    db_tool = ShieldedDatabaseQuery()
    file_tool = ShieldedFileReader()

    # Safe query
    print(f"[OK] {db_tool._run('SELECT * FROM orders WHERE id = 1')}")

    # Dangerous query — blocked
    print(f"[BLOCKED] {db_tool._run('DROP TABLE orders')}")

    # Safe file read
    print(f"[OK] {file_tool._run('README.md')}")

    # Sensitive file read — blocked
    print(f"[BLOCKED] {file_tool._run('/etc/shadow')}")


if __name__ == "__main__":
    main()

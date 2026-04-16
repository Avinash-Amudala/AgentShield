"""AgentShield quickstart — protect a tool in three lines.

Run:  python examples/quickstart.py
"""

from __future__ import annotations

import agentshield

shield = agentshield.Shield()


@shield.protect
def execute_sql(query: str) -> str:
    """Simulate running a SQL query."""
    return f"Executed: {query}"


# Safe call — allowed through
result = execute_sql("SELECT * FROM users WHERE id = 1")
print(f"[OK] {result}")

# Dangerous call — blocked by DestructiveSQLRule
try:
    execute_sql("DROP TABLE users")
except agentshield.ToolCallBlocked as exc:
    print(f"[BLOCKED] {exc.response.reason}")

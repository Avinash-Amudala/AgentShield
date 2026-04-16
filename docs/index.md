# AgentShield

**The runtime firewall for AI agents. Protect any agent in 3 lines of code.**

---

## What is AgentShield?

AgentShield is a lightweight, framework-agnostic Python library that intercepts AI agent tool calls at runtime and enforces safety policies before they execute. It ships with 39 built-in rules mapped to the OWASP Top 10 for Agentic Applications, a hash-chained audit logger, and integrations for every major agent framework.

## Key Principles

- **Zero dependencies** in the core — nothing to break, nothing to audit
- **Sub-millisecond latency** — agents don't even notice it's there
- **Framework agnostic** — works with MCP, LangChain, CrewAI, OpenAI Agents SDK, or plain Python
- **OWASP-aligned** — every rule maps to ASI01–ASI10
- **Tamper-proof audit** — SHA-256 hash-chained JSONL logs

## Quick Example

```python
import agentshield

shield = agentshield.Shield()

@shield.protect
def execute_sql(query: str) -> str:
    return db.execute(query)

# Safe call — passes through
execute_sql("SELECT * FROM users WHERE id = 1")

# Dangerous call — blocked automatically
execute_sql("DROP TABLE users")
# -> ToolCallBlocked: Destructive SQL detected (ASI02)
```

## How It Works

```
Agent -> Tool Call -> AgentShield Policy Engine -> Allow / Deny / Escalate
                                |
                          Audit Logger
                          (hash-chained JSONL)
```

1. Your agent makes a tool call (function call, API request, etc.)
2. AgentShield intercepts it via a decorator, middleware, or adapter
3. The policy engine evaluates all applicable rules in priority order
4. **Allow**: the call proceeds normally
5. **Deny**: the call is blocked and a `ToolCallBlocked` exception is raised
6. **Escalate**: the call is routed to a human via Slack, Discord, or terminal
7. Every decision is logged to a tamper-proof audit trail

## Next Steps

- [Getting Started](getting-started.md) — install and protect your first agent in 5 minutes
- [Configuration](configuration.md) — customize rules, thresholds, and HITL channels
- [Rules Reference](rules-reference.md) — all 39 built-in rules documented
- [OWASP Mapping](owasp-mapping.md) — how AgentShield covers ASI01–ASI10

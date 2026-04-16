# Getting Started

Get AgentShield running in under 5 minutes.

---

## Installation

```bash
# Core library (zero dependencies)
pip install agentshield
```

### Optional Extras

```bash
pip install agentshield[mcp]          # MCP server support
pip install agentshield[langchain]    # LangChain adapter
pip install agentshield[crewai]       # CrewAI adapter
pip install agentshield[openai]       # OpenAI Agents SDK
pip install agentshield[dashboard]    # Real-time dashboard
pip install agentshield[hitl]         # Human-in-the-loop gateway
pip install agentshield[otel]         # OpenTelemetry export
pip install agentshield[all]          # Everything
pip install agentshield[dev]          # Development tools
```

---

## Protect Any Python Function

The simplest integration — wrap any function with `@shield.protect`:

```python
import agentshield

shield = agentshield.Shield()

@shield.protect
def execute_sql(query: str) -> str:
    return db.execute(query)

@shield.protect
def read_file(path: str) -> str:
    return open(path).read()

# Safe calls pass through transparently
result = execute_sql("SELECT * FROM users WHERE id = 1")

# Dangerous calls are blocked
try:
    execute_sql("DROP TABLE users")
except agentshield.ToolCallBlocked as e:
    print(f"Blocked: {e.response.reason}")
    print(f"Rule: {e.response.rule_name}")
    print(f"OWASP: {e.response.owasp_id}")
```

---

## Protect an MCP Server

```python
from mcp.server import Server
from agentshield.adapters.mcp import shield_mcp_server

server = Server("my-server")
shield_mcp_server(server)

# All MCP tool calls now pass through AgentShield
```

---

## Protect a LangChain Agent

```python
from langchain.tools import Tool
from agentshield.adapters.langchain import ShieldedToolkit

tools = [sql_tool, file_tool, search_tool]
shielded = ShieldedToolkit(tools)

agent = create_react_agent(llm, shielded.tools)
```

---

## Protect a CrewAI Crew

```python
from crewai import Crew
from agentshield.adapters.crewai import shield_crew

crew = Crew(agents=[...], tasks=[...])
shield_crew(crew)
```

---

## Protect an OpenAI Agent

```python
from agents import Agent
from agentshield.adapters.openai_sdk import shield_agent

agent = Agent(name="assistant", tools=[...])
shield_agent(agent)
```

---

## Configuration

Create `agentshield.yaml` in your project root for custom configuration:

```yaml
mode: enforce

rules:
  destructive_sql:
    enabled: true
  rate_limiter:
    enabled: true
    max_calls: 100
    window_seconds: 60

audit:
  file: shield.jsonl
  hash_chain: true
```

See the [Configuration Reference](configuration.md) for all options.

---

## CLI Commands

```bash
# Verify audit log integrity
agentshield verify shield.jsonl

# Show statistics from audit log
agentshield stats shield.jsonl

# Export audit log to CSV
agentshield export shield.jsonl --format csv

# Start the dashboard
agentshield serve --port 9090
```

---

## Next Steps

- [Configuration Reference](configuration.md) — all YAML options
- [Rules Reference](rules-reference.md) — all 39 built-in rules
- [OWASP Mapping](owasp-mapping.md) — security coverage details

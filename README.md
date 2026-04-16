<div align="center">

# AgentShield

**The runtime firewall for AI agents.**
**Protect any agent in 3 lines of code.**

[![PyPI](https://img.shields.io/pypi/v/agentshield)](https://pypi.org/project/agentshield/)
[![Python](https://img.shields.io/pypi/pyversions/agentshield)](https://pypi.org/project/agentshield/)
[![CI](https://github.com/Avinash-Amudala/AgentShield/actions/workflows/ci.yml/badge.svg)](https://github.com/Avinash-Amudala/AgentShield/actions)
[![Coverage](https://codecov.io/gh/Avinash-Amudala/AgentShield/branch/main/graph/badge.svg)](https://codecov.io/gh/Avinash-Amudala/AgentShield)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

</div>

---

## Quickstart

```bash
pip install agentshield
```

```python
import agentshield

shield = agentshield.Shield()

@shield.protect
def execute_sql(query: str) -> str:
    return db.execute(query)

# Agent calls execute_sql("DROP TABLE users")
# -> Blocked by AgentShield: Destructive SQL detected (ASI02)
```

That's it. Your agent is now protected with 39 built-in safety rules.

---

## Why AgentShield?

AI agents are production infrastructure. They execute code, manage databases, and call APIs autonomously. But:

- **88%** of organizations have had agent security incidents ([Gravitee 2026 Report](https://gravitee.io/reports/agentic-ai-2026))
- **68%** cannot distinguish human from AI agent activity ([CSA Survey](https://cloudsecurityalliance.org/research))
- **EU AI Act** high-risk obligations take effect August 2026
- Every major framework is **permissive by default** — if a tool is registered, the agent can call it

AgentShield fixes this in 3 lines of code. Zero dependencies in the core. Sub-millisecond latency. Full OWASP coverage.

---

## Features

| Feature | AgentShield | MS Agent Gov Toolkit | NemoClaw | AgentLock |
|---------|:-----------:|:-------------------:|:--------:|:---------:|
| pip install + 3 lines | :white_check_mark: | :x: (7 packages) | :x: (alpha) | :x: (auth only) |
| Framework agnostic | :white_check_mark: | :x: (Azure-focused) | :x: (NVIDIA) | :warning: |
| 39 pre-built rules | :white_check_mark: | :white_check_mark: | :x: | :x: |
| OWASP ASI01-10 mapped | :white_check_mark: | :white_check_mark: | :x: | :x: |
| Human-in-the-loop | :white_check_mark: | :white_check_mark: | :x: | :x: |
| Real-time dashboard | :white_check_mark: | :warning: | :x: | :x: |
| Zero dependencies (core) | :white_check_mark: | :x: | :x: | :x: |
| Sub-millisecond latency | :white_check_mark: (0.3ms p50) | :white_check_mark: (0.1ms p99) | ? | ? |

---

## Supported Frameworks

| Framework | Integration | Example |
|-----------|------------|---------|
| Any Python function | `@shield.protect` | [quickstart.py](examples/quickstart.py) |
| MCP Servers | `shield_mcp_server(server)` | [mcp_example.py](examples/mcp_example.py) |
| LangChain | `ShieldedToolkit(tools)` | [langchain_example.py](examples/langchain_example.py) |
| CrewAI | `shield_crew(crew)` | [crewai_example.py](examples/crewai_example.py) |
| OpenAI Agents SDK | `shield_agent(agent)` | [openai_example.py](examples/openai_example.py) |

---

## OWASP Top 10 for Agentic Applications

AgentShield maps every rule to the [OWASP Top 10 for Agentic Applications](https://owasp.org/www-project-top-10-for-agentic-applications/).

| OWASP ID | Risk | AgentShield Coverage |
|----------|------|---------------------|
| ASI01 | Goal Hijacking | `prompt_injection`, `encoded_injection`, `role_override`, `delimiter_injection` |
| ASI02 | Tool Misuse | `destructive_sql`, `path_traversal`, `destructive_shell`, `reverse_shell`, `dangerous_eval` |
| ASI03 | Identity Abuse | `tool_allowlist`, `cross_agent_scope`, `argument_schema` |
| ASI04 | Data Leakage | `api_key_leak`, `token_leak`, `pii_leak`, `domain_denylist`, `internal_network_access` |
| ASI05 | Memory Poisoning | `require_approval_pattern`, input sanitization |
| ASI06 | Rogue Agent | `tool_allowlist`, `rate_limiter`, `cost_guard` |
| ASI07 | Cascading Failures | `per_tool_rate_limit`, `session_rate_limit`, `burst_detection`, `session_cost_ceiling` |
| ASI08 | Insufficient Logging | Hash-chained JSONL audit logger with SHA-256 tamper detection (`agentshield verify`) |
| ASI09 | Human Override Failure | HITL gateway with Slack, Discord, and terminal channels |
| ASI10 | Multi-Agent Exploitation | `cross_agent_scope`, `agent_id_validation` |

---

## Configuration

Create an `agentshield.yaml` in your project root:

```yaml
mode: enforce        # enforce | monitor | dry-run

log_file: shield.jsonl

rules:
  destructive_sql:
    enabled: true
    action: deny
  credential_leak:
    enabled: true
    action: deny
  rate_limiter:
    enabled: true
    max_calls: 100
    window_seconds: 60
  cost_guard:
    enabled: true
    max_cost_usd: 10.0
  scope:
    enabled: true
    allowed_tools:
      - execute_sql
      - read_file
      - search_web

hitl:
  timeout: 300
  timeout_action: deny
  channels:
    - type: slack
      webhook_url: ${SLACK_WEBHOOK_URL}

custom_rules:
  - name: block_twitter_posts
    tool_patterns: ["post_tweet", "send_tweet"]
    action: deny
    reason: "Twitter posting requires manual review"
```

---

## Performance

| Metric | Value |
|--------|-------|
| Policy evaluation (p50) | 0.3ms |
| Policy evaluation (p99) | <1.0ms |
| Memory footprint | ~15MB |
| Core dependencies | 0 |

---

## Installation

```bash
# Core (zero dependencies)
pip install agentshield

# With specific integrations
pip install agentshield[config]       # YAML config support (PyYAML)
pip install agentshield[mcp]          # MCP server support
pip install agentshield[langchain]    # LangChain adapter
pip install agentshield[crewai]       # CrewAI adapter
pip install agentshield[openai]       # OpenAI Agents SDK
pip install agentshield[dashboard]    # Real-time dashboard
pip install agentshield[hitl]         # Human-in-the-loop gateway
pip install agentshield[otel]         # OpenTelemetry export

# Everything
pip install agentshield[all]

# Development
pip install agentshield[dev]
```

---

## Documentation

Full documentation is available at [avinash-amudala.github.io/AgentShield](https://avinash-amudala.github.io/AgentShield/).

- [Getting Started](https://avinash-amudala.github.io/AgentShield/getting-started/)
- [Configuration Reference](https://avinash-amudala.github.io/AgentShield/configuration/)
- [Rules Reference](https://avinash-amudala.github.io/AgentShield/rules-reference/)
- [OWASP Mapping](https://avinash-amudala.github.io/AgentShield/owasp-mapping/)
- [API Reference](https://avinash-amudala.github.io/AgentShield/api-reference/)

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

```bash
git clone https://github.com/Avinash-Amudala/AgentShield.git
cd AgentShield
pip install -e ".[dev]"
pytest
```

---

## License

[MIT](LICENSE) — Copyright (c) 2026 Avinash Amudala

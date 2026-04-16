<div align="center">

# AgentShield

**The runtime firewall for AI agents.**
**Protect any agent in 3 lines of code.**

[![PyPI](https://img.shields.io/pypi/v/agentshield-fw)](https://pypi.org/project/agentshield-fw/)
[![Python](https://img.shields.io/pypi/pyversions/agentshield-fw)](https://pypi.org/project/agentshield-fw/)
[![CI](https://github.com/Avinash-Amudala/AgentShield/actions/workflows/ci.yml/badge.svg)](https://github.com/Avinash-Amudala/AgentShield/actions)
[![Coverage](https://codecov.io/gh/Avinash-Amudala/AgentShield/branch/main/graph/badge.svg)](https://codecov.io/gh/Avinash-Amudala/AgentShield)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

</div>

---

## Quickstart

```bash
pip install agentshield-fw
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

## How is this different?

Most "agent security" tools are **static scanners** — they analyze config files, review prompts offline, or audit logs after the fact. That's SAST (Static Analysis). Useful, but the agent is already running unsupervised.

AgentShield is a **runtime firewall**. It sits between your agent and its tools, intercepts every call as it happens, and blocks dangerous actions before they execute. That's the difference between a code linter and a WAF.

| | Static scanners | **AgentShield** |
|---|---|---|
| **When** | Before or after deployment | During every tool call |
| **What** | Scans configs, prompts, logs | Intercepts live function calls |
| **Action** | Reports findings | Blocks, escalates, or allows in real-time |
| **Analogy** | SAST / code review | WAF / runtime firewall |

**Others scan your config. AgentShield protects your agent while it runs.**

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
| Runtime interception | :white_check_mark: | :x: (policy only) | :x: (static) | :x: (auth only) |
| pip install + 3 lines | :white_check_mark: | :x: (7 packages) | :x: (alpha) | :x: (auth only) |
| Framework agnostic | :white_check_mark: | :x: (Azure-focused) | :x: (NVIDIA) | :warning: |
| 39 pre-built rules | :white_check_mark: | :white_check_mark: | :x: | :x: |
| OWASP ASI01-10 100% coverage | :white_check_mark: | :white_check_mark: | :x: | :x: |
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

## OWASP Top 10 for Agentic Applications — 50/50 (100%)

AgentShield is benchmarked against the [OWASP Top 10 for Agentic Applications](https://owasp.org/www-project-top-10-for-agentic-applications/) with 5 adversarial scenarios per category. Every scenario is detected.

Run it yourself: `python benchmarks/owasp_coverage.py`

| ID | Threat | Score | Rules that fire |
|---|---|:---:|---|
| ASI01 | **Prompt Injection** | 5/5 | `direct_injection`, `encoded_injection`, `role_override`, `delimiter_injection` |
| ASI02 | **Tool Misuse** | 5/5 | `destructive_sql`, `destructive_shell`, `reverse_shell`, `sql_union_injection`, `dangerous_eval`, `path_traversal`, `privilege_escalation` |
| ASI03 | **Excessive Agency** | 5/5 | `require_approval_pattern` (deploy/destroy/drop/delete), `dangerous_eval` |
| ASI04 | **Insufficient Access Controls** | 5/5 | `internal_network_access` (SSRF), `api_key_leak`, `token_leak`, `sensitive_file_read`, `path_traversal` |
| ASI05 | **Improper Output Handling** | 5/5 | `pii_leak`, `password_leak`, `api_key_leak`, `env_var_leak`, `credential_leak` |
| ASI06 | **Multi-Agent Delegation** | 5/5 | `privilege_escalation` (chmod/su/chown), `sql_admin_commands` (GRANT), `path_traversal` |
| ASI07 | **Denial of Service** | 5/5 | `destructive_shell` (fork bomb, dd, mkfs), `destructive_sql` (DELETE/TRUNCATE without WHERE) |
| ASI08 | **Model Theft / IP** | 5/5 | `data_exfiltration_shell` (scp/curl/wget/rsync), `path_traversal`, `sensitive_file_read` |
| ASI09 | **Human Oversight** | 5/5 | `require_approval_pattern`, `require_approval_financial` ($100+ threshold), `require_approval_data_export` (1000+ rows) |
| ASI10 | **Insecure Plugins** | 5/5 | `reverse_shell`, `dangerous_eval`, `sql_comment_injection`, `sensitive_file_read` |
| | **Total** | **50/50** | **39 built-in rules, zero configuration required** |

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
pip install agentshield-fw

# With specific integrations
pip install "agentshield-fw[config]"       # YAML config support (PyYAML)
pip install "agentshield-fw[mcp]"          # MCP server support
pip install "agentshield-fw[langchain]"    # LangChain adapter
pip install "agentshield-fw[crewai]"       # CrewAI adapter
pip install "agentshield-fw[openai]"       # OpenAI Agents SDK
pip install "agentshield-fw[dashboard]"    # Real-time dashboard
pip install "agentshield-fw[hitl]"         # Human-in-the-loop gateway
pip install "agentshield-fw[otel]"         # OpenTelemetry export

# Everything
pip install "agentshield-fw[all]"

# Development
pip install -e ".[dev]"
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

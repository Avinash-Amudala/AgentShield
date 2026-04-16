# Configuration Reference

AgentShield is configured via a YAML file (`agentshield.yaml`) in your project root, environment variables, or programmatically in Python.

---

## Loading Order

Configuration is resolved in this order (later overrides earlier):

1. Built-in defaults
2. `agentshield.yaml` in the current working directory
3. File specified by `AGENTSHIELD_CONFIG` environment variable
4. Environment variables prefixed with `AGENTSHIELD_`
5. Programmatic overrides via `Shield(config=...)`

---

## Complete YAML Reference

```yaml
# Operating mode: enforce | monitor | disabled
#   enforce  — block/escalate tool calls that violate policies
#   monitor  — log violations but allow all calls through
#   disabled — no policy evaluation, no logging
mode: enforce

# Rule configuration
rules:
  # SQL Safety
  destructive_sql:
    enabled: true
    action: deny              # deny | escalate | monitor
    patterns:                 # override default regex patterns
      - '\bDROP\s+(TABLE|DATABASE)\b'
      - '\bTRUNCATE\s+TABLE\b'
    allow_patterns: []        # explicit allowlist overrides

  sql_union_injection:
    enabled: true
    action: deny

  sql_comment_injection:
    enabled: true
    action: deny

  sql_batch_execution:
    enabled: true
    action: escalate

  sql_admin_commands:
    enabled: true
    action: deny

  # File System Safety
  path_traversal:
    enabled: true
    action: deny

  sensitive_file_read:
    enabled: true
    action: deny

  write_outside_sandbox:
    enabled: true
    action: deny
    sandbox_dir: "."          # restrict writes to this directory

  symlink_attack:
    enabled: true
    action: deny

  executable_write:
    enabled: true
    action: escalate

  # Shell Command Safety
  destructive_shell:
    enabled: true
    action: deny

  reverse_shell:
    enabled: true
    action: deny

  privilege_escalation:
    enabled: true
    action: deny

  data_exfiltration_shell:
    enabled: true
    action: escalate

  dangerous_eval:
    enabled: true
    action: deny

  # Network Safety
  internal_network_access:
    enabled: true
    action: deny

  domain_denylist:
    enabled: true
    action: deny
    denied_domains: []

  domain_allowlist:
    enabled: false            # disabled by default (allow all)
    allowed_domains: []

  dns_rebinding:
    enabled: true
    action: deny

  # Credential & Data Leak Prevention
  api_key_leak:
    enabled: true
    action: deny

  token_leak:
    enabled: true
    action: deny

  pii_leak:
    enabled: true
    action: escalate

  password_leak:
    enabled: true
    action: deny

  env_var_leak:
    enabled: true
    action: escalate

  # Prompt Injection Detection
  prompt_injection:
    enabled: true
    action: deny

  encoded_injection:
    enabled: true
    action: deny

  role_override:
    enabled: true
    action: deny

  delimiter_injection:
    enabled: true
    action: deny

  # Rate Limiting
  rate_limiter:
    enabled: true
    max_calls: 100            # per tool, per window
    window_seconds: 60

  session_rate_limit:
    enabled: true
    max_calls: 500            # total calls per session
    window_seconds: 3600

  burst_detection:
    enabled: true
    max_calls: 10             # max calls per second
    action: escalate

  # Scope Enforcement
  scope:
    enabled: false            # opt-in
    allowed_tools: []         # list of allowed tool names
    argument_schemas: {}      # JSON Schema per tool

  cross_agent_scope:
    enabled: false

  # Cost Control
  cost_guard:
    enabled: false            # opt-in
    max_cost_usd: 10.0
    cost_per_call: {}         # tool_name -> cost in USD

  # Human Approval Gates
  require_approval_pattern:
    enabled: false
    tool_patterns: []         # glob patterns like "deploy_*"

  require_approval_financial:
    enabled: false
    threshold_usd: 100.0

  require_approval_data_export:
    enabled: false
    row_threshold: 1000

# Human-in-the-loop configuration
hitl:
  channel: terminal           # slack | discord | terminal
  timeout_seconds: 300        # how long to wait for human response
  default_action: deny        # action if timeout: deny | allow

  slack:
    webhook_url: ${SLACK_WEBHOOK_URL}
    channel: "#agent-approvals"

  discord:
    webhook_url: ${DISCORD_WEBHOOK_URL}

# Audit logging
audit:
  enabled: true
  file: shield.jsonl
  hash_chain: true            # SHA-256 hash chaining for tamper detection
  max_file_size_mb: 100       # rotate after this size
  include_arguments: true     # log tool call arguments (disable for PII)

# Dashboard
dashboard:
  enabled: false
  port: 9090
  host: "0.0.0.0"

# Custom rules (no Python required)
custom_rules:
  - name: block_twitter_posts
    description: "Prevent agent from posting to Twitter/X"
    tool_patterns: ["post_tweet", "send_tweet", "twitter_*"]
    action: deny
    reason: "Twitter posting requires manual review"
    owasp_id: ASI02

  - name: approval_for_email
    description: "Require approval before sending any email"
    tool_patterns: ["send_email", "gmail_send", "smtp_send"]
    action: escalate
    reason: "Email sending requires human approval"
```

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AGENTSHIELD_CONFIG` | Path to YAML config file | `./agentshield.yaml` |
| `AGENTSHIELD_MODE` | Operating mode | `enforce` |
| `AGENTSHIELD_LOG_FILE` | Audit log file path | `shield.jsonl` |
| `SLACK_WEBHOOK_URL` | Slack webhook for HITL | — |
| `DISCORD_WEBHOOK_URL` | Discord webhook for HITL | — |

---

## Programmatic Configuration

```python
from agentshield import Shield
from agentshield.core.config import ShieldConfig

config = ShieldConfig(
    mode="enforce",
    rules={
        "destructive_sql": {"enabled": True, "action": "deny"},
        "rate_limiter": {"enabled": True, "max_calls": 50},
    },
    audit={"file": "my-audit.jsonl", "hash_chain": True},
)

shield = Shield(config=config)
```

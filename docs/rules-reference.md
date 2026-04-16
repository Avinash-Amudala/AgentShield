# Rules Reference

AgentShield ships with 39 built-in rules across 10 categories, covering all OWASP ASI01–ASI10 risks. Every rule can be enabled, disabled, or configured via YAML.

---

## Rule Actions

| Action | Behavior |
|--------|----------|
| `deny` | Block the tool call and raise `ToolCallBlocked` |
| `escalate` | Route to a human via HITL gateway for approval |
| `monitor` | Allow the call but log a warning |
| `allow` | Explicitly allow (used in evaluation results) |

---

## Priority Order

Rules are evaluated in priority order (lower number = higher priority). First `deny` or `escalate` result wins.

| Priority | Category | Rules |
|----------|----------|-------|
| 1–9 | Critical safety | Shell commands, reverse shells |
| 10–19 | Data protection | SQL injection, credential leak |
| 20–29 | Access control | Scope enforcement, network blocks |
| 30–39 | Resource control | Rate limiting, cost guard |
| 40–49 | Human gates | Approval requirements |
| 50+ | Custom | User-defined rules |

---

## Category 1: SQL Safety

**File:** `src/agentshield/rules/sql_injection.py`
**OWASP:** ASI02 (Tool Misuse)

### `destructive_sql`

Blocks SQL operations that could cause data loss.

| What it detects | Pattern |
|-----------------|---------|
| DROP TABLE/DATABASE/INDEX/VIEW | `\bDROP\s+(TABLE\|DATABASE\|INDEX\|VIEW)\b` |
| TRUNCATE TABLE | `\bTRUNCATE\s+TABLE\b` |
| DELETE without WHERE | `\bDELETE\s+FROM\s+\w+\s*$` |
| ALTER TABLE DROP | `\bALTER\s+TABLE\s+\w+\s+DROP\b` |

**Default action:** `deny`

**Configuration:**
```yaml
destructive_sql:
  enabled: true
  action: deny
  patterns: [...]        # override detection patterns
  allow_patterns: [...]  # explicit allowlist
```

### `sql_union_injection`

Blocks UNION-based SQL injection attempts.

| What it detects | Pattern |
|-----------------|---------|
| UNION SELECT | `\bUNION\s+(ALL\s+)?SELECT\b` |

**Default action:** `deny`

### `sql_comment_injection`

Blocks SQL comment injection used to bypass filters.

| What it detects | Pattern |
|-----------------|---------|
| Double-dash comments | `--` |
| Block comments | `\/\*.*\*\/` |
| Hash comments | `#` in SQL context |

**Default action:** `deny`

### `sql_batch_execution`

Blocks multiple SQL statements in a single call.

| What it detects | Pattern |
|-----------------|---------|
| Statement separators | Multiple `;` in a single argument |

**Default action:** `escalate`

### `sql_admin_commands`

Blocks administrative SQL commands.

| What it detects | Pattern |
|-----------------|---------|
| GRANT/REVOKE | `\bGRANT\b`, `\bREVOKE\b` |
| User management | `\bCREATE\s+USER\b`, `\bALTER\s+USER\b` |

**Default action:** `deny`

---

## Category 2: File System Safety

**File:** `src/agentshield/rules/filesystem.py`
**OWASP:** ASI02 (Tool Misuse)

### `path_traversal`

Blocks path traversal attempts that escape the sandbox.

| What it detects | Pattern |
|-----------------|---------|
| Directory traversal | `../` sequences |
| Absolute paths | Paths outside configured sandbox directory |

**Default action:** `deny`

### `sensitive_file_read`

Blocks access to sensitive system and credential files.

| What it detects | Files |
|-----------------|-------|
| System credentials | `/etc/passwd`, `/etc/shadow` |
| Environment files | `.env`, `.env.local` |
| Private keys | `*.pem`, `*.key` |
| SSH config | `~/.ssh/*` |

**Default action:** `deny`

### `write_outside_sandbox`

Restricts file writes to a configured sandbox directory.

**Default action:** `deny`
**Configuration:** `sandbox_dir` (default: current working directory)

### `symlink_attack`

Blocks creation of symlinks pointing outside the sandbox.

**Default action:** `deny`

### `executable_write`

Detects writes of files with executable extensions.

| What it detects | Extensions |
|-----------------|------------|
| Scripts | `.sh`, `.bash`, `.zsh` |
| Binaries | `.exe`, `.bat`, `.cmd` |
| Python | `.py` with shebang |

**Default action:** `escalate`

---

## Category 3: Shell Command Safety

**File:** `src/agentshield/rules/shell_command.py`
**OWASP:** ASI02 (Tool Misuse)

### `destructive_shell`

Blocks commands that could destroy data or systems.

| What it detects | Examples |
|-----------------|---------|
| Recursive delete | `rm -rf`, `rm -r /` |
| Disk operations | `mkfs`, `dd if=` |
| Fork bombs | `:(){ :\|:& };:` |

**Default action:** `deny`

### `reverse_shell`

Blocks reverse shell payloads.

| What it detects | Examples |
|-----------------|---------|
| Bash reverse shell | `bash -i >& /dev/tcp` |
| Netcat | `nc -e /bin/bash` |
| Python sockets | `python -c "import socket"` |

**Default action:** `deny`

### `privilege_escalation`

Blocks privilege escalation attempts.

| What it detects | Examples |
|-----------------|---------|
| Sudo | `sudo` commands |
| User switching | `su -` |
| Permissions | `chmod 777`, `chown root` |

**Default action:** `deny`

### `data_exfiltration_shell`

Detects potential data exfiltration via shell commands.

| What it detects | Examples |
|-----------------|---------|
| HTTP uploads | `curl` to external IPs |
| File transfer | `wget`, `scp` to unknown hosts |

**Default action:** `escalate`

### `dangerous_eval`

Blocks dynamic code execution.

| What it detects | Examples |
|-----------------|---------|
| Python eval | `eval()` with dynamic input |
| Python exec | `exec()` with dynamic input |
| Compile | `compile()` with dynamic input |

**Default action:** `deny`

---

## Category 4: Network Safety

**File:** `src/agentshield/rules/network.py`
**OWASP:** ASI04 (Data Leakage)

### `internal_network_access`

Blocks requests to private/internal IP ranges (SSRF prevention).

| What it detects | Ranges |
|-----------------|--------|
| Class A private | `10.0.0.0/8` |
| Class B private | `172.16.0.0/12` |
| Class C private | `192.168.0.0/16` |
| Loopback | `127.0.0.0/8` |
| Link-local | `169.254.0.0/16` |

**Default action:** `deny`

### `domain_denylist`

Blocks requests to explicitly denied domains.

**Default action:** `deny`
**Configuration:** `denied_domains: list[str]`

### `domain_allowlist`

When enabled, blocks requests to any domain NOT in the allowlist.

**Default action:** `deny`
**Configuration:** `allowed_domains: list[str]` (empty = disabled)

### `dns_rebinding`

Blocks domains that resolve to private IP ranges.

**Default action:** `deny`

---

## Category 5: Credential & Data Leak Prevention

**File:** `src/agentshield/rules/credential_leak.py`
**OWASP:** ASI04 (Data Leakage)

### `api_key_leak`

Detects API keys in outbound tool call arguments.

| Provider | Pattern |
|----------|---------|
| AWS | `AKIA[0-9A-Z]{16}` |
| Google | `AIza[0-9A-Za-z\-_]{35}` |
| OpenAI / Anthropic | `sk-[a-zA-Z0-9]{20,}` |
| Stripe | `sk_live_[a-zA-Z0-9]{24,}` |
| GitHub | `ghp_[a-zA-Z0-9]{36}` |
| Slack | `xoxb-[0-9]{10,}-[a-zA-Z0-9]{24,}` |

**Default action:** `deny`

### `token_leak`

Detects bearer tokens, JWTs, and OAuth tokens in arguments.

**Default action:** `deny`

### `pii_leak`

Detects personally identifiable information in outbound tool calls.

| What it detects | Examples |
|-----------------|---------|
| Social Security Numbers | `XXX-XX-XXXX` pattern |
| Credit card numbers | Luhn-valid 13-19 digit sequences |
| Email addresses | Standard email pattern |

**Default action:** `escalate`

### `password_leak`

Detects password-like values in arguments being sent to external tools.

**Default action:** `deny`

### `env_var_leak`

Detects references to environment variables containing sensitive keywords (SECRET, KEY, TOKEN, PASSWORD).

**Default action:** `escalate`

---

## Category 6: Prompt Injection Detection

**File:** `src/agentshield/rules/prompt_injection.py`
**OWASP:** ASI01 (Goal Hijacking)

### `direct_injection`

Detects direct prompt injection attempts in tool arguments.

| What it detects | Examples |
|-----------------|---------|
| Instruction override | "ignore previous instructions" |
| Identity hijacking | "you are now", "act as" |
| System prompt injection | "system: " prefix in args |

**Default action:** `deny`

### `encoded_injection`

Detects injection payloads hidden via encoding.

| What it detects | Encoding |
|-----------------|----------|
| Base64-encoded payloads | Base64 decode + re-check |
| Hex-encoded payloads | Hex decode + re-check |
| URL-encoded payloads | URL decode + re-check |

**Default action:** `deny`

### `role_override`

Blocks attempts to set system/assistant roles in tool arguments.

**Default action:** `deny`

### `delimiter_injection`

Detects model-specific delimiter tokens in arguments.

| What it detects | Tokens |
|-----------------|--------|
| OpenAI | `<\|im_start\|>`, `<\|im_end\|>` |
| Llama | `[INST]`, `[/INST]` |
| Generic | `<system>`, `</system>` |

**Default action:** `deny`

---

## Category 7: Rate Limiting & Resource Control

**File:** `src/agentshield/rules/rate_limiter.py`
**OWASP:** ASI07 (Cascading Failures)

### `per_tool_rate_limit`

Limits the number of calls to each individual tool within a time window.

**Default action:** `deny` (when limit exceeded)
**Configuration:**
```yaml
rate_limiter:
  max_calls: 100
  window_seconds: 60
```

### `session_rate_limit`

Limits the total number of tool calls per session.

**Default action:** `deny`
**Configuration:**
```yaml
session_rate_limit:
  max_calls: 500
  window_seconds: 3600
```

### `burst_detection`

Detects and limits rapid-fire tool calls (more than N per second).

**Default action:** `escalate`
**Configuration:**
```yaml
burst_detection:
  max_calls: 10
```

---

## Category 8: Scope Enforcement

**File:** `src/agentshield/rules/scope.py`
**OWASP:** ASI03 (Identity Abuse), ASI06 (Rogue Agent)

### `tool_allowlist`

Restricts an agent to a declared set of tools.

**Default action:** `deny`
**Configuration:**
```yaml
scope:
  allowed_tools:
    - execute_sql
    - read_file
    - search_web
```

### `argument_schema`

Validates tool call arguments against a JSON Schema.

**Default action:** `escalate`

### `cross_agent_scope`

Prevents Agent A from calling tools scoped exclusively to Agent B.

**Default action:** `deny`

---

## Category 9: Cost Control

**File:** `src/agentshield/rules/cost_guard.py`
**OWASP:** ASI07 (Cascading Failures)

### `session_cost_ceiling`

Blocks tool calls once estimated session costs exceed a limit.

**Default action:** `deny`
**Configuration:**
```yaml
cost_guard:
  max_cost_usd: 10.0
  cost_per_call:
    openai_completion: 0.03
    web_search: 0.01
```

### `cost_alert`

Escalates when costs reach 80% of the ceiling.

**Default action:** `escalate`

---

## Category 10: Human Approval Gates

**File:** `src/agentshield/rules/approval.py`
**OWASP:** ASI09 (Human Override Failure)

### `require_approval_pattern`

Requires human approval for tool calls matching name patterns.

**Default action:** `escalate`
**Configuration:**
```yaml
require_approval_pattern:
  tool_patterns:
    - "deploy_*"
    - "delete_prod_*"
    - "send_email"
```

### `require_approval_financial`

Requires human approval for tool calls with monetary arguments above a threshold.

**Default action:** `escalate`
**Configuration:** `threshold_usd: 100.0`

### `require_approval_data_export`

Requires human approval for data export operations exceeding a row count threshold.

**Default action:** `escalate`
**Configuration:** `row_threshold: 1000`

---

## Custom Rules (No Python Required)

Define rules in YAML without writing any Python:

```yaml
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

Custom rules are evaluated at priority 50+ (after all built-in rules).

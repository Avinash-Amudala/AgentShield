# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in AgentShield, please report it responsibly:

1. **DO NOT** open a public GitHub issue
2. Email: avinashamudala@gmail.com
3. Include: description, reproduction steps, impact assessment
4. You will receive a response within 48 hours
5. We will work with you to understand and fix the issue

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x.x   | Latest only |

## Security Design

AgentShield's core has **zero external dependencies**, minimizing supply chain risk.
All rule evaluation happens in-memory with no network I/O in the hot path.
Audit logs use SHA-256 hash chaining for tamper detection.

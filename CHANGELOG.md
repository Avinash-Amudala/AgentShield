# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-04-16

### Added

- Core policy engine with async evaluation
- 39 built-in safety rules covering OWASP ASI01-ASI10
- Hash-chained JSONL audit logger with tamper detection
- Generic `@shield.protect` decorator
- Framework adapters: MCP, LangChain, CrewAI, OpenAI Agents SDK
- Human-in-the-loop (HITL) gateway with Slack, Discord, and terminal channels
- Real-time dashboard with React frontend
- YAML configuration support
- CLI with verify, stats, export, and serve commands
- 266+ test cases with >80% coverage target
- Latency benchmark (<1ms p99)
- OWASP coverage benchmark (50 attack scenarios)

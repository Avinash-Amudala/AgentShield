# Contributing to AgentShield

Thank you for your interest in contributing!

## Development Setup

```bash
git clone https://github.com/Avinash-Amudala/AgentShield.git
cd AgentShield
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest                                    # Run all tests
pytest --cov=agentshield                 # With coverage
pytest tests/test_rules/                 # Just rule tests
python benchmarks/latency_bench.py       # Performance benchmark
```

## Adding a New Rule

1. Create `src/agentshield/rules/your_rule.py` inheriting from `BaseRule`
2. Add tests in `tests/test_rules/test_your_rule.py` (minimum 5 cases)
3. Add to `rules/__init__.py` default rule list
4. Add OWASP mapping in docs
5. Add YAML config support in schema

## Code Style

- Format: `black .`
- Sort imports: `isort .`
- Lint: `ruff check .`
- Type check: `mypy src/`

## Pull Request Process

1. Fork the repo and create a feature branch
2. Write tests for your changes
3. Ensure CI passes
4. Submit PR with a clear description

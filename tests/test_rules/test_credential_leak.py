from __future__ import annotations

import pytest

from agentshield.core.context import ToolCallContext
from agentshield.core.result import PolicyAction
from agentshield.rules.credential_leak import (
    APIKeyLeakRule,
    EnvVarLeakRule,
    PasswordLeakRule,
    PIILeakRule,
    TokenLeakRule,
)

# ── APIKeyLeakRule ──────────────────────────────────────────────────


class TestAPIKeyLeakRule:
    @pytest.fixture
    def rule(self):
        return APIKeyLeakRule()

    async def test_allow_normal_text(self, rule):
        ctx = ToolCallContext(
            tool_name="send", arguments={"body": "Hello, how are you?"}
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_allow_short_string(self, rule):
        ctx = ToolCallContext(tool_name="send", arguments={"data": "sk-short"})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_deny_aws_access_key(self, rule):
        ctx = ToolCallContext(
            tool_name="send",
            arguments={
                "body": "My key is AKIAIOSFODNN7EXAMPLE"
            },  # pragma: allowlist secret
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY
        assert "AWS" in result.reason

    async def test_deny_openai_key(self, rule):
        ctx = ToolCallContext(
            tool_name="send",
            arguments={
                "body": "sk-abc123def456ghi789jkl012mno345pq"
            },  # pragma: allowlist secret
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_deny_github_pat(self, rule):
        ctx = ToolCallContext(
            tool_name="send",
            arguments={
                "body": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
            },  # pragma: allowlist secret
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_edge_case_nested_key(self, rule):
        ctx = ToolCallContext(
            tool_name="send",
            arguments={
                "config": {"auth": "AKIAIOSFODNN7EXAMPLE"}
            },  # pragma: allowlist secret
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY


# ── TokenLeakRule ───────────────────────────────────────────────────


class TestTokenLeakRule:
    @pytest.fixture
    def rule(self):
        return TokenLeakRule()

    async def test_allow_normal_text(self, rule):
        ctx = ToolCallContext(
            tool_name="send", arguments={"body": "Just a normal message"}
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_allow_short_bearer(self, rule):
        ctx = ToolCallContext(tool_name="send", arguments={"header": "Bearer short"})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_deny_jwt_token(self, rule):
        jwt = (  # pragma: allowlist secret
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ik"
            "pvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        ctx = ToolCallContext(tool_name="send", arguments={"body": jwt})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY
        assert "JWT" in result.reason

    async def test_deny_bearer_token(self, rule):
        ctx = ToolCallContext(
            tool_name="send",
            arguments={
                "header": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcdefg12345"
            },  # pragma: allowlist secret
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_edge_case_oauth_token_in_value(self, rule):
        ctx = ToolCallContext(
            tool_name="send",
            arguments={"config": "oauth_token: abcdefghijklmnopqrstuvwxyz1234567890"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY


# ── PIILeakRule ─────────────────────────────────────────────────────


class TestPIILeakRule:
    @pytest.fixture
    def rule(self):
        return PIILeakRule()

    async def test_allow_normal_text(self, rule):
        ctx = ToolCallContext(
            tool_name="send", arguments={"body": "The total is 42 items"}
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_allow_non_pii_number(self, rule):
        ctx = ToolCallContext(tool_name="send", arguments={"body": "Order #12345"})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_escalate_ssn(self, rule):
        ctx = ToolCallContext(
            tool_name="send",
            arguments={"body": "SSN is 123-45-6789"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ESCALATE
        assert "SSN" in result.reason

    async def test_escalate_email(self, rule):
        ctx = ToolCallContext(
            tool_name="send",
            arguments={"body": "Contact user@example.com for details"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ESCALATE
        assert "email" in result.reason.lower() or "Email" in result.reason

    async def test_edge_case_credit_card_luhn_valid(self, rule):
        ctx = ToolCallContext(
            tool_name="send",
            arguments={"body": "Card: 4111 1111 1111 1111"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ESCALATE
        assert "credit_card" in result.details.get("pii_type", "")


# ── PasswordLeakRule ────────────────────────────────────────────────


class TestPasswordLeakRule:
    @pytest.fixture
    def rule(self):
        return PasswordLeakRule()

    async def test_allow_normal_args(self, rule):
        ctx = ToolCallContext(
            tool_name="send", arguments={"name": "Alice", "message": "Hi"}
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_allow_no_password_key(self, rule):
        ctx = ToolCallContext(
            tool_name="send", arguments={"query": "SELECT * FROM users"}
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_deny_password_key(self, rule):
        ctx = ToolCallContext(
            tool_name="send",
            arguments={"password": "s3cr3tP@ss!"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_deny_secret_key(self, rule):
        ctx = ToolCallContext(
            tool_name="send",
            arguments={"secret": "my_api_secret_value"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_deny_password_in_value(self, rule):
        ctx = ToolCallContext(
            tool_name="send",
            arguments={"config": "password: SuperSecret123!"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_edge_case_auth_token_key(self, rule):
        ctx = ToolCallContext(
            tool_name="send",
            arguments={"auth_token": "tok_abc123xyz"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY


# ── EnvVarLeakRule ──────────────────────────────────────────────────


class TestEnvVarLeakRule:
    @pytest.fixture
    def rule(self):
        return EnvVarLeakRule()

    async def test_allow_normal_text(self, rule):
        ctx = ToolCallContext(tool_name="send", arguments={"body": "Just a message"})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_allow_safe_env_var(self, rule):
        ctx = ToolCallContext(tool_name="send", arguments={"body": "$HOME/documents"})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_escalate_dollar_secret_key(self, rule):
        ctx = ToolCallContext(
            tool_name="send",
            arguments={"body": "Use $AWS_SECRET_KEY for auth"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ESCALATE

    async def test_escalate_env_bracket_notation(self, rule):
        ctx = ToolCallContext(
            tool_name="send",
            arguments={"body": "Token is ${API_TOKEN}"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ESCALATE

    async def test_escalate_os_environ(self, rule):
        ctx = ToolCallContext(
            tool_name="send",
            arguments={"code": "os.environ['DB_PASSWORD']"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ESCALATE

    async def test_edge_case_getenv_secret(self, rule):
        ctx = ToolCallContext(
            tool_name="send",
            arguments={"code": "os.getenv('SECRET_KEY')"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ESCALATE

from __future__ import annotations

import pytest

from agentshield import Shield, ToolCallBlocked
from agentshield.core.context import ToolCallContext
from agentshield.core.result import PolicyAction, PolicyResponse
from agentshield.rules.base import BaseRule
from agentshield.rules.sql_injection import DestructiveSQLRule


class AlwaysDenyRule(BaseRule):
    name = "test_deny"
    priority = 1

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        return PolicyResponse(
            action=PolicyAction.DENY,
            rule_name=self.name,
            reason="Denied by test rule",
            owasp_id="TEST01",
        )


class TestShieldProtectDecorator:
    async def test_protect_blocks_dangerous_sql(self):
        shield = Shield(rules=[DestructiveSQLRule()], mode="enforce")

        @shield.protect(tool_name="run_query")
        async def run_query(query: str) -> str:
            return query

        with pytest.raises(ToolCallBlocked):
            await run_query(query="DROP TABLE users")

    async def test_protect_allows_safe_sql(self):
        shield = Shield(rules=[DestructiveSQLRule()], mode="enforce")

        @shield.protect(tool_name="run_query")
        async def run_query(query: str) -> str:
            return query

        result = await run_query(query="SELECT * FROM users WHERE id = 1")
        assert result == "SELECT * FROM users WHERE id = 1"

    async def test_protect_allows_safe_update_with_where(self):
        shield = Shield(rules=[DestructiveSQLRule()], mode="enforce")

        @shield.protect(tool_name="run_query")
        async def run_query(query: str) -> str:
            return query

        result = await run_query(query="UPDATE users SET name='Bob' WHERE id=1")
        assert result == "UPDATE users SET name='Bob' WHERE id=1"


class TestShieldMonitorMode:
    async def test_monitor_mode_logs_but_does_not_block(self):
        shield = Shield(rules=[AlwaysDenyRule()], mode="monitor")
        ctx = ToolCallContext(tool_name="anything", arguments={"data": "test"})
        response = await shield.check(ctx)
        assert response.action is PolicyAction.DENY
        # No exception raised — monitor mode logs only

    async def test_monitor_mode_returns_deny_response(self):
        shield = Shield(rules=[AlwaysDenyRule()], mode="monitor")
        ctx = ToolCallContext(tool_name="anything", arguments={})
        response = await shield.check(ctx)
        assert response.rule_name == "test_deny"


class TestShieldDryRunMode:
    async def test_dry_run_mode_does_not_raise(self, capsys):
        shield = Shield(rules=[AlwaysDenyRule()], mode="dry-run")
        ctx = ToolCallContext(tool_name="danger_tool", arguments={})
        response = await shield.check(ctx)
        assert response.action is PolicyAction.DENY

        captured = capsys.readouterr()
        assert "WOULD BLOCK" in captured.out

    async def test_dry_run_prints_tool_name(self, capsys):
        shield = Shield(rules=[AlwaysDenyRule()], mode="dry-run")
        ctx = ToolCallContext(tool_name="my_tool", arguments={})
        await shield.check(ctx)

        captured = capsys.readouterr()
        assert "my_tool" in captured.out


class TestShieldEnforceMode:
    async def test_enforce_mode_raises_on_deny(self):
        shield = Shield(rules=[AlwaysDenyRule()], mode="enforce")
        ctx = ToolCallContext(tool_name="test", arguments={})
        with pytest.raises(ToolCallBlocked):
            await shield.check(ctx)

    async def test_enforce_mode_allows_when_no_deny(self):
        shield = Shield(rules=[], mode="enforce")
        ctx = ToolCallContext(tool_name="safe_tool", arguments={})
        response = await shield.check(ctx)
        assert response.action is PolicyAction.ALLOW


class TestShieldAsyncAndSyncProtection:
    async def test_async_function_protection(self):
        shield = Shield(rules=[DestructiveSQLRule()], mode="enforce")

        @shield.protect()
        async def async_query(sql: str) -> str:
            return f"result of {sql}"

        result = await async_query(sql="SELECT 1")
        assert result == "result of SELECT 1"

    def test_sync_function_protection(self):
        shield = Shield(rules=[DestructiveSQLRule()], mode="enforce")

        @shield.protect()
        def sync_query(sql: str) -> str:
            return f"result of {sql}"

        result = sync_query(sql="SELECT 1")
        assert result == "result of SELECT 1"

    def test_sync_function_blocked(self):
        shield = Shield(rules=[DestructiveSQLRule()], mode="enforce")

        @shield.protect()
        def sync_query(sql: str) -> str:
            return f"result of {sql}"

        with pytest.raises(ToolCallBlocked):
            sync_query(sql="DROP TABLE users")


class TestToolCallBlockedException:
    async def test_exception_has_response(self):
        shield = Shield(rules=[AlwaysDenyRule()], mode="enforce")
        ctx = ToolCallContext(tool_name="test", arguments={})
        with pytest.raises(ToolCallBlocked) as exc_info:
            await shield.check(ctx)

        assert exc_info.value.response.action is PolicyAction.DENY
        assert exc_info.value.response.rule_name == "test_deny"

    async def test_exception_message_contains_rule_name(self):
        shield = Shield(rules=[AlwaysDenyRule()], mode="enforce")
        ctx = ToolCallContext(tool_name="test", arguments={})
        with pytest.raises(ToolCallBlocked, match="test_deny"):
            await shield.check(ctx)

    async def test_exception_message_contains_owasp(self):
        shield = Shield(rules=[AlwaysDenyRule()], mode="enforce")
        ctx = ToolCallContext(tool_name="test", arguments={})
        with pytest.raises(ToolCallBlocked, match="TEST01"):
            await shield.check(ctx)


class TestShieldInvalidMode:
    def test_invalid_mode_raises_value_error(self):
        with pytest.raises(ValueError, match="Invalid mode"):
            Shield(rules=[], mode="invalid")


class TestShieldRepr:
    def test_repr_contains_mode_and_rule_count(self):
        shield = Shield(rules=[DestructiveSQLRule()], mode="enforce")
        r = repr(shield)
        assert "enforce" in r
        assert "rules=1" in r

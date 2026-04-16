from __future__ import annotations

import pytest

from agentshield.core.context import ToolCallContext
from agentshield.core.result import PolicyAction
from agentshield.rules.sql_injection import (
    DestructiveSQLRule,
    SQLAdminCommandsRule,
    SQLBatchExecutionRule,
    SQLCommentInjectionRule,
    SQLUnionInjectionRule,
)


# ── DestructiveSQLRule ──────────────────────────────────────────────

class TestDestructiveSQLRule:
    @pytest.fixture
    def rule(self):
        return DestructiveSQLRule()

    async def test_allow_safe_select(self, rule):
        ctx = ToolCallContext(tool_name="db", arguments={"query": "SELECT * FROM users"})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_allow_delete_with_where(self, rule):
        ctx = ToolCallContext(
            tool_name="db",
            arguments={"query": "DELETE FROM orders WHERE id = 5"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_deny_drop_table(self, rule):
        ctx = ToolCallContext(tool_name="db", arguments={"query": "DROP TABLE users"})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY
        assert "DROP TABLE" in result.reason

    async def test_deny_delete_without_where(self, rule):
        ctx = ToolCallContext(
            tool_name="db",
            arguments={"query": "DELETE FROM orders"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_deny_alter_table_drop_column(self, rule):
        ctx = ToolCallContext(
            tool_name="db",
            arguments={"query": "ALTER TABLE users DROP COLUMN name"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_deny_truncate_table(self, rule):
        ctx = ToolCallContext(
            tool_name="db",
            arguments={"query": "TRUNCATE TABLE sessions"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_edge_case_drop_in_string_literal(self, rule):
        ctx = ToolCallContext(
            tool_name="db",
            arguments={"query": "SELECT * FROM users WHERE name = 'DROP TABLE'"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY  # conservative detection

    async def test_owasp_id_set(self, rule):
        ctx = ToolCallContext(tool_name="db", arguments={"query": "DROP TABLE x"})
        result = await rule.evaluate(ctx)
        assert result.owasp_id == "ASI02"


# ── SQLUnionInjectionRule ───────────────────────────────────────────

class TestSQLUnionInjectionRule:
    @pytest.fixture
    def rule(self):
        return SQLUnionInjectionRule()

    async def test_allow_normal_select(self, rule):
        ctx = ToolCallContext(
            tool_name="db",
            arguments={"query": "SELECT id, name FROM users"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_allow_query_without_union(self, rule):
        ctx = ToolCallContext(
            tool_name="db",
            arguments={"query": "SELECT * FROM products WHERE category = 'union'"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_deny_union_select(self, rule):
        ctx = ToolCallContext(
            tool_name="db",
            arguments={"query": "SELECT id FROM users UNION SELECT password FROM credentials"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_deny_union_all_select(self, rule):
        ctx = ToolCallContext(
            tool_name="db",
            arguments={"query": "SELECT 1 UNION ALL SELECT secret FROM tokens"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_edge_case_nested_in_argument(self, rule):
        ctx = ToolCallContext(
            tool_name="db",
            arguments={"filters": {"sql": "1 UNION SELECT 1,2,3"}},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY


# ── SQLCommentInjectionRule ─────────────────────────────────────────

class TestSQLCommentInjectionRule:
    @pytest.fixture
    def rule(self):
        return SQLCommentInjectionRule()

    async def test_allow_normal_query(self, rule):
        ctx = ToolCallContext(
            tool_name="db",
            arguments={"query": "SELECT * FROM users WHERE active = 1"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_allow_safe_string_with_hyphens(self, rule):
        ctx = ToolCallContext(
            tool_name="db",
            arguments={"query": "SELECT * FROM users WHERE code = 'ABC-DEF'"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_deny_double_dash_comment(self, rule):
        ctx = ToolCallContext(
            tool_name="db",
            arguments={"query": "SELECT * FROM users WHERE id = 1-- AND password = 'x'"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_deny_block_comment(self, rule):
        ctx = ToolCallContext(
            tool_name="db",
            arguments={"query": "SELECT * FROM users WHERE id = 1 /* drop everything */"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_edge_case_hash_comment(self, rule):
        ctx = ToolCallContext(
            tool_name="db",
            arguments={"query": "SELECT * FROM users WHERE 1=1 # comment"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY


# ── SQLBatchExecutionRule ───────────────────────────────────────────

class TestSQLBatchExecutionRule:
    @pytest.fixture
    def rule(self):
        return SQLBatchExecutionRule()

    async def test_allow_single_statement(self, rule):
        ctx = ToolCallContext(
            tool_name="db",
            arguments={"query": "SELECT * FROM users"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_allow_semicolon_in_value(self, rule):
        ctx = ToolCallContext(
            tool_name="db",
            arguments={"query": "SELECT * FROM users WHERE bio LIKE '%hello;world%'"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_escalate_batch_select(self, rule):
        ctx = ToolCallContext(
            tool_name="db",
            arguments={"query": "SELECT 1; SELECT secret FROM keys"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ESCALATE

    async def test_escalate_batch_drop(self, rule):
        ctx = ToolCallContext(
            tool_name="db",
            arguments={"query": "SELECT 1; DROP TABLE users"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ESCALATE

    async def test_edge_case_insert_after_semicolon(self, rule):
        ctx = ToolCallContext(
            tool_name="db",
            arguments={"query": "SELECT 1; INSERT INTO log VALUES('hack')"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ESCALATE


# ── SQLAdminCommandsRule ────────────────────────────────────────────

class TestSQLAdminCommandsRule:
    @pytest.fixture
    def rule(self):
        return SQLAdminCommandsRule()

    async def test_allow_normal_select(self, rule):
        ctx = ToolCallContext(
            tool_name="db",
            arguments={"query": "SELECT * FROM users"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_allow_insert(self, rule):
        ctx = ToolCallContext(
            tool_name="db",
            arguments={"query": "INSERT INTO users (name) VALUES ('alice')"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_deny_grant_all(self, rule):
        ctx = ToolCallContext(
            tool_name="db",
            arguments={"query": "GRANT ALL PRIVILEGES ON db.* TO 'hacker'@'%'"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_deny_revoke(self, rule):
        ctx = ToolCallContext(
            tool_name="db",
            arguments={"query": "REVOKE SELECT ON users FROM 'readonly'@'%'"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_deny_create_user(self, rule):
        ctx = ToolCallContext(
            tool_name="db",
            arguments={"query": "CREATE USER 'backdoor'@'%' IDENTIFIED BY 'pass123'"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_edge_case_alter_user(self, rule):
        ctx = ToolCallContext(
            tool_name="db",
            arguments={"query": "ALTER USER 'admin'@'%' IDENTIFIED BY 'newpass'"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

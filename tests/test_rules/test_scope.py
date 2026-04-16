from __future__ import annotations

import pytest

from agentshield.core.context import ToolCallContext
from agentshield.core.result import PolicyAction
from agentshield.rules.scope import (
    ArgumentSchemaRule,
    CrossAgentScopeRule,
    ToolAllowlistRule,
)

# ── ToolAllowlistRule ───────────────────────────────────────────────


class TestToolAllowlistRule:
    @pytest.fixture
    def rule(self):
        r = ToolAllowlistRule()
        r.allowed_tools = ["read_file", "write_file", "list_dir"]
        return r

    async def test_allow_listed_tool(self, rule):
        ctx = ToolCallContext(tool_name="read_file", arguments={})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_allow_another_listed_tool(self, rule):
        ctx = ToolCallContext(tool_name="write_file", arguments={})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_deny_unlisted_tool(self, rule):
        ctx = ToolCallContext(tool_name="exec_command", arguments={})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_deny_similar_name(self, rule):
        ctx = ToolCallContext(tool_name="read_files", arguments={})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_edge_case_empty_allowlist_permits_all(self):
        rule = ToolAllowlistRule()
        ctx = ToolCallContext(tool_name="anything", arguments={})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW


# ── ArgumentSchemaRule ──────────────────────────────────────────────


class TestArgumentSchemaRule:
    @pytest.fixture
    def rule(self):
        r = ArgumentSchemaRule()
        r.expected_schemas = {
            "read_file": {"path": "str"},
            "write_file": {"path": "str", "content": "str"},
        }
        return r

    async def test_allow_matching_schema(self, rule):
        ctx = ToolCallContext(
            tool_name="read_file", arguments={"path": "/tmp/test.txt"}
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_allow_no_schema_defined(self, rule):
        ctx = ToolCallContext(tool_name="unknown_tool", arguments={"anything": 123})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_escalate_wrong_type(self, rule):
        ctx = ToolCallContext(tool_name="read_file", arguments={"path": 12345})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ESCALATE
        assert "expected str" in result.reason

    async def test_escalate_unexpected_argument(self, rule):
        ctx = ToolCallContext(
            tool_name="read_file",
            arguments={"path": "/tmp/test.txt", "extra_arg": "bad"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ESCALATE

    async def test_edge_case_multiple_violations(self, rule):
        ctx = ToolCallContext(
            tool_name="write_file",
            arguments={"path": 123, "content": 456, "unknown": "x"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ESCALATE
        assert len(result.details["violations"]) >= 2


# ── CrossAgentScopeRule ─────────────────────────────────────────────


class TestCrossAgentScopeRule:
    @pytest.fixture
    def rule(self):
        r = CrossAgentScopeRule()
        r.agent_scopes = {
            "reader": ["read_file", "list_dir"],
            "writer": ["write_file", "delete_file"],
        }
        return r

    async def test_allow_agent_in_scope(self, rule):
        ctx = ToolCallContext(tool_name="read_file", arguments={}, agent_id="reader")
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_allow_no_scopes_configured(self):
        rule = CrossAgentScopeRule()
        ctx = ToolCallContext(tool_name="anything", arguments={}, agent_id="any_agent")
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_deny_agent_out_of_scope(self, rule):
        ctx = ToolCallContext(tool_name="write_file", arguments={}, agent_id="reader")
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_deny_cross_agent_tool_access(self, rule):
        ctx = ToolCallContext(tool_name="read_file", arguments={}, agent_id="writer")
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_edge_case_undefined_agent(self, rule):
        ctx = ToolCallContext(
            tool_name="read_file", arguments={}, agent_id="unknown_agent"
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

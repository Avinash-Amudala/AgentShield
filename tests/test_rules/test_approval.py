from __future__ import annotations

import pytest

from agentshield.core.context import ToolCallContext
from agentshield.core.result import PolicyAction
from agentshield.rules.approval import (
    RequireApprovalDataExportRule,
    RequireApprovalFinancialRule,
    RequireApprovalPatternRule,
    _extract_strings,
)

# ── RequireApprovalPatternRule ──────────────────────────────────────


class TestRequireApprovalPatternRule:
    @pytest.fixture
    def rule(self):
        return RequireApprovalPatternRule()

    async def test_allow_normal_tool(self, rule):
        ctx = ToolCallContext(tool_name="read_file", arguments={})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_allow_non_matching_tool(self, rule):
        ctx = ToolCallContext(tool_name="list_users", arguments={})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_escalate_deploy_tool(self, rule):
        ctx = ToolCallContext(tool_name="deploy_production", arguments={})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ESCALATE

    async def test_escalate_delete_prod_tool(self, rule):
        ctx = ToolCallContext(tool_name="delete_prod_database", arguments={})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ESCALATE

    async def test_escalate_destroy_tool(self, rule):
        ctx = ToolCallContext(tool_name="destroy_cluster", arguments={})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ESCALATE

    async def test_edge_case_drop_star(self, rule):
        ctx = ToolCallContext(tool_name="drop_table", arguments={})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ESCALATE


# ── RequireApprovalFinancialRule ────────────────────────────────────


class TestRequireApprovalFinancialRule:
    @pytest.fixture
    def rule(self):
        return RequireApprovalFinancialRule()

    async def test_allow_no_monetary_args(self, rule):
        ctx = ToolCallContext(tool_name="send", arguments={"message": "Hello"})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_allow_small_amount(self, rule):
        ctx = ToolCallContext(tool_name="payment", arguments={"amount": 50.0})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_escalate_large_amount(self, rule):
        ctx = ToolCallContext(tool_name="payment", arguments={"amount": 500.0})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ESCALATE

    async def test_escalate_amount_as_string(self, rule):
        ctx = ToolCallContext(tool_name="payment", arguments={"amount": "$1,500.00"})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ESCALATE

    async def test_edge_case_cost_key(self, rule):
        ctx = ToolCallContext(tool_name="purchase", arguments={"cost": 250})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ESCALATE

    async def test_edge_case_at_threshold(self, rule):
        ctx = ToolCallContext(tool_name="payment", arguments={"amount": 100.0})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW  # > threshold, not >=


# ── RequireApprovalDataExportRule ───────────────────────────────────


class TestRequireApprovalDataExportRule:
    @pytest.fixture
    def rule(self):
        return RequireApprovalDataExportRule()

    async def test_allow_non_export_tool(self, rule):
        ctx = ToolCallContext(
            tool_name="read_file",
            arguments={"limit": 5000},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_allow_export_within_limit(self, rule):
        ctx = ToolCallContext(
            tool_name="export_data",
            arguments={"limit": 500},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_escalate_export_exceeds_limit(self, rule):
        ctx = ToolCallContext(
            tool_name="export_data",
            arguments={"limit": 5000},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ESCALATE

    async def test_escalate_download_tool(self, rule):
        ctx = ToolCallContext(
            tool_name="download_report",
            arguments={"row_count": 2000},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ESCALATE

    async def test_edge_case_dump_with_batch_size(self, rule):
        ctx = ToolCallContext(
            tool_name="dump_table",
            arguments={"batch_size": 10000},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ESCALATE

    async def test_edge_case_export_at_limit(self, rule):
        ctx = ToolCallContext(
            tool_name="export_data",
            arguments={"limit": 1000},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_export_invalid_row_count(self, rule):
        ctx = ToolCallContext(
            tool_name="export_data",
            arguments={"limit": "not-a-number"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_export_no_row_keys(self, rule):
        ctx = ToolCallContext(
            tool_name="export_data",
            arguments={"format": "csv"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW


class TestExtractStrings:
    def test_string_value(self):
        assert _extract_strings("hello") == ["hello"]

    def test_dict_values(self):
        result = _extract_strings({"a": "x", "b": "y"})
        assert "x" in result and "y" in result

    def test_nested(self):
        result = _extract_strings({"a": ["b", {"c": "d"}]})
        assert "b" in result and "d" in result

    def test_number_ignored(self):
        assert _extract_strings(42) == []


class TestFinancialRuleEdgeCases:
    async def test_amount_none(self):
        rule = RequireApprovalFinancialRule()
        ctx = ToolCallContext(tool_name="pay", arguments={"amount": None})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_amount_non_numeric_string(self):
        rule = RequireApprovalFinancialRule()
        ctx = ToolCallContext(tool_name="pay", arguments={"amount": "free"})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

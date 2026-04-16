"""Tests for custom pattern rules and base rule utilities."""

from __future__ import annotations

from agentshield.core.context import ToolCallContext
from agentshield.core.result import PolicyAction
from agentshield.rules.base import BaseRule
from agentshield.rules.custom import CustomPatternRule


class TestCustomPatternRule:
    async def test_match_deny(self):
        rule = CustomPatternRule(
            name="block_deploy",
            tool_patterns=["deploy_*"],
            action="deny",
            reason="no deploys",
        )
        ctx = ToolCallContext(tool_name="deploy_prod", arguments={})
        resp = await rule.evaluate(ctx)
        assert resp.action is PolicyAction.DENY
        assert "deploy_prod" in resp.details["tool_name"]

    async def test_match_escalate(self):
        rule = CustomPatternRule(
            name="review_delete",
            tool_patterns=["delete_*"],
            action="escalate",
        )
        ctx = ToolCallContext(tool_name="delete_user", arguments={})
        resp = await rule.evaluate(ctx)
        assert resp.action is PolicyAction.ESCALATE

    async def test_match_allow(self):
        rule = CustomPatternRule(
            name="pass_all",
            tool_patterns=["*"],
            action="allow",
        )
        ctx = ToolCallContext(tool_name="anything", arguments={})
        resp = await rule.evaluate(ctx)
        assert resp.action is PolicyAction.ALLOW

    async def test_no_match(self):
        rule = CustomPatternRule(
            name="block_deploy",
            tool_patterns=["deploy_*"],
        )
        ctx = ToolCallContext(tool_name="read_file", arguments={})
        resp = await rule.evaluate(ctx)
        assert resp.action is PolicyAction.ALLOW

    async def test_no_patterns(self):
        rule = CustomPatternRule(name="empty")
        ctx = ToolCallContext(tool_name="anything", arguments={})
        resp = await rule.evaluate(ctx)
        assert resp.action is PolicyAction.ALLOW

    async def test_unknown_action_defaults_deny(self):
        rule = CustomPatternRule(
            name="bad_action", tool_patterns=["*"], action="explode"
        )
        ctx = ToolCallContext(tool_name="x", arguments={})
        resp = await rule.evaluate(ctx)
        assert resp.action is PolicyAction.DENY

    def test_configure(self):
        rule = CustomPatternRule(name="test", action="deny")
        rule.configure({"action": "escalate", "enabled": False})
        assert rule._action_str == "escalate"
        assert not rule.enabled

    def test_owasp_id(self):
        rule = CustomPatternRule(name="t", owasp_id="ASI03")
        assert rule.owasp_id == "ASI03"


class TestBaseRule:
    def test_configure(self):
        class MyRule(BaseRule):
            async def evaluate(self, context):
                pass

        r = MyRule()
        r.configure({"enabled": False, "priority": 5})
        assert not r.enabled
        assert r.priority == 5

    def test_configure_ignores_unknown(self):
        class MyRule(BaseRule):
            async def evaluate(self, context):
                pass

        r = MyRule()
        r.configure({"nonexistent_field": 42})

    def test_repr(self):
        class MyRule(BaseRule):
            name = "test_rule"

            async def evaluate(self, context):
                pass

        r = MyRule()
        s = repr(r)
        assert "test_rule" in s
        assert "enabled" in s

        r.enabled = False
        assert "disabled" in repr(r)

from __future__ import annotations

import pytest

from agentshield.core.context import ToolCallContext
from agentshield.core.engine import PolicyEngine
from agentshield.core.result import PolicyAction, PolicyResponse
from agentshield.rules.base import BaseRule


class AlwaysAllowRule(BaseRule):
    name = "always_allow"
    priority = 100

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        return PolicyResponse(
            action=PolicyAction.ALLOW, rule_name=self.name, reason="Always allow"
        )


class AlwaysDenyRule(BaseRule):
    name = "always_deny"
    priority = 50

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        return PolicyResponse(
            action=PolicyAction.DENY, rule_name=self.name, reason="Always deny"
        )


class AlwaysEscalateRule(BaseRule):
    name = "always_escalate"
    priority = 50

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        return PolicyResponse(
            action=PolicyAction.ESCALATE,
            rule_name=self.name,
            reason="Always escalate",
        )


class HighPriorityAllowRule(BaseRule):
    name = "high_priority_allow"
    priority = 1

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason="High priority allow",
        )


class LowPriorityDenyRule(BaseRule):
    name = "low_priority_deny"
    priority = 200

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        return PolicyResponse(
            action=PolicyAction.DENY,
            rule_name=self.name,
            reason="Low priority deny",
        )


@pytest.fixture
def ctx():
    return ToolCallContext(tool_name="test_tool", arguments={})


class TestPolicyEngineEmptyRules:
    async def test_empty_rules_returns_default_allow(self, ctx):
        engine = PolicyEngine(rules=[])
        result = await engine.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW
        assert result.rule_name == "default"

    async def test_empty_rules_returns_custom_default(self, ctx):
        engine = PolicyEngine(rules=[], default_action=PolicyAction.DENY)
        result = await engine.evaluate(ctx)
        assert result.action is PolicyAction.DENY


class TestPolicyEngineDenyShortCircuit:
    async def test_deny_rule_short_circuits(self, ctx):
        engine = PolicyEngine(rules=[AlwaysDenyRule(), AlwaysAllowRule()])
        result = await engine.evaluate(ctx)
        assert result.action is PolicyAction.DENY
        assert result.rule_name == "always_deny"

    async def test_deny_before_allow_prevents_allow(self, ctx):
        deny = AlwaysDenyRule()
        deny.priority = 10
        allow = AlwaysAllowRule()
        allow.priority = 20
        engine = PolicyEngine(rules=[allow, deny])
        result = await engine.evaluate(ctx)
        assert result.action is PolicyAction.DENY


class TestPolicyEngineEscalateShortCircuit:
    async def test_escalate_rule_short_circuits(self, ctx):
        engine = PolicyEngine(rules=[AlwaysEscalateRule(), AlwaysAllowRule()])
        result = await engine.evaluate(ctx)
        assert result.action is PolicyAction.ESCALATE
        assert result.rule_name == "always_escalate"

    async def test_escalate_stops_further_evaluation(self, ctx):
        escalate = AlwaysEscalateRule()
        escalate.priority = 5
        deny = AlwaysDenyRule()
        deny.priority = 10
        engine = PolicyEngine(rules=[deny, escalate])
        result = await engine.evaluate(ctx)
        assert result.action is PolicyAction.ESCALATE


class TestPolicyEngineAllowPassthrough:
    async def test_all_allow_rules_returns_default(self, ctx):
        engine = PolicyEngine(rules=[AlwaysAllowRule(), HighPriorityAllowRule()])
        result = await engine.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_allow_does_not_short_circuit(self, ctx):
        allow1 = AlwaysAllowRule()
        allow1.priority = 1
        allow2 = AlwaysAllowRule()
        allow2.priority = 2
        deny = LowPriorityDenyRule()
        engine = PolicyEngine(rules=[allow1, allow2, deny])
        result = await engine.evaluate(ctx)
        assert result.action is PolicyAction.DENY


class TestPolicyEnginePriorityOrdering:
    async def test_rules_sorted_by_priority(self):
        r1 = AlwaysAllowRule()
        r1.priority = 50
        r2 = AlwaysDenyRule()
        r2.priority = 10
        r3 = AlwaysEscalateRule()
        r3.priority = 30
        engine = PolicyEngine(rules=[r1, r2, r3])
        assert [r.priority for r in engine.rules] == [10, 30, 50]

    async def test_lower_priority_deny_runs_first(self, ctx):
        deny = AlwaysDenyRule()
        deny.priority = 5
        escalate = AlwaysEscalateRule()
        escalate.priority = 10
        engine = PolicyEngine(rules=[escalate, deny])
        result = await engine.evaluate(ctx)
        assert result.action is PolicyAction.DENY


class TestPolicyEngineDisabledRules:
    async def test_disabled_rule_is_skipped(self, ctx):
        deny = AlwaysDenyRule()
        deny.enabled = False
        engine = PolicyEngine(rules=[deny])
        result = await engine.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_disabled_deny_allows_passthrough_to_next(self, ctx):
        deny = AlwaysDenyRule()
        deny.enabled = False
        deny.priority = 1
        escalate = AlwaysEscalateRule()
        escalate.priority = 2
        engine = PolicyEngine(rules=[deny, escalate])
        result = await engine.evaluate(ctx)
        assert result.action is PolicyAction.ESCALATE

    async def test_re_enable_rule_takes_effect(self, ctx):
        deny = AlwaysDenyRule()
        deny.enabled = False
        engine = PolicyEngine(rules=[deny])
        result = await engine.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

        deny.enabled = True
        result = await engine.evaluate(ctx)
        assert result.action is PolicyAction.DENY

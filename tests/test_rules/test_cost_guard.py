from __future__ import annotations


from agentshield.core.context import ToolCallContext
from agentshield.core.result import PolicyAction
from agentshield.rules.cost_guard import CostAlertRule, SessionCostCeilingRule

# ── SessionCostCeilingRule ──────────────────────────────────────────


class TestSessionCostCeilingRule:
    def _make_rule(
        self,
        max_cost: float = 1.0,
        default_cost: float = 0.10,
        cost_per_call: dict | None = None,
    ):
        rule = SessionCostCeilingRule()
        rule.max_cost_usd = max_cost
        rule.default_cost_usd = default_cost
        if cost_per_call:
            rule.cost_per_call = cost_per_call
        return rule

    def _ctx(self, tool_name: str = "tool", session_id: str = "s1"):
        return ToolCallContext(tool_name=tool_name, arguments={}, session_id=session_id)

    async def test_allow_first_call(self):
        rule = self._make_rule()
        result = await rule.evaluate(self._ctx())
        assert result.action is PolicyAction.ALLOW

    async def test_allow_within_ceiling(self):
        rule = self._make_rule(max_cost=1.0, default_cost=0.10)
        for _ in range(9):
            result = await rule.evaluate(self._ctx())
        assert result.action is PolicyAction.ALLOW

    async def test_deny_exceeds_ceiling(self):
        rule = self._make_rule(max_cost=0.50, default_cost=0.20)
        await rule.evaluate(self._ctx())  # 0.20
        await rule.evaluate(self._ctx())  # 0.40
        result = await rule.evaluate(self._ctx())  # 0.60 > 0.50
        assert result.action is PolicyAction.DENY

    async def test_separate_sessions(self):
        rule = self._make_rule(max_cost=0.30, default_cost=0.15)
        await rule.evaluate(self._ctx(session_id="a"))
        await rule.evaluate(self._ctx(session_id="a"))
        result = await rule.evaluate(self._ctx(session_id="b"))
        assert result.action is PolicyAction.ALLOW

    async def test_edge_case_custom_tool_cost(self):
        rule = self._make_rule(
            max_cost=1.0,
            default_cost=0.01,
            cost_per_call={"expensive_tool": 0.80},
        )
        await rule.evaluate(self._ctx(tool_name="expensive_tool"))  # 0.80
        result = await rule.evaluate(
            self._ctx(tool_name="expensive_tool")
        )  # 1.60 > 1.0
        assert result.action is PolicyAction.DENY


# ── CostAlertRule ───────────────────────────────────────────────────


class TestCostAlertRule:
    def _make_rule(
        self,
        max_cost: float = 1.0,
        default_cost: float = 0.10,
        alert_threshold: float = 0.80,
    ):
        rule = CostAlertRule()
        rule.max_cost_usd = max_cost
        rule.default_cost_usd = default_cost
        rule.alert_threshold = alert_threshold
        return rule

    def _ctx(self, session_id: str = "s1"):
        return ToolCallContext(tool_name="tool", arguments={}, session_id=session_id)

    async def test_allow_below_threshold(self):
        rule = self._make_rule(max_cost=1.0, default_cost=0.10)
        result = await rule.evaluate(self._ctx())
        assert result.action is PolicyAction.ALLOW

    async def test_allow_well_below_threshold(self):
        rule = self._make_rule(max_cost=10.0, default_cost=0.01)
        result = await rule.evaluate(self._ctx())
        assert result.action is PolicyAction.ALLOW

    async def test_escalate_at_threshold(self):
        rule = self._make_rule(max_cost=1.0, default_cost=0.125, alert_threshold=0.80)
        for _ in range(6):
            await rule.evaluate(self._ctx())
        result = await rule.evaluate(self._ctx())  # 0.875 >= 0.80
        assert result.action is PolicyAction.ESCALATE

    async def test_escalate_fires_only_once(self):
        rule = self._make_rule(max_cost=1.0, default_cost=0.125, alert_threshold=0.80)
        for _ in range(6):
            await rule.evaluate(self._ctx())
        result1 = await rule.evaluate(self._ctx())  # 0.875 >= 0.80
        assert result1.action is PolicyAction.ESCALATE
        result2 = await rule.evaluate(self._ctx())
        assert result2.action is PolicyAction.ALLOW

    async def test_edge_case_separate_sessions(self):
        rule = self._make_rule(max_cost=1.0, default_cost=0.50, alert_threshold=0.80)
        await rule.evaluate(self._ctx(session_id="a"))
        result = await rule.evaluate(self._ctx(session_id="a"))
        assert result.action is PolicyAction.ESCALATE
        result_b = await rule.evaluate(self._ctx(session_id="b"))
        assert result_b.action is PolicyAction.ALLOW

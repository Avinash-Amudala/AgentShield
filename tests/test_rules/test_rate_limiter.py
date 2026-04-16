from __future__ import annotations


from agentshield.core.context import ToolCallContext
from agentshield.core.result import PolicyAction
from agentshield.rules.rate_limiter import (
    BurstDetectionRule,
    PerToolRateLimitRule,
    SessionRateLimitRule,
)

# ── PerToolRateLimitRule ────────────────────────────────────────────


class TestPerToolRateLimitRule:
    def _make_rule(self, max_calls: int = 3, window_seconds: float = 60.0):
        rule = PerToolRateLimitRule()
        rule.max_calls = max_calls
        rule.window_seconds = window_seconds
        return rule

    def _ctx(self, tool_name: str = "test_tool", session_id: str = "sess1"):
        return ToolCallContext(tool_name=tool_name, arguments={}, session_id=session_id)

    async def test_allow_first_call(self):
        rule = self._make_rule(max_calls=5)
        result = await rule.evaluate(self._ctx())
        assert result.action is PolicyAction.ALLOW

    async def test_allow_within_limit(self):
        rule = self._make_rule(max_calls=5)
        for _ in range(4):
            result = await rule.evaluate(self._ctx())
        assert result.action is PolicyAction.ALLOW

    async def test_deny_exceeds_limit(self):
        rule = self._make_rule(max_calls=3)
        for _ in range(3):
            await rule.evaluate(self._ctx())
        result = await rule.evaluate(self._ctx())
        assert result.action is PolicyAction.DENY

    async def test_separate_tools_have_separate_limits(self):
        rule = self._make_rule(max_calls=2)
        await rule.evaluate(self._ctx(tool_name="tool_a"))
        await rule.evaluate(self._ctx(tool_name="tool_a"))
        result = await rule.evaluate(self._ctx(tool_name="tool_b"))
        assert result.action is PolicyAction.ALLOW

    async def test_edge_case_exactly_at_limit(self):
        rule = self._make_rule(max_calls=3)
        for _ in range(3):
            result = await rule.evaluate(self._ctx())
        assert result.action is PolicyAction.ALLOW
        result = await rule.evaluate(self._ctx())
        assert result.action is PolicyAction.DENY


# ── SessionRateLimitRule ────────────────────────────────────────────


class TestSessionRateLimitRule:
    def _make_rule(self, max_calls: int = 5, window_seconds: float = 3600.0):
        rule = SessionRateLimitRule()
        rule.max_calls = max_calls
        rule.window_seconds = window_seconds
        return rule

    def _ctx(self, session_id: str = "sess1"):
        return ToolCallContext(
            tool_name="any_tool", arguments={}, session_id=session_id
        )

    async def test_allow_first_call(self):
        rule = self._make_rule()
        result = await rule.evaluate(self._ctx())
        assert result.action is PolicyAction.ALLOW

    async def test_allow_within_limit(self):
        rule = self._make_rule(max_calls=5)
        for _ in range(4):
            await rule.evaluate(self._ctx())
        result = await rule.evaluate(self._ctx())
        assert result.action is PolicyAction.ALLOW

    async def test_deny_exceeds_limit(self):
        rule = self._make_rule(max_calls=3)
        for _ in range(3):
            await rule.evaluate(self._ctx())
        result = await rule.evaluate(self._ctx())
        assert result.action is PolicyAction.DENY

    async def test_separate_sessions_have_separate_limits(self):
        rule = self._make_rule(max_calls=2)
        await rule.evaluate(self._ctx(session_id="a"))
        await rule.evaluate(self._ctx(session_id="a"))
        result = await rule.evaluate(self._ctx(session_id="b"))
        assert result.action is PolicyAction.ALLOW

    async def test_edge_case_counts_all_tools_in_session(self):
        rule = self._make_rule(max_calls=3)
        ctx1 = ToolCallContext(tool_name="tool_a", arguments={}, session_id="sess")
        ctx2 = ToolCallContext(tool_name="tool_b", arguments={}, session_id="sess")
        await rule.evaluate(ctx1)
        await rule.evaluate(ctx2)
        await rule.evaluate(ctx1)
        result = await rule.evaluate(ctx2)
        assert result.action is PolicyAction.DENY


# ── BurstDetectionRule ──────────────────────────────────────────────


class TestBurstDetectionRule:
    def _make_rule(self, max_burst: int = 3):
        rule = BurstDetectionRule()
        rule.max_burst = max_burst
        rule.burst_window_seconds = 10.0  # wide window to avoid timing issues
        return rule

    def _ctx(self, session_id: str = "sess1"):
        return ToolCallContext(
            tool_name="any_tool", arguments={}, session_id=session_id
        )

    async def test_allow_single_call(self):
        rule = self._make_rule()
        result = await rule.evaluate(self._ctx())
        assert result.action is PolicyAction.ALLOW

    async def test_allow_within_burst_limit(self):
        rule = self._make_rule(max_burst=5)
        for _ in range(4):
            await rule.evaluate(self._ctx())
        result = await rule.evaluate(self._ctx())
        assert result.action is PolicyAction.ALLOW

    async def test_escalate_burst_exceeded(self):
        rule = self._make_rule(max_burst=3)
        for _ in range(3):
            await rule.evaluate(self._ctx())
        result = await rule.evaluate(self._ctx())
        assert result.action is PolicyAction.ESCALATE

    async def test_separate_sessions(self):
        rule = self._make_rule(max_burst=2)
        await rule.evaluate(self._ctx(session_id="a"))
        await rule.evaluate(self._ctx(session_id="a"))
        result = await rule.evaluate(self._ctx(session_id="b"))
        assert result.action is PolicyAction.ALLOW

    async def test_edge_case_rapid_calls_exactly_at_limit(self):
        rule = self._make_rule(max_burst=5)
        for _ in range(5):
            result = await rule.evaluate(self._ctx())
        assert result.action is PolicyAction.ALLOW
        result = await rule.evaluate(self._ctx())
        assert result.action is PolicyAction.ESCALATE

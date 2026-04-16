"""Deterministic, async policy evaluation engine."""

from __future__ import annotations

from agentshield.core.context import ToolCallContext
from agentshield.core.result import PolicyAction, PolicyResponse
from agentshield.rules.base import BaseRule


class PolicyEngine:
    """Evaluates an ordered list of rules against a tool-call context.

    Rules are sorted by :attr:`BaseRule.priority` (lower values run first).
    The engine short-circuits on the first ``DENY`` or ``ESCALATE`` response.
    If every enabled rule returns ``ALLOW``, the engine returns
    *default_action* (``ALLOW`` by default).

    Args:
        rules: Collection of rule instances to evaluate.
        default_action: Action returned when no rule triggers a block.
    """

    def __init__(
        self,
        rules: list[BaseRule],
        default_action: PolicyAction = PolicyAction.ALLOW,
    ) -> None:
        self.rules: list[BaseRule] = sorted(rules, key=lambda r: r.priority)
        self.default_action = default_action

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Run every enabled rule in priority order.

        Args:
            context: The tool-call context to evaluate.

        Returns:
            A :class:`PolicyResponse` from the first blocking rule, or a
            default ``ALLOW`` response if nothing triggered.
        """
        for rule in self.rules:
            if not rule.enabled:
                continue
            response = await rule.evaluate(context)
            if response.action in (PolicyAction.DENY, PolicyAction.ESCALATE):
                return response
        return PolicyResponse(
            action=self.default_action,
            rule_name="default",
            reason="No rule triggered",
        )

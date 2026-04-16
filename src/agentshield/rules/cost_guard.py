"""Cost guardrail rules (OWASP ASI07 — Denial of Service / runaway spend)."""

from __future__ import annotations

from agentshield.core.context import ToolCallContext
from agentshield.core.result import PolicyAction, PolicyResponse
from agentshield.rules.base import BaseRule


class SessionCostCeilingRule(BaseRule):
    """Deny tool calls when estimated session costs exceed a ceiling.

    Tracks cumulative cost per ``session_id`` using ``cost_per_call``,
    a mapping of tool names to their per-invocation cost in USD.
    Un-mapped tools default to ``default_cost_usd``.
    """

    name: str = "session_cost_ceiling"
    description: str = "Block calls when estimated session cost exceeds the ceiling"
    priority: int = 35
    enabled: bool = True
    owasp_id: str = "ASI07"

    max_cost_usd: float = 10.0
    cost_per_call: dict[str, float] = {}
    default_cost_usd: float = 0.01

    def __init__(self) -> None:
        self._session_costs: dict[str, float] = {}

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Deny if cumulative cost exceeds the ceiling.

        Args:
            context: The tool-call context to inspect.

        Returns:
            DENY if the session cost ceiling is exceeded, ALLOW otherwise.
        """
        call_cost = self.cost_per_call.get(context.tool_name, self.default_cost_usd)
        current = self._session_costs.get(context.session_id, 0.0)
        projected = current + call_cost

        if projected > self.max_cost_usd:
            return PolicyResponse(
                action=PolicyAction.DENY,
                rule_name=self.name,
                reason=(
                    f"Session cost ceiling exceeded: "
                    f"${projected:.4f} > ${self.max_cost_usd:.2f}"
                ),
                details={
                    "session_id": context.session_id,
                    "current_cost": current,
                    "call_cost": call_cost,
                    "projected_cost": projected,
                    "max_cost_usd": self.max_cost_usd,
                },
                owasp_id=self.owasp_id,
            )

        self._session_costs[context.session_id] = projected
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason=f"Session cost ${projected:.4f} within ceiling ${self.max_cost_usd:.2f}",
        )


class CostAlertRule(BaseRule):
    """Escalate when session costs approach the ceiling (default 80%).

    Companion to :class:`SessionCostCeilingRule` — fires a warning before
    the hard limit is hit so a human can review.
    """

    name: str = "cost_alert"
    description: str = (
        "Escalate when session cost reaches alert threshold (default 80%)"
    )
    priority: int = 36
    enabled: bool = True
    owasp_id: str = "ASI07"

    max_cost_usd: float = 10.0
    alert_threshold: float = 0.80
    cost_per_call: dict[str, float] = {}
    default_cost_usd: float = 0.01

    def __init__(self) -> None:
        self._session_costs: dict[str, float] = {}
        self._alerted_sessions: set[str] = set()

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Escalate if session cost exceeds the alert threshold.

        Args:
            context: The tool-call context to inspect.

        Returns:
            ESCALATE once per session when the threshold is crossed, ALLOW
            otherwise.
        """
        call_cost = self.cost_per_call.get(context.tool_name, self.default_cost_usd)
        current = self._session_costs.get(context.session_id, 0.0)
        projected = current + call_cost
        self._session_costs[context.session_id] = projected

        threshold_usd = self.max_cost_usd * self.alert_threshold

        if (
            projected >= threshold_usd
            and context.session_id not in self._alerted_sessions
        ):
            self._alerted_sessions.add(context.session_id)
            return PolicyResponse(
                action=PolicyAction.ESCALATE,
                rule_name=self.name,
                reason=(
                    f"Session cost alert: ${projected:.4f} reached "
                    f"{self.alert_threshold:.0%} of ${self.max_cost_usd:.2f} ceiling"
                ),
                details={
                    "session_id": context.session_id,
                    "current_cost": projected,
                    "alert_threshold": self.alert_threshold,
                    "max_cost_usd": self.max_cost_usd,
                },
                owasp_id=self.owasp_id,
            )

        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason=f"Session cost ${projected:.4f} below alert threshold",
        )

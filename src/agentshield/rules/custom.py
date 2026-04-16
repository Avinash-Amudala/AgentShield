"""YAML-defined custom pattern rules without writing Python."""
from __future__ import annotations

import fnmatch
from typing import Any

from agentshield.core.context import ToolCallContext
from agentshield.core.result import PolicyAction, PolicyResponse
from agentshield.rules.base import BaseRule


class CustomPatternRule(BaseRule):
    """Rule defined entirely through configuration (e.g. YAML).

    Instead of writing a Python subclass, users declare a rule with
    ``name``, ``description``, ``tool_patterns`` (glob), ``action``,
    ``reason``, and ``owasp_id``.  The rule matches tool calls whose
    ``tool_name`` matches any of the configured glob patterns.

    Args:
        name: Machine-friendly rule identifier.
        description: Human-readable explanation.
        tool_patterns: Glob patterns to match against ``tool_name``
            (e.g. ``["deploy_*", "delete_*"]``).
        action: The :class:`PolicyAction` to return on match
            (``"deny"`` or ``"escalate"``).
        reason: Human-readable reason text.
        owasp_id: Optional OWASP Agentic AI identifier.
        priority: Evaluation order (default 50).
        enabled: Whether the rule is active (default True).
    """

    def __init__(
        self,
        *,
        name: str,
        description: str = "",
        tool_patterns: list[str] | None = None,
        action: str = "deny",
        reason: str = "Blocked by custom pattern rule",
        owasp_id: str | None = None,
        priority: int = 50,
        enabled: bool = True,
    ) -> None:
        self.name = name
        self.description = description
        self.tool_patterns: list[str] = tool_patterns or []
        self._action_str = action.lower()
        self.reason = reason
        self.owasp_id = owasp_id
        self.priority = priority
        self.enabled = enabled

    @property
    def _policy_action(self) -> PolicyAction:
        """Resolve the string action to a PolicyAction enum member."""
        mapping = {
            "deny": PolicyAction.DENY,
            "escalate": PolicyAction.ESCALATE,
            "allow": PolicyAction.ALLOW,
        }
        return mapping.get(self._action_str, PolicyAction.DENY)

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Match tool name against configured glob patterns.

        Args:
            context: The tool-call context to inspect.

        Returns:
            The configured action if the tool name matches a pattern,
            ALLOW otherwise.
        """
        for pattern in self.tool_patterns:
            if fnmatch.fnmatch(context.tool_name, pattern):
                return PolicyResponse(
                    action=self._policy_action,
                    rule_name=self.name,
                    reason=self.reason,
                    details={
                        "tool_name": context.tool_name,
                        "matched_pattern": pattern,
                    },
                    owasp_id=self.owasp_id,
                )
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason=f"Tool {context.tool_name!r} did not match any custom pattern",
        )

    def configure(self, settings: dict[str, Any]) -> None:
        """Apply external settings with action-string handling.

        Args:
            settings: Key-value pairs to apply.
        """
        if "action" in settings:
            self._action_str = str(settings.pop("action")).lower()
        super().configure(settings)

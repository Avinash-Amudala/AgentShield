"""Abstract base class for all AgentShield rules."""

from __future__ import annotations

import abc
from typing import Any

from agentshield.core.context import ToolCallContext
from agentshield.core.result import PolicyResponse


class BaseRule(abc.ABC):
    """Abstract base that every AgentShield rule must extend.

    Subclasses **must** override :meth:`evaluate` and should set
    :attr:`name`, :attr:`description`, and :attr:`priority` to meaningful
    values.

    Attributes:
        name: Machine-friendly identifier (e.g. ``"path_traversal"``).
        description: Human-readable explanation of what the rule checks.
        priority: Evaluation order — lower numbers run first.
        enabled: Toggle to skip the rule without removing it.
        owasp_id: Optional OWASP Agentic AI identifier.
    """

    name: str = "unnamed_rule"
    description: str = ""
    priority: int = 100
    enabled: bool = True
    owasp_id: str | None = None

    @abc.abstractmethod
    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Evaluate the tool-call context against this rule.

        Args:
            context: Snapshot of the tool invocation to inspect.

        Returns:
            A :class:`PolicyResponse` indicating the verdict.
        """
        ...

    def configure(self, settings: dict[str, Any]) -> None:
        """Apply external settings (e.g. from ``agentshield.yaml``).

        The default implementation updates instance attributes that already
        exist.  Subclasses may override for richer validation.

        Args:
            settings: Key-value pairs to apply.
        """
        for key, value in settings.items():
            if hasattr(self, key):
                setattr(self, key, value)

    def __repr__(self) -> str:
        status = "enabled" if self.enabled else "disabled"
        return f"<{self.__class__.__name__} name={self.name!r} priority={self.priority} {status}>"

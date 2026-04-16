"""Policy evaluation result types."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PolicyAction(Enum):
    """Possible outcomes of a policy evaluation."""

    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"


@dataclass
class PolicyResponse:
    """Structured result returned by every rule evaluation.

    Attributes:
        action: The policy verdict.
        rule_name: Name of the rule that produced this response.
        reason: Human-readable explanation of the verdict.
        details: Optional machine-readable metadata (matched patterns, etc.).
        owasp_id: Optional OWASP Agentic AI identifier (e.g. ``"OWASP-A1"``).
    """

    action: PolicyAction
    rule_name: str
    reason: str
    details: dict[str, Any] = field(default_factory=dict)
    owasp_id: str | None = None

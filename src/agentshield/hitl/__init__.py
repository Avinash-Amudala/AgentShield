"""Human-in-the-Loop (HITL) approval subsystem for AgentShield."""

from __future__ import annotations

from agentshield.hitl.gateway import ApprovalResult, HITLGateway, NotificationChannel

_active_gateway: HITLGateway | None = None

__all__ = [
    "ApprovalResult",
    "HITLGateway",
    "NotificationChannel",
]

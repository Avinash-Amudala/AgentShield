"""AgentShield — The runtime firewall for AI agents."""

from __future__ import annotations

from agentshield.core.shield import Shield
from agentshield.core.context import ToolCallContext
from agentshield.core.result import PolicyAction, PolicyResponse
from agentshield.rules.base import BaseRule
from agentshield.core.exceptions import ToolCallBlocked

__version__ = "0.1.0"

__all__ = [
    "Shield",
    "ToolCallContext",
    "PolicyAction",
    "PolicyResponse",
    "BaseRule",
    "ToolCallBlocked",
]

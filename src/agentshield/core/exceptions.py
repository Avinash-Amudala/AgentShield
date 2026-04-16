"""Custom exceptions raised by AgentShield."""
from __future__ import annotations

from agentshield.core.result import PolicyResponse


class ToolCallBlocked(Exception):
    """Raised when a tool call is denied in *enforce* mode.

    Attributes:
        response: The full :class:`PolicyResponse` that triggered the block.
    """

    def __init__(self, response: PolicyResponse) -> None:
        self.response = response
        msg = (
            f"Action blocked by AgentShield: {response.reason} "
            f"Rule: {response.rule_name}"
        )
        if response.owasp_id:
            msg += f" | OWASP: {response.owasp_id}"
        msg += (
            "\nTo allow this action, add an exception in "
            "agentshield.yaml or use monitor mode."
        )
        super().__init__(msg)

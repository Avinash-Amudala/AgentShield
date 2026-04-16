"""HITL (Human-in-the-Loop) approval gateway for AgentShield."""
from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import uuid4

from agentshield.core.context import ToolCallContext
from agentshield.core.result import PolicyResponse

logger = logging.getLogger("agentshield.hitl")


@dataclass
class ApprovalResult:
    """Outcome of a human-in-the-loop review.

    Attributes:
        approved: Whether the action was approved.
        reviewer: Identifier of the person who reviewed (e.g. Slack user).
        timestamp: UTC time the decision was recorded.
        event_id: Unique identifier tying this result to its request.
    """

    approved: bool
    reviewer: str = "unknown"
    timestamp: datetime = field(default_factory=datetime.utcnow)
    event_id: str = ""


class NotificationChannel(ABC):
    """Abstract base for delivering approval requests to humans.

    Subclasses must implement :meth:`send` which delivers a structured
    notification payload and returns when delivery is confirmed (or raises).
    """

    @abstractmethod
    async def send(self, payload: dict[str, Any]) -> None:
        """Deliver a notification payload.

        Args:
            payload: Dictionary containing at minimum ``event_id``,
                ``tool_name``, ``agent_id``, ``reason``, and ``arguments``.
        """


class HITLGateway:
    """Central dispatcher for human-in-the-loop approval requests.

    Sends notifications through all registered
    :class:`NotificationChannel` instances and waits for a resolution
    (or timeout).

    Args:
        config: Optional HITL configuration dictionary.  Recognised keys:
            ``timeout`` (float, seconds), ``timeout_action``
            (``"deny"`` | ``"allow"``), ``channels`` (list of channel
            config dicts).
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        cfg = config or {}
        self._channels: list[NotificationChannel] = []
        self._pending: dict[str, asyncio.Future[ApprovalResult]] = {}
        self._timeout: float = float(cfg.get("timeout", 300.0))
        self._timeout_action: str = cfg.get("timeout_action", "deny")

        for ch_cfg in cfg.get("channels", []):
            channel = _build_channel(ch_cfg)
            if channel is not None:
                self._channels.append(channel)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_channel(self, channel: NotificationChannel) -> None:
        """Register a notification channel.

        Args:
            channel: A :class:`NotificationChannel` implementation.
        """
        self._channels.append(channel)

    async def request_approval(
        self,
        context: ToolCallContext,
        response: PolicyResponse,
    ) -> ApprovalResult:
        """Send an approval request and block until resolved or timed out.

        Args:
            context: The tool-call context that triggered escalation.
            response: The policy response that caused the escalation.

        Returns:
            An :class:`ApprovalResult` indicating the human decision.
        """
        event_id = str(uuid4())
        payload = _build_payload(event_id, context, response)

        loop = asyncio.get_running_loop()
        future: asyncio.Future[ApprovalResult] = loop.create_future()
        self._pending[event_id] = future

        logger.info(
            "HITL approval requested: event_id=%s tool=%s agent=%s",
            event_id,
            context.tool_name,
            context.agent_id,
        )

        await self._notify_all(payload)

        try:
            result = await asyncio.wait_for(future, timeout=self._timeout)
        except asyncio.TimeoutError:
            logger.warning(
                "HITL approval timed out after %.0fs: event_id=%s — "
                "applying timeout_action=%s",
                self._timeout,
                event_id,
                self._timeout_action,
            )
            result = ApprovalResult(
                approved=(self._timeout_action == "allow"),
                reviewer="timeout",
                event_id=event_id,
            )
        finally:
            self._pending.pop(event_id, None)

        return result

    def resolve(
        self,
        event_id: str,
        approved: bool,
        reviewer: str = "unknown",
    ) -> None:
        """Resolve a pending approval request.

        Safe to call from any thread — uses
        :meth:`asyncio.Future.set_result` via the event loop's
        thread-safe call mechanism when necessary.

        Args:
            event_id: The unique event identifier from the original request.
            approved: Whether the action is approved.
            reviewer: Who made the decision.

        Raises:
            KeyError: If *event_id* is not found in pending requests.
        """
        future = self._pending.get(event_id)
        if future is None:
            raise KeyError(
                f"No pending approval with event_id={event_id!r}. "
                "It may have already been resolved or timed out."
            )

        result = ApprovalResult(
            approved=approved,
            reviewer=reviewer,
            event_id=event_id,
        )

        if future.get_loop().is_running():
            future.get_loop().call_soon_threadsafe(future.set_result, result)
        else:
            future.set_result(result)

        action_label = "APPROVED" if approved else "DENIED"
        logger.info(
            "HITL %s: event_id=%s reviewer=%s",
            action_label,
            event_id,
            reviewer,
        )

    @property
    def pending_count(self) -> int:
        """Number of approval requests awaiting a decision."""
        return len(self._pending)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _notify_all(self, payload: dict[str, Any]) -> None:
        """Fan-out notification to all channels, logging failures."""
        tasks = [ch.send(payload) for ch in self._channels]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for ch, result in zip(self._channels, results):
            if isinstance(result, Exception):
                logger.error(
                    "Channel %s failed to send notification: %s",
                    type(ch).__name__,
                    result,
                )


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _build_payload(
    event_id: str,
    context: ToolCallContext,
    response: PolicyResponse,
) -> dict[str, Any]:
    """Assemble the notification payload dictionary.

    Args:
        event_id: Unique request identifier.
        context: The tool-call context.
        response: The policy evaluation result.

    Returns:
        A JSON-serialisable dictionary.
    """
    return {
        "event_id": event_id,
        "tool_name": context.tool_name,
        "agent_id": context.agent_id,
        "session_id": context.session_id,
        "arguments": context.arguments,
        "rule_name": response.rule_name,
        "action": response.action.value,
        "reason": response.reason,
        "timestamp": context.timestamp.isoformat(),
    }


def _build_channel(cfg: dict[str, Any]) -> NotificationChannel | None:
    """Instantiate a :class:`NotificationChannel` from a config dict.

    Recognised ``type`` values: ``"terminal"``, ``"slack"``, ``"discord"``.

    Args:
        cfg: Channel configuration with at least a ``type`` key.

    Returns:
        A channel instance, or *None* if the type is unrecognised.
    """
    ch_type = cfg.get("type", "").lower()
    if ch_type == "terminal":
        from agentshield.hitl.terminal import TerminalChannel
        return TerminalChannel()
    if ch_type == "slack":
        from agentshield.hitl.slack import SlackChannel
        return SlackChannel(webhook_url=cfg.get("webhook_url", ""))
    if ch_type == "discord":
        from agentshield.hitl.discord import DiscordChannel
        return DiscordChannel(webhook_url=cfg.get("webhook_url", ""))

    logger.warning("Unknown HITL channel type: %r", ch_type)
    return None

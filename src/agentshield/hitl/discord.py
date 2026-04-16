"""Discord webhook HITL notification channel."""

from __future__ import annotations

import json
import logging
from typing import Any

from agentshield.hitl.gateway import NotificationChannel

logger = logging.getLogger("agentshield.hitl.discord")


class DiscordChannel(NotificationChannel):
    """Sends approval-request notifications to a Discord channel via webhook.

    Requires `httpx <https://www.python-httpx.org/>`_ as an **optional**
    dependency.  The import is deferred to :meth:`send` so that the
    module can be imported without httpx installed.

    Args:
        webhook_url: Discord Webhook URL.
    """

    def __init__(self, webhook_url: str) -> None:
        if not webhook_url:
            raise ValueError(
                "DiscordChannel requires a non-empty webhook_url. "
                "Set it in the HITL config under channels → webhook_url."
            )
        self._webhook_url = webhook_url

    async def send(self, payload: dict[str, Any]) -> None:
        """Post a formatted embed to Discord.

        Args:
            payload: Notification payload produced by the gateway.

        Raises:
            ImportError: If httpx is not installed.
            httpx.HTTPStatusError: On non-2xx responses from Discord.
        """
        try:
            import httpx  # type: ignore[import-untyped]
        except ImportError:
            raise ImportError(
                "httpx is required for the Discord notification channel. "
                "Install it with: pip install httpx"
            ) from None

        message = _format_discord_message(payload)
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                self._webhook_url,
                content=json.dumps(message),
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()

        logger.info(
            "Discord notification sent: event_id=%s",
            payload.get("event_id"),
        )


def _format_discord_message(payload: dict[str, Any]) -> dict[str, Any]:
    """Build a Discord embed message from the notification payload.

    Args:
        payload: Gateway notification payload.

    Returns:
        A Discord-API-compatible webhook payload.
    """
    args_repr = json.dumps(payload.get("arguments", {}), indent=2)

    embed: dict[str, Any] = {
        "title": "AgentShield — Approval Required",
        "color": 0xFF9900,
        "fields": [
            {
                "name": "Event ID",
                "value": f"`{payload.get('event_id', 'N/A')}`",
                "inline": False,
            },
            {
                "name": "Tool",
                "value": f"`{payload.get('tool_name', 'N/A')}`",
                "inline": True,
            },
            {
                "name": "Agent",
                "value": f"`{payload.get('agent_id', 'N/A')}`",
                "inline": True,
            },
            {
                "name": "Rule",
                "value": f"`{payload.get('rule_name', 'N/A')}`",
                "inline": True,
            },
            {"name": "Reason", "value": payload.get("reason", "N/A"), "inline": False},
            {
                "name": "Arguments",
                "value": f"```json\n{args_repr}\n```",
                "inline": False,
            },
        ],
    }

    return {"embeds": [embed]}

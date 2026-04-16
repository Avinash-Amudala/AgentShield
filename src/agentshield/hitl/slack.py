"""Slack webhook HITL notification channel."""

from __future__ import annotations

import json
import logging
from typing import Any

from agentshield.hitl.gateway import NotificationChannel

logger = logging.getLogger("agentshield.hitl.slack")


class SlackChannel(NotificationChannel):
    """Sends approval-request notifications to a Slack channel via webhook.

    Requires `httpx <https://www.python-httpx.org/>`_ as an **optional**
    dependency.  The import is deferred to :meth:`send` so that the
    module can be imported without httpx installed.

    Args:
        webhook_url: Slack Incoming Webhook URL.
    """

    def __init__(self, webhook_url: str) -> None:
        if not webhook_url:
            raise ValueError(
                "SlackChannel requires a non-empty webhook_url. "
                "Set it in the HITL config under channels → webhook_url."
            )
        self._webhook_url = webhook_url

    async def send(self, payload: dict[str, Any]) -> None:
        """Post a formatted message to Slack.

        Args:
            payload: Notification payload produced by the gateway.

        Raises:
            ImportError: If httpx is not installed.
            httpx.HTTPStatusError: On non-2xx responses from Slack.
        """
        try:
            import httpx  # type: ignore[import-untyped]
        except ImportError:
            raise ImportError(
                "httpx is required for the Slack notification channel. "
                "Install it with: pip install httpx"
            ) from None

        message = _format_slack_message(payload)
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                self._webhook_url,
                content=json.dumps(message),
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()

        logger.info(
            "Slack notification sent: event_id=%s",
            payload.get("event_id"),
        )


def _format_slack_message(payload: dict[str, Any]) -> dict[str, Any]:
    """Build a Slack Block Kit message from the notification payload.

    Args:
        payload: Gateway notification payload.

    Returns:
        A Slack-API-compatible message dictionary.
    """
    fields = [
        f"*Event ID:* `{payload.get('event_id', 'N/A')}`",
        f"*Tool:* `{payload.get('tool_name', 'N/A')}`",
        f"*Agent:* `{payload.get('agent_id', 'N/A')}`",
        f"*Rule:* `{payload.get('rule_name', 'N/A')}`",
        f"*Reason:* {payload.get('reason', 'N/A')}",
    ]
    args_repr = json.dumps(payload.get("arguments", {}), indent=2)

    return {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🛡️ AgentShield — Approval Required",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "\n".join(fields),
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Arguments:*\n```{args_repr}```",
                },
            },
        ],
    }

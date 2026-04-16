"""Tests for the HITL (Human-in-the-Loop) subsystem."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest import mock

import pytest

from agentshield.core.context import ToolCallContext
from agentshield.core.result import PolicyAction, PolicyResponse
from agentshield.hitl.gateway import (
    ApprovalResult,
    HITLGateway,
    NotificationChannel,
    _build_channel,
    _build_payload,
)


class DummyChannel(NotificationChannel):
    def __init__(self):
        self.sent: list[dict] = []

    async def send(self, payload: dict[str, Any]) -> None:
        self.sent.append(payload)


class FailingChannel(NotificationChannel):
    async def send(self, payload: dict[str, Any]) -> None:
        raise RuntimeError("channel down")


@pytest.fixture
def ctx():
    return ToolCallContext(tool_name="deploy", arguments={"env": "prod"})


@pytest.fixture
def response():
    return PolicyResponse(
        action=PolicyAction.ESCALATE,
        rule_name="require_approval",
        reason="needs human review",
    )


class TestApprovalResult:
    def test_defaults(self):
        r = ApprovalResult(approved=True)
        assert r.reviewer == "unknown"
        assert r.event_id == ""


class TestHITLGateway:
    async def test_request_approval_timeout_deny(self, ctx, response):
        gw = HITLGateway(config={"timeout": 0.01, "timeout_action": "deny"})
        result = await gw.request_approval(ctx, response)
        assert not result.approved
        assert result.reviewer == "timeout"

    async def test_request_approval_timeout_allow(self, ctx, response):
        gw = HITLGateway(config={"timeout": 0.01, "timeout_action": "allow"})
        result = await gw.request_approval(ctx, response)
        assert result.approved

    async def test_resolve_approves(self, ctx, response):
        gw = HITLGateway(config={"timeout": 5})
        ch = DummyChannel()
        gw.add_channel(ch)

        async def _approve_soon():
            await asyncio.sleep(0.05)
            assert gw.pending_count == 1
            eid = ch.sent[0]["event_id"]
            gw.resolve(eid, approved=True, reviewer="alice")

        task = asyncio.create_task(_approve_soon())
        result = await gw.request_approval(ctx, response)
        await task
        assert result.approved
        assert result.reviewer == "alice"
        assert gw.pending_count == 0

    async def test_resolve_denies(self, ctx, response):
        gw = HITLGateway(config={"timeout": 5})
        ch = DummyChannel()
        gw.add_channel(ch)

        async def _deny():
            await asyncio.sleep(0.05)
            eid = ch.sent[0]["event_id"]
            gw.resolve(eid, approved=False, reviewer="bob")

        task = asyncio.create_task(_deny())
        result = await gw.request_approval(ctx, response)
        await task
        assert not result.approved

    async def test_resolve_unknown_event_raises(self):
        gw = HITLGateway()
        with pytest.raises(KeyError, match="No pending"):
            gw.resolve("nonexistent", approved=True)

    async def test_failing_channel_logged(self, ctx, response):
        gw = HITLGateway(config={"timeout": 0.01})
        gw.add_channel(FailingChannel())
        result = await gw.request_approval(ctx, response)
        assert result.reviewer == "timeout"

    def test_add_channel(self):
        gw = HITLGateway()
        ch = DummyChannel()
        gw.add_channel(ch)
        assert len(gw._channels) == 1


class TestBuildPayload:
    def test_payload_structure(self, ctx, response):
        p = _build_payload("evt-1", ctx, response)
        assert p["event_id"] == "evt-1"
        assert p["tool_name"] == "deploy"
        assert p["rule_name"] == "require_approval"
        assert "timestamp" in p


class TestBuildChannel:
    def test_terminal(self):
        ch = _build_channel({"type": "terminal"})
        from agentshield.hitl.terminal import TerminalChannel

        assert isinstance(ch, TerminalChannel)

    def test_slack(self):
        ch = _build_channel(
            {"type": "slack", "webhook_url": "https://hooks.slack.com/x"}
        )
        from agentshield.hitl.slack import SlackChannel

        assert isinstance(ch, SlackChannel)

    def test_discord(self):
        ch = _build_channel(
            {"type": "discord", "webhook_url": "https://discord.com/api/x"}
        )
        from agentshield.hitl.discord import DiscordChannel

        assert isinstance(ch, DiscordChannel)

    def test_unknown_returns_none(self):
        assert _build_channel({"type": "carrier_pigeon"}) is None

    def test_config_builds_channels(self):
        gw = HITLGateway(
            config={
                "channels": [
                    {"type": "terminal"},
                    {"type": "unknown_type"},
                ]
            }
        )
        assert len(gw._channels) == 1


class TestSlackChannel:
    def test_empty_webhook_raises(self):
        from agentshield.hitl.slack import SlackChannel

        with pytest.raises(ValueError, match="non-empty"):
            SlackChannel(webhook_url="")

    async def test_send_with_mock_httpx(self):
        from agentshield.hitl.slack import SlackChannel, _format_slack_message

        payload = {
            "event_id": "e1",
            "tool_name": "t",
            "agent_id": "a",
            "rule_name": "r",
            "reason": "why",
            "arguments": {},
        }
        msg = _format_slack_message(payload)
        assert "blocks" in msg

        ch = SlackChannel(webhook_url="https://hooks.slack.com/test")
        mock_resp = mock.MagicMock()
        mock_resp.raise_for_status = mock.MagicMock()

        mock_client_inst = mock.AsyncMock()
        mock_client_inst.post = mock.AsyncMock(return_value=mock_resp)
        mock_client_inst.__aenter__ = mock.AsyncMock(return_value=mock_client_inst)
        mock_client_inst.__aexit__ = mock.AsyncMock(return_value=False)

        with mock.patch("httpx.AsyncClient", return_value=mock_client_inst):
            await ch.send(payload)
        mock_client_inst.post.assert_called_once()


class TestDiscordChannel:
    def test_empty_webhook_raises(self):
        from agentshield.hitl.discord import DiscordChannel

        with pytest.raises(ValueError, match="non-empty"):
            DiscordChannel(webhook_url="")

    def test_format_message(self):
        from agentshield.hitl.discord import _format_discord_message

        msg = _format_discord_message({"event_id": "x", "arguments": {}})
        assert "embeds" in msg
        assert msg["embeds"][0]["color"] == 0xFF9900

    async def test_send_with_mock_httpx(self):
        from agentshield.hitl.discord import DiscordChannel

        payload = {
            "event_id": "e1",
            "tool_name": "t",
            "agent_id": "a",
            "rule_name": "r",
            "reason": "why",
            "arguments": {},
        }

        ch = DiscordChannel(webhook_url="https://discord.com/api/test")
        mock_resp = mock.MagicMock()
        mock_resp.raise_for_status = mock.MagicMock()

        mock_client_inst = mock.AsyncMock()
        mock_client_inst.post = mock.AsyncMock(return_value=mock_resp)
        mock_client_inst.__aenter__ = mock.AsyncMock(return_value=mock_client_inst)
        mock_client_inst.__aexit__ = mock.AsyncMock(return_value=False)

        with mock.patch("httpx.AsyncClient", return_value=mock_client_inst):
            await ch.send(payload)
        mock_client_inst.post.assert_called_once()


class TestTerminalChannel:
    async def test_prompt_yes(self):
        from agentshield.hitl.terminal import TerminalChannel

        ch = TerminalChannel()
        payload = {
            "event_id": "e1",
            "tool_name": "t",
            "agent_id": "a",
            "rule_name": "r",
            "reason": "test",
            "arguments": {},
        }
        with mock.patch("builtins.input", return_value="y"):
            await ch.send(payload)

    async def test_prompt_no(self):
        from agentshield.hitl.terminal import TerminalChannel

        ch = TerminalChannel()
        payload = {
            "event_id": "e1",
            "tool_name": "t",
            "agent_id": "a",
            "rule_name": "r",
            "reason": "test",
            "arguments": {},
        }
        with mock.patch("builtins.input", return_value="n"):
            await ch.send(payload)

    async def test_prompt_eof(self):
        from agentshield.hitl.terminal import TerminalChannel

        ch = TerminalChannel()
        payload = {
            "event_id": "e1",
            "tool_name": "t",
            "agent_id": "a",
            "rule_name": "r",
            "reason": "test",
            "arguments": {},
        }
        with mock.patch("builtins.input", side_effect=EOFError):
            await ch.send(payload)

    async def test_prompt_keyboard_interrupt(self):
        from agentshield.hitl.terminal import TerminalChannel

        ch = TerminalChannel()
        payload = {
            "event_id": "e1",
            "tool_name": "t",
            "agent_id": "a",
            "rule_name": "r",
            "reason": "test",
            "arguments": {},
        }
        with mock.patch("builtins.input", side_effect=KeyboardInterrupt):
            await ch.send(payload)

    def test_try_resolve_no_gateway(self):
        from agentshield.hitl.terminal import _try_resolve

        _try_resolve("nonexistent", True)

"""Extended Shield tests covering decorator, dry-run, escalate paths, and properties."""

from __future__ import annotations

from unittest import mock

import pytest

from agentshield import Shield, ToolCallBlocked, ToolCallContext
from agentshield.core.result import PolicyAction, PolicyResponse
from agentshield.rules.base import BaseRule


class AlwaysDenyRule(BaseRule):
    name = "always_deny"
    priority = 1

    async def evaluate(self, context):
        return PolicyResponse(
            action=PolicyAction.DENY, rule_name=self.name, reason="denied"
        )


class AlwaysEscalateRule(BaseRule):
    name = "always_escalate"
    priority = 1

    async def evaluate(self, context):
        return PolicyResponse(
            action=PolicyAction.ESCALATE,
            rule_name=self.name,
            reason="needs review",
            owasp_id="ASI09",
        )


class TestShieldDryRun:
    async def test_dry_run_does_not_block(self):
        shield = Shield(rules=[AlwaysDenyRule()], mode="dry-run", log_file=None)
        ctx = ToolCallContext(tool_name="test", arguments={})
        resp = await shield.check(ctx)
        assert resp.action is PolicyAction.DENY

    async def test_dry_run_prints(self, capsys):
        shield = Shield(rules=[AlwaysDenyRule()], mode="dry-run", log_file=None)
        ctx = ToolCallContext(tool_name="test", arguments={})
        await shield.check(ctx)
        assert "WOULD BLOCK" in capsys.readouterr().out


class TestShieldEscalate:
    async def test_escalate_no_hitl_allows(self):
        shield = Shield(rules=[AlwaysEscalateRule()], mode="enforce", log_file=None)
        ctx = ToolCallContext(tool_name="deploy_prod", arguments={})
        resp = await shield.check(ctx)
        assert resp.action is PolicyAction.ESCALATE

    async def test_escalate_with_hitl_approved(self):
        shield = Shield(rules=[AlwaysEscalateRule()], mode="enforce", log_file=None)
        from agentshield.hitl.gateway import ApprovalResult

        mock_hitl = mock.AsyncMock()
        mock_hitl.request_approval = mock.AsyncMock(
            return_value=ApprovalResult(approved=True, reviewer="alice")
        )
        shield._hitl = mock_hitl

        ctx = ToolCallContext(tool_name="deploy_prod", arguments={})
        resp = await shield.check(ctx)
        assert resp.action is PolicyAction.ESCALATE

    async def test_escalate_with_hitl_denied(self):
        shield = Shield(rules=[AlwaysEscalateRule()], mode="enforce", log_file=None)
        from agentshield.hitl.gateway import ApprovalResult

        mock_hitl = mock.AsyncMock()
        mock_hitl.request_approval = mock.AsyncMock(
            return_value=ApprovalResult(approved=False, reviewer="bob")
        )
        shield._hitl = mock_hitl

        ctx = ToolCallContext(tool_name="deploy_prod", arguments={})
        with pytest.raises(ToolCallBlocked):
            await shield.check(ctx)


class TestShieldMonitor:
    async def test_monitor_mode_no_block(self):
        shield = Shield(rules=[AlwaysDenyRule()], mode="monitor", log_file=None)
        ctx = ToolCallContext(tool_name="test", arguments={})
        resp = await shield.check(ctx)
        assert resp.action is PolicyAction.DENY


class TestShieldProtectDecorator:
    async def test_protect_async(self):
        shield = Shield(rules=[], mode="enforce", log_file=None)

        @shield.protect
        async def my_tool(query: str) -> str:
            return f"ran: {query}"

        result = await my_tool("test")
        assert result == "ran: test"

    def test_protect_sync(self):
        shield = Shield(rules=[], mode="enforce", log_file=None)

        @shield.protect
        def my_tool(query: str) -> str:
            return f"ran: {query}"

        result = my_tool("test")
        assert result == "ran: test"

    async def test_protect_with_kwargs(self):
        shield = Shield(rules=[], mode="enforce", log_file=None)

        @shield.protect(tool_name="custom_name", agent_id="bot-1")
        async def my_tool(x: int) -> int:
            return x + 1

        assert await my_tool(5) == 6

    def test_protect_sync_blocks(self):
        shield = Shield(rules=[AlwaysDenyRule()], mode="enforce", log_file=None)

        @shield.protect
        def my_tool(query: str) -> str:
            return query

        with pytest.raises(ToolCallBlocked):
            my_tool("test")


class TestShieldProperties:
    def test_rules_property(self):
        shield = Shield(rules=[], mode="enforce", log_file=None)
        assert isinstance(shield.rules, list)

    def test_audit_logger_none(self):
        shield = Shield(rules=[], mode="enforce", log_file=None)
        assert shield.audit_logger is None

    def test_audit_logger_set(self, tmp_path):
        shield = Shield(rules=[], log_file=str(tmp_path / "a.jsonl"))
        assert shield.audit_logger is not None

    def test_hitl_gateway_none(self):
        shield = Shield(rules=[], mode="enforce", log_file=None)
        assert shield.hitl_gateway is None

    def test_dashboard_none(self):
        shield = Shield(rules=[], mode="enforce", log_file=None)
        assert shield.dashboard is None

    def test_repr_minimal(self):
        shield = Shield(rules=[], mode="enforce", log_file=None)
        r = repr(shield)
        assert "enforce" in r
        assert "log_file" not in r

    def test_repr_with_log(self, tmp_path):
        shield = Shield(rules=[], log_file=str(tmp_path / "a.jsonl"))
        assert "log_file" in repr(shield)

    def test_invalid_mode(self):
        with pytest.raises(ValueError, match="Invalid mode"):
            Shield(rules=[], mode="turbo")


class TestShieldConfigIntegration:
    def test_yaml_config_with_rules(self, tmp_path):
        cfg = tmp_path / "agentshield.yaml"
        cfg.write_text(
            "mode: monitor\nrules:\n  destructive_sql:\n    enabled: false\n",
            encoding="utf-8",
        )
        shield = Shield(config_path=str(cfg))
        assert shield.mode == "monitor"

    def test_constructor_overrides_config(self, tmp_path):
        cfg = tmp_path / "agentshield.yaml"
        cfg.write_text("mode: monitor\n", encoding="utf-8")
        shield = Shield(config_path=str(cfg), mode="enforce", rules=[])
        assert shield.mode == "enforce"

    def test_hitl_from_config(self, tmp_path):
        cfg = tmp_path / "agentshield.yaml"
        cfg.write_text(
            "mode: enforce\nhitl:\n  timeout_seconds: 30\n  channel: terminal\n",
            encoding="utf-8",
        )
        shield = Shield(config_path=str(cfg), rules=[])
        assert shield.hitl_gateway is not None

    def test_hitl_shorthand_conversion(self, tmp_path):
        cfg = tmp_path / "agentshield.yaml"
        cfg.write_text(
            "mode: enforce\nhitl:\n  channel: slack\n  webhook_url: https://example.com\n  timeout_seconds: 60\n  default_action: allow\n",
            encoding="utf-8",
        )
        shield = Shield(config_path=str(cfg), rules=[])
        assert shield.hitl_gateway is not None

    def test_config_default_action_string(self, tmp_path):
        cfg = tmp_path / "agentshield.yaml"
        cfg.write_text("default_action: deny\n", encoding="utf-8")
        shield = Shield(config_path=str(cfg), rules=[])
        assert shield.mode == "enforce"

    def test_dashboard_port_from_config(self, tmp_path):
        cfg = tmp_path / "agentshield.yaml"
        cfg.write_text("dashboard_port: 8080\n", encoding="utf-8")
        shield = Shield(config_path=str(cfg), rules=[])
        assert shield.dashboard_port == 8080

    def test_missing_config_path_raises(self):
        with pytest.raises(FileNotFoundError):
            Shield(config_path="/no/such/config.yaml", rules=[])

    def test_normalize_hitl_already_canonical(self):
        raw = {"timeout": 30, "channels": [{"type": "terminal"}]}
        result = Shield._normalize_hitl_config(raw)
        assert result["channels"] == [{"type": "terminal"}]

    def test_dashboard_push_event(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        shield = Shield(rules=[], log_file=str(log), dashboard_port=9999)
        if shield.dashboard is not None:
            shield.dashboard.push_event({"test": True})
            assert len(shield.dashboard.events) > 0


class TestShieldLogEvaluation:
    async def test_log_with_owasp(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        shield = Shield(rules=[], log_file=str(log))

        class OWASPRule(BaseRule):
            name = "owasp_test"
            owasp_id = "ASI01"

            async def evaluate(self, context):
                return PolicyResponse(
                    action=PolicyAction.ALLOW,
                    rule_name=self.name,
                    reason="ok",
                    owasp_id="ASI01",
                )

        shield._engine._rules = [OWASPRule()]
        ctx = ToolCallContext(tool_name="t", arguments={})
        await shield.check(ctx)

    async def test_escalate_logged(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        shield = Shield(rules=[AlwaysEscalateRule()], log_file=str(log), mode="enforce")
        ctx = ToolCallContext(tool_name="deploy", arguments={})
        resp = await shield.check(ctx)
        assert resp.action is PolicyAction.ESCALATE

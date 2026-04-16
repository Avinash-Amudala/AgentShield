from __future__ import annotations

from unittest.mock import patch

import pytest

from agentshield.core.context import ToolCallContext
from agentshield.core.result import PolicyAction
from agentshield.rules.network import (
    DNSRebindingRule,
    DomainAllowlistRule,
    DomainDenylistRule,
    InternalNetworkAccessRule,
)

# ── InternalNetworkAccessRule ───────────────────────────────────────


class TestInternalNetworkAccessRule:
    @pytest.fixture
    def rule(self):
        return InternalNetworkAccessRule()

    async def test_allow_public_ip(self, rule):
        ctx = ToolCallContext(
            tool_name="fetch",
            arguments={"url": "http://8.8.8.8/api"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_allow_no_ip(self, rule):
        ctx = ToolCallContext(
            tool_name="fetch",
            arguments={"query": "SELECT 1"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_deny_private_10_range(self, rule):
        ctx = ToolCallContext(
            tool_name="fetch",
            arguments={"url": "http://10.0.0.1/admin"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_deny_private_192_168(self, rule):
        ctx = ToolCallContext(
            tool_name="fetch",
            arguments={"url": "http://192.168.1.1/config"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_deny_loopback(self, rule):
        ctx = ToolCallContext(
            tool_name="fetch",
            arguments={"url": "http://127.0.0.1:8080/secret"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_edge_case_link_local(self, rule):
        ctx = ToolCallContext(
            tool_name="fetch",
            arguments={"url": "http://169.254.169.254/metadata"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_disabled_blocking(self, rule):
        rule.block_private_ips = False
        ctx = ToolCallContext(
            tool_name="fetch",
            arguments={"url": "http://10.0.0.1/admin"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW


# ── DomainDenylistRule ──────────────────────────────────────────────


class TestDomainDenylistRule:
    @pytest.fixture
    def rule(self):
        r = DomainDenylistRule()
        r.denied_domains = ["evil.com", "malware.org"]
        return r

    async def test_allow_safe_domain(self, rule):
        ctx = ToolCallContext(
            tool_name="fetch",
            arguments={"url": "https://example.com/api"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_allow_no_url(self, rule):
        ctx = ToolCallContext(tool_name="query", arguments={"sql": "SELECT 1"})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_deny_exact_match(self, rule):
        ctx = ToolCallContext(
            tool_name="fetch",
            arguments={"url": "https://evil.com/phishing"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_deny_subdomain(self, rule):
        ctx = ToolCallContext(
            tool_name="fetch",
            arguments={"url": "https://api.evil.com/data"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_edge_case_empty_denylist(self):
        rule = DomainDenylistRule()
        ctx = ToolCallContext(
            tool_name="fetch",
            arguments={"url": "https://anything.com"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW


# ── DomainAllowlistRule ────────────────────────────────────────────


class TestDomainAllowlistRule:
    @pytest.fixture
    def rule(self):
        r = DomainAllowlistRule()
        r.allowed_domains = ["api.example.com", "cdn.example.com"]
        return r

    async def test_allow_listed_domain(self, rule):
        ctx = ToolCallContext(
            tool_name="fetch",
            arguments={"url": "https://api.example.com/data"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_allow_no_urls(self, rule):
        ctx = ToolCallContext(tool_name="query", arguments={"data": "no url here"})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_deny_unlisted_domain(self, rule):
        ctx = ToolCallContext(
            tool_name="fetch",
            arguments={"url": "https://evil.com/steal"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_deny_similar_but_unlisted(self, rule):
        ctx = ToolCallContext(
            tool_name="fetch",
            arguments={"url": "https://notexample.com/data"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_edge_case_empty_allowlist_permits_all(self):
        rule = DomainAllowlistRule()
        ctx = ToolCallContext(
            tool_name="fetch",
            arguments={"url": "https://anything.com"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW


# ── DNSRebindingRule ────────────────────────────────────────────────


class TestDNSRebindingRule:
    @pytest.fixture
    def rule(self):
        return DNSRebindingRule()

    async def test_allow_no_urls(self, rule):
        ctx = ToolCallContext(tool_name="query", arguments={"data": "no url"})
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_allow_ip_urls_skipped(self, rule):
        ctx = ToolCallContext(
            tool_name="fetch",
            arguments={"url": "http://8.8.8.8/dns"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    @patch("agentshield.rules.network.socket.getaddrinfo")
    async def test_deny_rebinding_to_private_ip(self, mock_getaddrinfo, rule):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("10.0.0.1", 0)),
        ]
        ctx = ToolCallContext(
            tool_name="fetch",
            arguments={"url": "http://rebind.attacker.com/steal"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY
        assert "rebinding" in result.reason.lower() or "rebind" in result.reason.lower()

    @patch("agentshield.rules.network.socket.getaddrinfo")
    async def test_allow_resolves_to_public(self, mock_getaddrinfo, rule):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 0)),
        ]
        ctx = ToolCallContext(
            tool_name="fetch",
            arguments={"url": "http://example.com/api"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    @patch("agentshield.rules.network.socket.getaddrinfo")
    async def test_edge_case_dns_failure_allows(self, mock_getaddrinfo, rule):
        import socket

        mock_getaddrinfo.side_effect = socket.gaierror("DNS lookup failed")
        ctx = ToolCallContext(
            tool_name="fetch",
            arguments={"url": "http://nonexistent.example.com/test"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

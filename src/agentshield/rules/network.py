"""Network access safety rules (OWASP ASI04 — Insufficient Access Controls)."""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Any
from urllib.parse import urlparse

from agentshield.core.context import ToolCallContext
from agentshield.core.result import PolicyAction, PolicyResponse
from agentshield.rules.base import BaseRule


def _extract_strings(obj: Any) -> list[str]:
    """Recursively extract all string values from nested dicts/lists."""
    strings: list[str] = []
    if isinstance(obj, str):
        strings.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            strings.extend(_extract_strings(v))
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            strings.extend(_extract_strings(item))
    return strings


_URL_PATTERN: re.Pattern[str] = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)

_IP_PATTERN: re.Pattern[str] = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


def _extract_urls(obj: Any) -> list[str]:
    """Extract HTTP(S) URLs from all string values."""
    urls: list[str] = []
    for value in _extract_strings(obj):
        urls.extend(_URL_PATTERN.findall(value))
    return urls


def _extract_hostnames(urls: list[str]) -> list[str]:
    """Extract hostnames from URL strings."""
    hostnames: list[str] = []
    for url in urls:
        try:
            parsed = urlparse(url)
            if parsed.hostname:
                hostnames.append(parsed.hostname.lower())
        except Exception:
            continue
    return hostnames


def _is_private_ip(ip_str: str) -> bool:
    """Return True if the IP address is private/reserved/link-local/loopback."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
        )
    except ValueError:
        return False


class InternalNetworkAccessRule(BaseRule):
    """Block requests targeting private / internal network addresses.

    Prevents SSRF by detecting 10.x, 172.16-31.x, 192.168.x, 127.x,
    and 169.254.x addresses.
    """

    name: str = "internal_network_access"
    description: str = (
        "Block requests to private/internal IP addresses (SSRF prevention)"
    )
    priority: int = 20
    enabled: bool = True
    owasp_id: str = "ASI04"

    block_private_ips: bool = True

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Block requests that target private IP addresses.

        Args:
            context: The tool-call context to inspect.

        Returns:
            DENY if a private IP is targeted, ALLOW otherwise.
        """
        if not self.block_private_ips:
            return PolicyResponse(
                action=PolicyAction.ALLOW,
                rule_name=self.name,
                reason="Private IP blocking is disabled",
            )

        for value in _extract_strings(context.arguments):
            for ip_match in _IP_PATTERN.findall(value):
                if _is_private_ip(ip_match):
                    return PolicyResponse(
                        action=PolicyAction.DENY,
                        rule_name=self.name,
                        reason=f"Internal network access blocked: {ip_match}",
                        details={"ip_address": ip_match, "value_snippet": value[:200]},
                        owasp_id=self.owasp_id,
                    )

        for url in _extract_urls(context.arguments):
            hostnames = _extract_hostnames([url])
            for hostname in hostnames:
                if _IP_PATTERN.match(hostname) and _is_private_ip(hostname):
                    return PolicyResponse(
                        action=PolicyAction.DENY,
                        rule_name=self.name,
                        reason=f"Internal network access via URL blocked: {hostname}",
                        details={"hostname": hostname, "url": url[:200]},
                        owasp_id=self.owasp_id,
                    )

        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason="No internal network access detected",
        )


class DomainDenylistRule(BaseRule):
    """Block requests to explicitly denied domains."""

    name: str = "domain_denylist"
    description: str = "Block requests to denied domains (configurable list)"
    priority: int = 20
    enabled: bool = True
    owasp_id: str = "ASI04"

    denied_domains: list[str] = []

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Block requests whose target domain is in the denylist.

        Args:
            context: The tool-call context to inspect.

        Returns:
            DENY if a denied domain is found, ALLOW otherwise.
        """
        if not self.denied_domains:
            return PolicyResponse(
                action=PolicyAction.ALLOW,
                rule_name=self.name,
                reason="No denied domains configured",
            )

        denied = {d.lower() for d in self.denied_domains}
        urls = _extract_urls(context.arguments)
        hostnames = _extract_hostnames(urls)

        for hostname in hostnames:
            if hostname in denied:
                return PolicyResponse(
                    action=PolicyAction.DENY,
                    rule_name=self.name,
                    reason=f"Domain is on denylist: {hostname}",
                    details={"hostname": hostname},
                    owasp_id=self.owasp_id,
                )
            for denied_domain in denied:
                if hostname.endswith("." + denied_domain):
                    return PolicyResponse(
                        action=PolicyAction.DENY,
                        rule_name=self.name,
                        reason=f"Subdomain of denied domain: {hostname}",
                        details={"hostname": hostname, "denied_parent": denied_domain},
                        owasp_id=self.owasp_id,
                    )

        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason="No denied domains detected",
        )


class DomainAllowlistRule(BaseRule):
    """Block requests to domains not on the allowlist.

    Only active when ``allowed_domains`` is non-empty.
    """

    name: str = "domain_allowlist"
    description: str = "Block requests to non-allowlisted domains"
    priority: int = 20
    enabled: bool = True
    owasp_id: str = "ASI04"

    allowed_domains: list[str] = []

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Block requests whose domain is not in the allowlist.

        Args:
            context: The tool-call context to inspect.

        Returns:
            DENY if a non-allowlisted domain is found, ALLOW if the
            allowlist is empty or all domains are allowed.
        """
        if not self.allowed_domains:
            return PolicyResponse(
                action=PolicyAction.ALLOW,
                rule_name=self.name,
                reason="No allowlist configured — all domains permitted",
            )

        allowed = {d.lower() for d in self.allowed_domains}
        urls = _extract_urls(context.arguments)
        hostnames = _extract_hostnames(urls)

        for hostname in hostnames:
            is_allowed = hostname in allowed or any(
                hostname.endswith("." + a) for a in allowed
            )
            if not is_allowed:
                return PolicyResponse(
                    action=PolicyAction.DENY,
                    rule_name=self.name,
                    reason=f"Domain not on allowlist: {hostname}",
                    details={"hostname": hostname, "allowed_domains": list(allowed)},
                    owasp_id=self.owasp_id,
                )

        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason="All domains are on the allowlist",
        )


class DNSRebindingRule(BaseRule):
    """Block domains that resolve to private IP ranges (DNS rebinding).

    Performs a synchronous DNS lookup to detect domains that may have been
    pointed at internal infrastructure.
    """

    name: str = "dns_rebinding"
    description: str = "Block domains resolving to private IP ranges (DNS rebinding)"
    priority: int = 20
    enabled: bool = True
    owasp_id: str = "ASI04"

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Resolve hostnames and block if they map to private IPs.

        Args:
            context: The tool-call context to inspect.

        Returns:
            DENY if DNS rebinding is detected, ALLOW otherwise.
        """
        urls = _extract_urls(context.arguments)
        hostnames = _extract_hostnames(urls)

        for hostname in hostnames:
            if _IP_PATTERN.match(hostname):
                continue

            try:
                resolved_ips = socket.getaddrinfo(hostname, None, socket.AF_INET)
                for _family, _type, _proto, _canonname, sockaddr in resolved_ips:
                    ip_str = sockaddr[0]
                    if _is_private_ip(ip_str):
                        return PolicyResponse(
                            action=PolicyAction.DENY,
                            rule_name=self.name,
                            reason=f"DNS rebinding detected: {hostname} resolves to private IP {ip_str}",
                            details={"hostname": hostname, "resolved_ip": ip_str},
                            owasp_id=self.owasp_id,
                        )
            except (socket.gaierror, OSError):
                continue

        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason="No DNS rebinding detected",
        )

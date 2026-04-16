"""Credential and sensitive-data leak rules (OWASP ASI04)."""
from __future__ import annotations

import re
from typing import Any

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


class APIKeyLeakRule(BaseRule):
    """Block tool calls that contain well-known API key patterns.

    Detects AWS access keys (``AKIA…``), Google API keys (``AIza…``),
    OpenAI keys (``sk-…``), Stripe keys (``sk_live_…``), GitHub PATs
    (``ghp_…``), and Slack tokens (``xoxb-…``).
    """

    name: str = "api_key_leak"
    description: str = "Block calls containing well-known API key patterns"
    priority: int = 10
    enabled: bool = True
    owasp_id: str = "ASI04"

    _PATTERNS: dict[str, re.Pattern[str]] = {
        "AWS Access Key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "Google API Key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "OpenAI Key": re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
        "Stripe Live Key": re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b"),
        "GitHub PAT": re.compile(r"\bghp_[A-Za-z0-9]{36,}\b"),
        "Slack Token": re.compile(r"\bxoxb-[0-9]{10,}-[0-9A-Za-z]{20,}\b"),
        "Slack Bot Token (xoxp)": re.compile(r"\bxoxp-[0-9]{10,}-[0-9A-Za-z]{20,}\b"),
    }

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Scan argument strings for known API key patterns.

        Args:
            context: The tool-call context to inspect.

        Returns:
            DENY if an API key pattern is found, ALLOW otherwise.
        """
        for value in _extract_strings(context.arguments):
            for key_type, pattern in self._PATTERNS.items():
                match = pattern.search(value)
                if match:
                    masked = match.group()[:8] + "****"
                    return PolicyResponse(
                        action=PolicyAction.DENY,
                        rule_name=self.name,
                        reason=f"{key_type} detected in tool arguments",
                        details={"key_type": key_type, "masked_match": masked},
                        owasp_id=self.owasp_id,
                    )
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason="No API key patterns detected",
        )


class TokenLeakRule(BaseRule):
    """Block tool calls that contain JWT, Bearer, or OAuth tokens."""

    name: str = "token_leak"
    description: str = "Block calls containing JWT, Bearer, or OAuth tokens"
    priority: int = 10
    enabled: bool = True
    owasp_id: str = "ASI04"

    _PATTERNS: dict[str, re.Pattern[str]] = {
        "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "Bearer Token": re.compile(r"\bBearer\s+[A-Za-z0-9_\-.~+/]{20,}\b"),
        "OAuth Token": re.compile(r"\boauth[_-]?token[\"':\s=]+[A-Za-z0-9_\-.]{20,}", re.IGNORECASE),
    }

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Scan argument strings for token patterns.

        Args:
            context: The tool-call context to inspect.

        Returns:
            DENY if a token pattern is found, ALLOW otherwise.
        """
        for value in _extract_strings(context.arguments):
            for token_type, pattern in self._PATTERNS.items():
                match = pattern.search(value)
                if match:
                    masked = match.group()[:12] + "****"
                    return PolicyResponse(
                        action=PolicyAction.DENY,
                        rule_name=self.name,
                        reason=f"{token_type} detected in tool arguments",
                        details={"token_type": token_type, "masked_match": masked},
                        owasp_id=self.owasp_id,
                    )
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason="No token patterns detected",
        )


class PIILeakRule(BaseRule):
    """Escalate tool calls that contain PII patterns.

    Detects US Social Security Numbers, credit card numbers (Luhn-validated),
    and email addresses.
    """

    name: str = "pii_leak"
    description: str = "Escalate calls containing SSN, credit card, or email patterns"
    priority: int = 11
    enabled: bool = True
    owasp_id: str = "ASI04"

    _SSN_PATTERN: re.Pattern[str] = re.compile(
        r"\b\d{3}-\d{2}-\d{4}\b"
    )
    _CC_PATTERN: re.Pattern[str] = re.compile(
        r"\b(?:\d[ -]*?){13,19}\b"
    )
    _EMAIL_PATTERN: re.Pattern[str] = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    )

    @staticmethod
    def _luhn_check(number: str) -> bool:
        """Validate a credit-card number with the Luhn algorithm."""
        digits = [int(d) for d in number if d.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False
        checksum = 0
        reverse = digits[::-1]
        for i, digit in enumerate(reverse):
            if i % 2 == 1:
                digit *= 2
                if digit > 9:
                    digit -= 9
            checksum += digit
        return checksum % 10 == 0

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Scan argument strings for PII patterns.

        Args:
            context: The tool-call context to inspect.

        Returns:
            ESCALATE if PII is detected, ALLOW otherwise.
        """
        for value in _extract_strings(context.arguments):
            if self._SSN_PATTERN.search(value):
                return PolicyResponse(
                    action=PolicyAction.ESCALATE,
                    rule_name=self.name,
                    reason="Possible SSN detected in tool arguments",
                    details={"pii_type": "SSN"},
                    owasp_id=self.owasp_id,
                )
            for cc_match in self._CC_PATTERN.finditer(value):
                raw = cc_match.group().replace(" ", "").replace("-", "")
                if raw.isdigit() and self._luhn_check(raw):
                    return PolicyResponse(
                        action=PolicyAction.ESCALATE,
                        rule_name=self.name,
                        reason="Possible credit card number detected in tool arguments",
                        details={"pii_type": "credit_card", "masked": raw[:4] + "****" + raw[-4:]},
                        owasp_id=self.owasp_id,
                    )
            if self._EMAIL_PATTERN.search(value):
                return PolicyResponse(
                    action=PolicyAction.ESCALATE,
                    rule_name=self.name,
                    reason="Email address detected in tool arguments",
                    details={"pii_type": "email"},
                    owasp_id=self.owasp_id,
                )
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason="No PII detected",
        )


class PasswordLeakRule(BaseRule):
    """Block tool calls that contain password-like values in arguments.

    Looks for argument keys/values that suggest credential transport to
    external-facing tools.
    """

    name: str = "password_leak"
    description: str = "Block password-like patterns in args sent to external tools"
    priority: int = 10
    enabled: bool = True
    owasp_id: str = "ASI04"

    _KEY_PATTERN: re.Pattern[str] = re.compile(
        r"(password|passwd|pwd|secret|credential|auth_token)", re.IGNORECASE
    )
    _VALUE_PATTERN: re.Pattern[str] = re.compile(
        r"(?:password|passwd|pwd|secret)[\"':\s=]+\S{6,}", re.IGNORECASE
    )

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Scan argument keys and values for password-like content.

        Args:
            context: The tool-call context to inspect.

        Returns:
            DENY if password content is found in arguments, ALLOW otherwise.
        """
        for key in context.arguments:
            if self._KEY_PATTERN.search(key):
                return PolicyResponse(
                    action=PolicyAction.DENY,
                    rule_name=self.name,
                    reason=f"Password-like argument key detected: {key!r}",
                    details={"argument_key": key},
                    owasp_id=self.owasp_id,
                )
        for value in _extract_strings(context.arguments):
            if self._VALUE_PATTERN.search(value):
                return PolicyResponse(
                    action=PolicyAction.DENY,
                    rule_name=self.name,
                    reason="Password-like value detected in tool arguments",
                    details={"value_snippet": value[:50] + "..."},
                    owasp_id=self.owasp_id,
                )
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason="No password patterns detected",
        )


class EnvVarLeakRule(BaseRule):
    """Escalate tool calls referencing environment variables with secret names.

    Detects references to env vars whose names contain SECRET, KEY, TOKEN,
    or PASSWORD.
    """

    name: str = "env_var_leak"
    description: str = "Escalate references to env vars containing SECRET, KEY, TOKEN, PASSWORD"
    priority: int = 11
    enabled: bool = True
    owasp_id: str = "ASI04"

    _PATTERN: re.Pattern[str] = re.compile(
        r"\$\{?([A-Z_]*(?:SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL)[A-Z_]*)\}?",
        re.IGNORECASE,
    )
    _GETENV_PATTERN: re.Pattern[str] = re.compile(
        r"(?:os\.(?:environ|getenv)|process\.env|ENV)[\[(]?[\"']([^\"']*(?:SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL)[^\"']*)[\"']",
        re.IGNORECASE,
    )

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Scan argument strings for references to secret-bearing env vars.

        Args:
            context: The tool-call context to inspect.

        Returns:
            ESCALATE if secret env var references are found, ALLOW otherwise.
        """
        for value in _extract_strings(context.arguments):
            match = self._PATTERN.search(value) or self._GETENV_PATTERN.search(value)
            if match:
                return PolicyResponse(
                    action=PolicyAction.ESCALATE,
                    rule_name=self.name,
                    reason=f"Reference to secret env var detected: {match.group(1)}",
                    details={"env_var": match.group(1), "value_snippet": value[:200]},
                    owasp_id=self.owasp_id,
                )
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason="No secret env var references detected",
        )

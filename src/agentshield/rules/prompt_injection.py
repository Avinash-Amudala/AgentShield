"""Prompt injection detection rules (OWASP ASI01 — Prompt Injection)."""
from __future__ import annotations

import base64
import re
from typing import Any
from urllib.parse import unquote

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


class DirectInjectionRule(BaseRule):
    """Block direct prompt injection attempts in tool arguments.

    Detects phrases like "ignore previous instructions", "you are now",
    "system: ", and similar override attempts.
    """

    name: str = "direct_injection"
    description: str = "Block direct prompt injection ('ignore previous instructions', etc.)"
    priority: int = 5
    enabled: bool = True
    owasp_id: str = "ASI01"

    _PATTERNS: list[re.Pattern[str]] = [
        re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
        re.compile(r"ignore\s+(all\s+)?prior\s+instructions", re.IGNORECASE),
        re.compile(r"disregard\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
        re.compile(r"forget\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
        re.compile(r"you\s+are\s+now\s+", re.IGNORECASE),
        re.compile(r"act\s+as\s+if\s+you\s+are\b", re.IGNORECASE),
        re.compile(r"pretend\s+you\s+are\b", re.IGNORECASE),
        re.compile(r"^system:\s+", re.IGNORECASE | re.MULTILINE),
        re.compile(r"new\s+instructions?:\s+", re.IGNORECASE),
        re.compile(r"override\s+(?:your\s+)?(?:previous\s+)?instructions", re.IGNORECASE),
    ]

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Scan argument strings for direct injection phrases.

        Args:
            context: The tool-call context to inspect.

        Returns:
            DENY if a direct injection pattern is found, ALLOW otherwise.
        """
        for value in _extract_strings(context.arguments):
            for pattern in self._PATTERNS:
                match = pattern.search(value)
                if match:
                    return PolicyResponse(
                        action=PolicyAction.DENY,
                        rule_name=self.name,
                        reason=f"Prompt injection detected: {match.group()!r}",
                        details={"matched_pattern": match.group(), "value_snippet": value[:200]},
                        owasp_id=self.owasp_id,
                    )
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason="No direct injection detected",
        )


class EncodedInjectionRule(BaseRule):
    """Block encoded prompt injection payloads.

    Decodes base64, hex, and URL-encoded strings, then scans the decoded
    content for injection patterns.
    """

    name: str = "encoded_injection"
    description: str = "Block base64, hex, and URL-encoded injection payloads"
    priority: int = 5
    enabled: bool = True
    owasp_id: str = "ASI01"

    _INJECTION_PATTERNS: list[re.Pattern[str]] = [
        re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
        re.compile(r"you\s+are\s+now\s+", re.IGNORECASE),
        re.compile(r"^system:\s+", re.IGNORECASE | re.MULTILINE),
        re.compile(r"<\|im_start\|>", re.IGNORECASE),
        re.compile(r"\[INST\]", re.IGNORECASE),
    ]

    _BASE64_PATTERN: re.Pattern[str] = re.compile(
        r"[A-Za-z0-9+/]{20,}={0,2}"
    )
    _HEX_PATTERN: re.Pattern[str] = re.compile(
        r"(?:0x)?(?:[0-9a-fA-F]{2}){10,}"
    )

    def _try_decode_base64(self, text: str) -> str | None:
        """Attempt to decode a base64 string, returning None on failure."""
        try:
            decoded = base64.b64decode(text, validate=True).decode("utf-8", errors="ignore")
            if decoded.isprintable() or any(c.isalpha() for c in decoded):
                return decoded
        except Exception:
            pass
        return None

    def _try_decode_hex(self, text: str) -> str | None:
        """Attempt to decode a hex string, returning None on failure."""
        try:
            clean = text.removeprefix("0x")
            decoded = bytes.fromhex(clean).decode("utf-8", errors="ignore")
            if decoded.isprintable() or any(c.isalpha() for c in decoded):
                return decoded
        except Exception:
            pass
        return None

    def _try_decode_url(self, text: str) -> str | None:
        """Attempt URL-decoding, returning None if nothing changed."""
        decoded = unquote(text)
        return decoded if decoded != text else None

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Decode and scan argument strings for injection payloads.

        Args:
            context: The tool-call context to inspect.

        Returns:
            DENY if an encoded injection payload is found, ALLOW otherwise.
        """
        for value in _extract_strings(context.arguments):
            decoded_candidates: list[str] = []

            url_decoded = self._try_decode_url(value)
            if url_decoded:
                decoded_candidates.append(url_decoded)

            for b64_match in self._BASE64_PATTERN.finditer(value):
                decoded = self._try_decode_base64(b64_match.group())
                if decoded:
                    decoded_candidates.append(decoded)

            for hex_match in self._HEX_PATTERN.finditer(value):
                decoded = self._try_decode_hex(hex_match.group())
                if decoded:
                    decoded_candidates.append(decoded)

            for candidate in decoded_candidates:
                for pattern in self._INJECTION_PATTERNS:
                    match = pattern.search(candidate)
                    if match:
                        return PolicyResponse(
                            action=PolicyAction.DENY,
                            rule_name=self.name,
                            reason=f"Encoded injection detected after decoding: {match.group()!r}",
                            details={
                                "matched_pattern": match.group(),
                                "decoded_snippet": candidate[:200],
                            },
                            owasp_id=self.owasp_id,
                        )
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason="No encoded injection detected",
        )


class RoleOverrideRule(BaseRule):
    """Block attempts to override system/assistant roles in arguments.

    Detects JSON-like role assignment patterns that try to hijack the
    conversation structure.
    """

    name: str = "role_override"
    description: str = "Block attempts to set system/assistant role in arguments"
    priority: int = 5
    enabled: bool = True
    owasp_id: str = "ASI01"

    _PATTERNS: list[re.Pattern[str]] = [
        re.compile(r'["\']role["\']\s*:\s*["\']system["\']', re.IGNORECASE),
        re.compile(r'["\']role["\']\s*:\s*["\']assistant["\']', re.IGNORECASE),
        re.compile(r"\brole\s*=\s*[\"']?system\b", re.IGNORECASE),
        re.compile(r"\brole\s*=\s*[\"']?assistant\b", re.IGNORECASE),
        re.compile(r"<<\s*SYS\s*>>", re.IGNORECASE),
        re.compile(r"###\s*System\s*:", re.IGNORECASE),
    ]

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Scan argument strings for role override patterns.

        Args:
            context: The tool-call context to inspect.

        Returns:
            DENY if a role override attempt is found, ALLOW otherwise.
        """
        for value in _extract_strings(context.arguments):
            for pattern in self._PATTERNS:
                match = pattern.search(value)
                if match:
                    return PolicyResponse(
                        action=PolicyAction.DENY,
                        rule_name=self.name,
                        reason=f"Role override attempt detected: {match.group()!r}",
                        details={"matched_pattern": match.group(), "value_snippet": value[:200]},
                        owasp_id=self.owasp_id,
                    )
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason="No role override detected",
        )


class DelimiterInjectionRule(BaseRule):
    """Block injection of LLM-specific delimiter tokens.

    Detects ``<|im_start|>``, ``[INST]``, ``<system>``, ``</s>``, and
    other framing markers that could manipulate model behaviour.
    """

    name: str = "delimiter_injection"
    description: str = "Block LLM delimiter tokens (<|im_start|>, [INST], <system>, </s>)"
    priority: int = 5
    enabled: bool = True
    owasp_id: str = "ASI01"

    _DELIMITERS: list[re.Pattern[str]] = [
        re.compile(r"<\|im_start\|>", re.IGNORECASE),
        re.compile(r"<\|im_end\|>", re.IGNORECASE),
        re.compile(r"<\|endoftext\|>", re.IGNORECASE),
        re.compile(r"\[INST\]", re.IGNORECASE),
        re.compile(r"\[/INST\]", re.IGNORECASE),
        re.compile(r"<system>", re.IGNORECASE),
        re.compile(r"</system>", re.IGNORECASE),
        re.compile(r"</s>"),
        re.compile(r"<\|system\|>", re.IGNORECASE),
        re.compile(r"<\|user\|>", re.IGNORECASE),
        re.compile(r"<\|assistant\|>", re.IGNORECASE),
    ]

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Scan argument strings for LLM delimiter tokens.

        Args:
            context: The tool-call context to inspect.

        Returns:
            DENY if delimiter tokens are found, ALLOW otherwise.
        """
        for value in _extract_strings(context.arguments):
            for pattern in self._DELIMITERS:
                match = pattern.search(value)
                if match:
                    return PolicyResponse(
                        action=PolicyAction.DENY,
                        rule_name=self.name,
                        reason=f"LLM delimiter injection detected: {match.group()!r}",
                        details={"delimiter": match.group(), "value_snippet": value[:200]},
                        owasp_id=self.owasp_id,
                    )
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason="No delimiter injection detected",
        )

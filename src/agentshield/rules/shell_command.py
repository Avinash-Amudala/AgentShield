"""Shell command safety rules (OWASP ASI02 — Tool Misuse)."""

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


class DestructiveShellRule(BaseRule):
    """Block catastrophically destructive shell commands.

    Detects ``rm -rf``, ``rm -r /``, ``mkfs``, ``dd if=``, and fork bombs.
    """

    name: str = "destructive_shell"
    description: str = "Block destructive shell commands (rm -rf, mkfs, dd, fork bomb)"
    priority: int = 1
    enabled: bool = True
    owasp_id: str = "ASI02"

    _PATTERNS: list[re.Pattern[str]] = [
        re.compile(
            r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|--recursive\s+--force|-[a-zA-Z]*f[a-zA-Z]*r)\b"
        ),
        re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*\s+/\s*$"),
        re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*\s+/\b"),
        re.compile(r"\bmkfs\b"),
        re.compile(r"\bdd\s+if="),
        re.compile(r":\(\)\{.*\|.*\};:"),  # fork bomb :(){ :|:& };:
        re.compile(r"\bfork\s*bomb\b", re.IGNORECASE),
    ]

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Block destructive shell commands.

        Args:
            context: The tool-call context to inspect.

        Returns:
            DENY if a destructive command is found, ALLOW otherwise.
        """
        for value in _extract_strings(context.arguments):
            for pattern in self._PATTERNS:
                match = pattern.search(value)
                if match:
                    return PolicyResponse(
                        action=PolicyAction.DENY,
                        rule_name=self.name,
                        reason=f"Destructive shell command detected: {match.group()!r}",
                        details={
                            "matched_pattern": match.group(),
                            "command_snippet": value[:200],
                        },
                        owasp_id=self.owasp_id,
                    )
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason="No destructive shell commands detected",
        )


class ReverseShellRule(BaseRule):
    """Block reverse shell payloads.

    Detects ``bash -i >& /dev/tcp``, ``nc -e``, and Python socket-based
    reverse shell patterns.
    """

    name: str = "reverse_shell"
    description: str = (
        "Block reverse shell payloads (bash /dev/tcp, nc -e, python socket)"
    )
    priority: int = 1
    enabled: bool = True
    owasp_id: str = "ASI02"

    _PATTERNS: list[re.Pattern[str]] = [
        re.compile(r"bash\s+-i\s+>&?\s*/dev/tcp"),
        re.compile(r"\bnc\s+(-[a-zA-Z]*e\b|-[a-zA-Z]*\s+-e\b)"),
        re.compile(r"\bncat\s+(-[a-zA-Z]*e\b|-[a-zA-Z]*\s+-e\b)"),
        re.compile(r"python[23]?\s+-c\s+.*import\s+socket", re.IGNORECASE),
        re.compile(r"\bsocat\b.*\bexec\b", re.IGNORECASE),
        re.compile(r"/dev/tcp/\d+\.\d+\.\d+\.\d+"),
        re.compile(r"\bmkfifo\b.*\bnc\b"),
    ]

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Block reverse shell payloads.

        Args:
            context: The tool-call context to inspect.

        Returns:
            DENY if a reverse shell pattern is found, ALLOW otherwise.
        """
        for value in _extract_strings(context.arguments):
            for pattern in self._PATTERNS:
                match = pattern.search(value)
                if match:
                    return PolicyResponse(
                        action=PolicyAction.DENY,
                        rule_name=self.name,
                        reason=f"Reverse shell detected: {match.group()!r}",
                        details={
                            "matched_pattern": match.group(),
                            "command_snippet": value[:200],
                        },
                        owasp_id=self.owasp_id,
                    )
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason="No reverse shell payloads detected",
        )


class PrivilegeEscalationRule(BaseRule):
    """Block privilege escalation attempts.

    Detects ``sudo``, ``su -``, ``chmod 777``, and ``chown root`` patterns.
    """

    name: str = "privilege_escalation"
    description: str = "Block privilege escalation (sudo, su -, chmod 777, chown root)"
    priority: int = 2
    enabled: bool = True
    owasp_id: str = "ASI02"

    _PATTERNS: list[re.Pattern[str]] = [
        re.compile(r"\bsudo\s+"),
        re.compile(r"\bsu\s+-"),
        re.compile(r"\bsu\s+root\b"),
        re.compile(r"\bchmod\s+777\b"),
        re.compile(r"\bchmod\s+[0-7]*7[0-7]*7\b"),
        re.compile(r"\bchmod\s+\+s\b"),
        re.compile(r"\bchown\s+root\b"),
        re.compile(r"\bsetuid\b"),
    ]

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Block privilege escalation commands.

        Args:
            context: The tool-call context to inspect.

        Returns:
            DENY if a privilege escalation attempt is detected, ALLOW otherwise.
        """
        for value in _extract_strings(context.arguments):
            for pattern in self._PATTERNS:
                match = pattern.search(value)
                if match:
                    return PolicyResponse(
                        action=PolicyAction.DENY,
                        rule_name=self.name,
                        reason=f"Privilege escalation detected: {match.group()!r}",
                        details={
                            "matched_pattern": match.group(),
                            "command_snippet": value[:200],
                        },
                        owasp_id=self.owasp_id,
                    )
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason="No privilege escalation detected",
        )


class DataExfiltrationShellRule(BaseRule):
    """Escalate potential data exfiltration via network tools.

    Detects ``curl`` to external IPs, ``wget``, and ``scp`` to unknown hosts.
    """

    name: str = "data_exfiltration_shell"
    description: str = (
        "Escalate data exfiltration via curl, wget, scp to external hosts"
    )
    priority: int = 3
    enabled: bool = True
    owasp_id: str = "ASI02"

    _PATTERNS: list[re.Pattern[str]] = [
        re.compile(r"\bcurl\s+.*https?://\d+\.\d+\.\d+\.\d+"),
        re.compile(r"\bcurl\s+.*-d\s+", re.IGNORECASE),
        re.compile(r"\bcurl\s+.*--data\b", re.IGNORECASE),
        re.compile(r"\bcurl\s+.*-X\s*POST\b", re.IGNORECASE),
        re.compile(r"\bwget\s+"),
        re.compile(r"\bscp\s+"),
        re.compile(r"\brsync\s+.*@"),
        re.compile(r"\bftp\s+"),
    ]

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Escalate potential data exfiltration commands.

        Args:
            context: The tool-call context to inspect.

        Returns:
            ESCALATE if exfiltration patterns are found, ALLOW otherwise.
        """
        for value in _extract_strings(context.arguments):
            for pattern in self._PATTERNS:
                match = pattern.search(value)
                if match:
                    return PolicyResponse(
                        action=PolicyAction.ESCALATE,
                        rule_name=self.name,
                        reason=f"Potential data exfiltration detected: {match.group()!r}",
                        details={
                            "matched_pattern": match.group(),
                            "command_snippet": value[:200],
                        },
                        owasp_id=self.owasp_id,
                    )
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason="No data exfiltration patterns detected",
        )


class DangerousEvalRule(BaseRule):
    """Block dangerous dynamic code execution.

    Detects ``eval()``, ``exec()``, and ``compile()`` calls with dynamic input
    that could execute arbitrary code.
    """

    name: str = "dangerous_eval"
    description: str = "Block eval(), exec(), compile() with dynamic input"
    priority: int = 2
    enabled: bool = True
    owasp_id: str = "ASI02"

    _PATTERNS: list[re.Pattern[str]] = [
        re.compile(r"\beval\s*\("),
        re.compile(r"\bexec\s*\("),
        re.compile(r"\bcompile\s*\("),
        re.compile(r"\b__import__\s*\("),
        re.compile(r"\bos\.system\s*\("),
        re.compile(r"\bos\.popen\s*\("),
        re.compile(r"\bsubprocess\.(call|run|Popen|check_output)\s*\("),
    ]

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Block dangerous dynamic code execution patterns.

        Args:
            context: The tool-call context to inspect.

        Returns:
            DENY if dangerous eval/exec usage is found, ALLOW otherwise.
        """
        for value in _extract_strings(context.arguments):
            for pattern in self._PATTERNS:
                match = pattern.search(value)
                if match:
                    return PolicyResponse(
                        action=PolicyAction.DENY,
                        rule_name=self.name,
                        reason=f"Dangerous code execution detected: {match.group()!r}",
                        details={
                            "matched_pattern": match.group(),
                            "command_snippet": value[:200],
                        },
                        owasp_id=self.owasp_id,
                    )
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason="No dangerous eval/exec detected",
        )

"""SQL injection detection rules (OWASP ASI02 — Tool Misuse)."""
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


class DestructiveSQLRule(BaseRule):
    """Block destructive SQL statements that can destroy data or schema.

    Detects DROP TABLE/DATABASE/INDEX/VIEW, TRUNCATE TABLE, DELETE without
    WHERE, and ALTER TABLE … DROP.
    """

    name: str = "destructive_sql"
    description: str = "Block destructive SQL statements (DROP, TRUNCATE, DELETE without WHERE)"
    priority: int = 10
    enabled: bool = True
    owasp_id: str = "ASI02"

    _PATTERNS: list[re.Pattern[str]] = [
        re.compile(r"\bDROP\s+(TABLE|DATABASE|INDEX|VIEW)\b", re.IGNORECASE),
        re.compile(r"\bTRUNCATE\s+TABLE\b", re.IGNORECASE),
        re.compile(r"\bDELETE\s+FROM\s+\S+\s*(?:;|\s*$)", re.IGNORECASE),
        re.compile(r"\bALTER\s+TABLE\s+\S+\s+DROP\b", re.IGNORECASE),
    ]

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Scan argument strings for destructive SQL patterns.

        Args:
            context: The tool-call context to inspect.

        Returns:
            DENY if a destructive SQL pattern is found, ALLOW otherwise.
        """
        for value in _extract_strings(context.arguments):
            for pattern in self._PATTERNS:
                match = pattern.search(value)
                if match:
                    return PolicyResponse(
                        action=PolicyAction.DENY,
                        rule_name=self.name,
                        reason=f"Destructive SQL detected: {match.group()}",
                        details={"matched_pattern": match.group(), "value_snippet": value[:200]},
                        owasp_id=self.owasp_id,
                    )
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason="No destructive SQL detected",
        )


class SQLUnionInjectionRule(BaseRule):
    """Block UNION-based SQL injection attempts.

    Detects ``UNION SELECT`` and ``UNION ALL SELECT`` patterns commonly
    used to exfiltrate data from adjacent query columns.
    """

    name: str = "sql_union_injection"
    description: str = "Block UNION SELECT / UNION ALL SELECT injection"
    priority: int = 10
    enabled: bool = True
    owasp_id: str = "ASI02"

    _PATTERN: re.Pattern[str] = re.compile(
        r"\bUNION\s+(ALL\s+)?SELECT\b", re.IGNORECASE
    )

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Scan argument strings for UNION injection patterns.

        Args:
            context: The tool-call context to inspect.

        Returns:
            DENY if a UNION injection pattern is found, ALLOW otherwise.
        """
        for value in _extract_strings(context.arguments):
            match = self._PATTERN.search(value)
            if match:
                return PolicyResponse(
                    action=PolicyAction.DENY,
                    rule_name=self.name,
                    reason=f"UNION injection detected: {match.group()}",
                    details={"matched_pattern": match.group(), "value_snippet": value[:200]},
                    owasp_id=self.owasp_id,
                )
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason="No UNION injection detected",
        )


class SQLCommentInjectionRule(BaseRule):
    """Block SQL comment-based injection attempts.

    Detects ``--``, ``/* … */``, and ``#`` comment markers that attackers
    use to neutralise trailing query clauses.
    """

    name: str = "sql_comment_injection"
    description: str = "Block SQL comment markers (--, /* */, #) used in injection"
    priority: int = 11
    enabled: bool = True
    owasp_id: str = "ASI02"

    _PATTERNS: list[re.Pattern[str]] = [
        re.compile(r"--\s"),
        re.compile(r"/\*.*?\*/", re.DOTALL),
        re.compile(r"#\s"),
    ]

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Scan argument strings for SQL comment injection markers.

        Args:
            context: The tool-call context to inspect.

        Returns:
            DENY if a comment injection marker is found, ALLOW otherwise.
        """
        for value in _extract_strings(context.arguments):
            for pattern in self._PATTERNS:
                match = pattern.search(value)
                if match:
                    return PolicyResponse(
                        action=PolicyAction.DENY,
                        rule_name=self.name,
                        reason=f"SQL comment injection detected: {match.group()!r}",
                        details={"matched_pattern": match.group(), "value_snippet": value[:200]},
                        owasp_id=self.owasp_id,
                    )
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason="No SQL comment injection detected",
        )


class SQLBatchExecutionRule(BaseRule):
    """Escalate SQL batches containing multiple statements.

    Multiple statements separated by ``;`` can piggyback malicious queries
    onto legitimate ones.
    """

    name: str = "sql_batch_execution"
    description: str = "Escalate multi-statement SQL batches (semicolon-separated)"
    priority: int = 12
    enabled: bool = True
    owasp_id: str = "ASI02"

    _PATTERN: re.Pattern[str] = re.compile(
        r";\s*\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|GRANT|REVOKE)\b",
        re.IGNORECASE,
    )

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Scan argument strings for multi-statement SQL batches.

        Args:
            context: The tool-call context to inspect.

        Returns:
            ESCALATE if multiple SQL statements are found, ALLOW otherwise.
        """
        for value in _extract_strings(context.arguments):
            match = self._PATTERN.search(value)
            if match:
                return PolicyResponse(
                    action=PolicyAction.ESCALATE,
                    rule_name=self.name,
                    reason=f"SQL batch execution detected: multiple statements separated by ';'",
                    details={"matched_pattern": match.group(), "value_snippet": value[:200]},
                    owasp_id=self.owasp_id,
                )
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason="No SQL batch execution detected",
        )


class SQLAdminCommandsRule(BaseRule):
    """Block SQL administrative commands that alter permissions or users.

    Detects GRANT, REVOKE, CREATE USER, and ALTER USER statements.
    """

    name: str = "sql_admin_commands"
    description: str = "Block SQL admin commands (GRANT, REVOKE, CREATE/ALTER USER)"
    priority: int = 10
    enabled: bool = True
    owasp_id: str = "ASI02"

    _PATTERNS: list[re.Pattern[str]] = [
        re.compile(r"\bGRANT\s+", re.IGNORECASE),
        re.compile(r"\bREVOKE\s+", re.IGNORECASE),
        re.compile(r"\bCREATE\s+USER\b", re.IGNORECASE),
        re.compile(r"\bALTER\s+USER\b", re.IGNORECASE),
    ]

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Scan argument strings for SQL administrative commands.

        Args:
            context: The tool-call context to inspect.

        Returns:
            DENY if an administrative SQL command is found, ALLOW otherwise.
        """
        for value in _extract_strings(context.arguments):
            for pattern in self._PATTERNS:
                match = pattern.search(value)
                if match:
                    return PolicyResponse(
                        action=PolicyAction.DENY,
                        rule_name=self.name,
                        reason=f"SQL admin command detected: {match.group().strip()}",
                        details={"matched_pattern": match.group().strip(), "value_snippet": value[:200]},
                        owasp_id=self.owasp_id,
                    )
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason="No SQL admin commands detected",
        )

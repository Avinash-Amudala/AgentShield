"""Human-in-the-loop approval rules (OWASP ASI09 — Improper Output Handling)."""
from __future__ import annotations

import fnmatch
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


class RequireApprovalPatternRule(BaseRule):
    """Escalate tool calls whose name matches configurable patterns.

    Use glob patterns like ``deploy_*``, ``delete_prod_*`` to flag
    high-risk operations for human review.
    """

    name: str = "require_approval_pattern"
    description: str = "Escalate tool calls matching name patterns (e.g. deploy_*, delete_prod_*)"
    priority: int = 40
    enabled: bool = True
    owasp_id: str = "ASI09"

    patterns: list[str] = [
        "deploy_*",
        "delete_prod_*",
        "drop_*",
        "destroy_*",
    ]

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Escalate if the tool name matches any configured pattern.

        Args:
            context: The tool-call context to inspect.

        Returns:
            ESCALATE if the tool name matches a pattern, ALLOW otherwise.
        """
        for pattern in self.patterns:
            if fnmatch.fnmatch(context.tool_name, pattern):
                return PolicyResponse(
                    action=PolicyAction.ESCALATE,
                    rule_name=self.name,
                    reason=f"Tool {context.tool_name!r} matches approval pattern {pattern!r}",
                    details={
                        "tool_name": context.tool_name,
                        "matched_pattern": pattern,
                    },
                    owasp_id=self.owasp_id,
                )
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason=f"Tool {context.tool_name!r} does not match any approval pattern",
        )


class RequireApprovalFinancialRule(BaseRule):
    """Escalate tool calls containing monetary amounts above a threshold.

    Scans argument values for numeric amounts and currency indicators.
    """

    name: str = "require_approval_financial"
    description: str = "Escalate calls with monetary arguments above threshold"
    priority: int = 40
    enabled: bool = True
    owasp_id: str = "ASI09"

    threshold_usd: float = 100.0
    monetary_arg_keys: list[str] = [
        "amount", "price", "cost", "total", "value", "payment",
        "charge", "fee", "budget",
    ]

    _CURRENCY_PATTERN: re.Pattern[str] = re.compile(
        r"(?:\$|USD\s*|€|EUR\s*|£|GBP\s*)\s*([0-9][0-9,]*(?:\.[0-9]{1,2})?)"
    )
    _NUMBER_PATTERN: re.Pattern[str] = re.compile(
        r"\b([0-9][0-9,]*(?:\.[0-9]{1,2})?)\b"
    )

    def _extract_amount(self, value: Any) -> float | None:
        """Attempt to extract a numeric amount from a value."""
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            currency_match = self._CURRENCY_PATTERN.search(value)
            if currency_match:
                return float(currency_match.group(1).replace(",", ""))
            num_match = self._NUMBER_PATTERN.search(value)
            if num_match:
                return float(num_match.group(1).replace(",", ""))
        return None

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Escalate if monetary arguments exceed the threshold.

        Args:
            context: The tool-call context to inspect.

        Returns:
            ESCALATE if a monetary amount exceeds the threshold, ALLOW
            otherwise.
        """
        for key in self.monetary_arg_keys:
            if key in context.arguments:
                amount = self._extract_amount(context.arguments[key])
                if amount is not None and amount > self.threshold_usd:
                    return PolicyResponse(
                        action=PolicyAction.ESCALATE,
                        rule_name=self.name,
                        reason=(
                            f"Financial amount ${amount:,.2f} in argument "
                            f"{key!r} exceeds threshold ${self.threshold_usd:,.2f}"
                        ),
                        details={
                            "argument_key": key,
                            "amount": amount,
                            "threshold": self.threshold_usd,
                        },
                        owasp_id=self.owasp_id,
                    )
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason="No financial amounts exceeding threshold",
        )


class RequireApprovalDataExportRule(BaseRule):
    """Escalate data export tools when row counts exceed a threshold.

    Scans for tools whose name suggests data export and checks for row
    count arguments.
    """

    name: str = "require_approval_data_export"
    description: str = "Escalate data export tools with row count above threshold"
    priority: int = 40
    enabled: bool = True
    owasp_id: str = "ASI09"

    export_tool_patterns: list[str] = [
        "export_*",
        "download_*",
        "dump_*",
        "extract_*",
        "bulk_read_*",
    ]
    row_count_keys: list[str] = [
        "limit", "row_count", "rows", "count", "batch_size", "max_rows",
    ]
    max_rows: int = 1000

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Escalate data exports exceeding the row threshold.

        Args:
            context: The tool-call context to inspect.

        Returns:
            ESCALATE if a data export exceeds the row threshold, ALLOW
            otherwise.
        """
        is_export_tool = any(
            fnmatch.fnmatch(context.tool_name, pat)
            for pat in self.export_tool_patterns
        )
        if not is_export_tool:
            return PolicyResponse(
                action=PolicyAction.ALLOW,
                rule_name=self.name,
                reason=f"Tool {context.tool_name!r} is not an export tool",
            )

        for key in self.row_count_keys:
            value = context.arguments.get(key)
            if value is None:
                continue
            try:
                row_count = int(value)
            except (TypeError, ValueError):
                continue
            if row_count > self.max_rows:
                return PolicyResponse(
                    action=PolicyAction.ESCALATE,
                    rule_name=self.name,
                    reason=(
                        f"Data export {context.tool_name!r} requests "
                        f"{row_count} rows (threshold: {self.max_rows})"
                    ),
                    details={
                        "tool_name": context.tool_name,
                        "row_count_key": key,
                        "row_count": row_count,
                        "max_rows": self.max_rows,
                    },
                    owasp_id=self.owasp_id,
                )

        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason=f"Data export {context.tool_name!r} within row threshold",
        )

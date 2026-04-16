"""Scope enforcement rules (OWASP ASI03 / ASI06)."""
from __future__ import annotations

from typing import Any

from agentshield.core.context import ToolCallContext
from agentshield.core.result import PolicyAction, PolicyResponse
from agentshield.rules.base import BaseRule


class ToolAllowlistRule(BaseRule):
    """Deny tool calls that are not in the agent's declared scope.

    When ``allowed_tools`` is non-empty, only those tools are permitted.
    """

    name: str = "tool_allowlist"
    description: str = "Block tools not in the agent's declared allowlist"
    priority: int = 20
    enabled: bool = True
    owasp_id: str = "ASI03"

    allowed_tools: list[str] = []

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Check whether the tool is on the allowlist.

        Args:
            context: The tool-call context to inspect.

        Returns:
            DENY if the tool is not on the allowlist, ALLOW otherwise.
        """
        if not self.allowed_tools:
            return PolicyResponse(
                action=PolicyAction.ALLOW,
                rule_name=self.name,
                reason="No tool allowlist configured — all tools permitted",
            )

        if context.tool_name in self.allowed_tools:
            return PolicyResponse(
                action=PolicyAction.ALLOW,
                rule_name=self.name,
                reason=f"Tool {context.tool_name!r} is on the allowlist",
            )

        return PolicyResponse(
            action=PolicyAction.DENY,
            rule_name=self.name,
            reason=f"Tool {context.tool_name!r} is not on the allowlist",
            details={
                "tool_name": context.tool_name,
                "allowed_tools": self.allowed_tools,
            },
            owasp_id=self.owasp_id,
        )


class ArgumentSchemaRule(BaseRule):
    """Escalate tool calls whose arguments don't match the expected schema.

    ``expected_schemas`` maps tool names to dicts of
    ``{arg_name: type_name}`` where *type_name* is one of
    ``"str"``, ``"int"``, ``"float"``, ``"bool"``, ``"list"``, ``"dict"``.
    """

    name: str = "argument_schema"
    description: str = "Escalate arguments not matching expected tool schema"
    priority: int = 21
    enabled: bool = True
    owasp_id: str = "ASI03"

    expected_schemas: dict[str, dict[str, str]] = {}

    _TYPE_MAP: dict[str, type] = {
        "str": str,
        "int": int,
        "float": float,
        "bool": bool,
        "list": list,
        "dict": dict,
    }

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Validate argument names and types against the expected schema.

        Args:
            context: The tool-call context to inspect.

        Returns:
            ESCALATE if schema violations are found, ALLOW otherwise.
        """
        schema = self.expected_schemas.get(context.tool_name)
        if schema is None:
            return PolicyResponse(
                action=PolicyAction.ALLOW,
                rule_name=self.name,
                reason=f"No schema defined for tool {context.tool_name!r}",
            )

        violations: list[str] = []

        for arg_name in context.arguments:
            if arg_name not in schema:
                violations.append(f"unexpected argument: {arg_name!r}")

        for arg_name, expected_type_name in schema.items():
            if arg_name not in context.arguments:
                continue
            expected_type = self._TYPE_MAP.get(expected_type_name)
            if expected_type is None:
                continue
            value = context.arguments[arg_name]
            if not isinstance(value, expected_type):
                violations.append(
                    f"argument {arg_name!r}: expected {expected_type_name}, "
                    f"got {type(value).__name__}"
                )

        if violations:
            return PolicyResponse(
                action=PolicyAction.ESCALATE,
                rule_name=self.name,
                reason=f"Schema violations for tool {context.tool_name!r}: {'; '.join(violations)}",
                details={
                    "tool_name": context.tool_name,
                    "violations": violations,
                },
                owasp_id=self.owasp_id,
            )

        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason=f"Arguments match schema for tool {context.tool_name!r}",
        )


class CrossAgentScopeRule(BaseRule):
    """Deny agent A from calling tools scoped to agent B.

    ``agent_scopes`` maps ``agent_id`` to the list of tools that agent is
    allowed to invoke.  If a tool is declared for agent B but not agent A,
    agent A is blocked.
    """

    name: str = "cross_agent_scope"
    description: str = "Block agent from calling tools scoped to another agent"
    priority: int = 20
    enabled: bool = True
    owasp_id: str = "ASI06"

    agent_scopes: dict[str, list[str]] = {}

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Enforce cross-agent scope boundaries.

        Args:
            context: The tool-call context to inspect.

        Returns:
            DENY if the agent is invoking a tool scoped to another agent,
            ALLOW otherwise.
        """
        if not self.agent_scopes:
            return PolicyResponse(
                action=PolicyAction.ALLOW,
                rule_name=self.name,
                reason="No agent scopes configured",
            )

        agent_tools = self.agent_scopes.get(context.agent_id)
        if agent_tools is None:
            return PolicyResponse(
                action=PolicyAction.ALLOW,
                rule_name=self.name,
                reason=f"No scope defined for agent {context.agent_id!r}",
            )

        if context.tool_name in agent_tools:
            return PolicyResponse(
                action=PolicyAction.ALLOW,
                rule_name=self.name,
                reason=f"Tool {context.tool_name!r} is in scope for agent {context.agent_id!r}",
            )

        owning_agents = [
            aid for aid, tools in self.agent_scopes.items()
            if context.tool_name in tools
        ]
        return PolicyResponse(
            action=PolicyAction.DENY,
            rule_name=self.name,
            reason=(
                f"Agent {context.agent_id!r} attempted to call tool "
                f"{context.tool_name!r} scoped to agent(s) {owning_agents}"
            ),
            details={
                "agent_id": context.agent_id,
                "tool_name": context.tool_name,
                "owning_agents": owning_agents,
            },
            owasp_id=self.owasp_id,
        )

"""AgentShield built-in rules — safe defaults for agentic AI systems."""

from __future__ import annotations

from agentshield.rules.base import BaseRule

from agentshield.rules.sql_injection import (
    DestructiveSQLRule,
    SQLAdminCommandsRule,
    SQLBatchExecutionRule,
    SQLCommentInjectionRule,
    SQLUnionInjectionRule,
)
from agentshield.rules.filesystem import (
    ExecutableWriteRule,
    PathTraversalRule,
    SensitiveFileReadRule,
    SymlinkAttackRule,
    WriteOutsideSandboxRule,
)
from agentshield.rules.shell_command import (
    DangerousEvalRule,
    DataExfiltrationShellRule,
    DestructiveShellRule,
    PrivilegeEscalationRule,
    ReverseShellRule,
)
from agentshield.rules.network import (
    DNSRebindingRule,
    DomainAllowlistRule,
    DomainDenylistRule,
    InternalNetworkAccessRule,
)
from agentshield.rules.credential_leak import (
    APIKeyLeakRule,
    EnvVarLeakRule,
    PasswordLeakRule,
    PIILeakRule,
    TokenLeakRule,
)
from agentshield.rules.prompt_injection import (
    DelimiterInjectionRule,
    DirectInjectionRule,
    EncodedInjectionRule,
    RoleOverrideRule,
)
from agentshield.rules.rate_limiter import (
    BurstDetectionRule,
    PerToolRateLimitRule,
    SessionRateLimitRule,
)
from agentshield.rules.scope import (
    ArgumentSchemaRule,
    CrossAgentScopeRule,
    ToolAllowlistRule,
)
from agentshield.rules.cost_guard import (
    CostAlertRule,
    SessionCostCeilingRule,
)
from agentshield.rules.approval import (
    RequireApprovalDataExportRule,
    RequireApprovalFinancialRule,
    RequireApprovalPatternRule,
)
from agentshield.rules.custom import CustomPatternRule

ALL_RULE_CLASSES: list[type[BaseRule]] = [
    # Shell / system (priority 1-2)
    DestructiveShellRule,
    ReverseShellRule,
    PrivilegeEscalationRule,
    DangerousEvalRule,
    DataExfiltrationShellRule,
    # Filesystem (priority 5-7)
    PathTraversalRule,
    WriteOutsideSandboxRule,
    SymlinkAttackRule,
    SensitiveFileReadRule,
    ExecutableWriteRule,
    # Prompt injection (priority 5)
    DirectInjectionRule,
    EncodedInjectionRule,
    RoleOverrideRule,
    DelimiterInjectionRule,
    # SQL injection (priority 10-12)
    DestructiveSQLRule,
    SQLUnionInjectionRule,
    SQLCommentInjectionRule,
    SQLAdminCommandsRule,
    SQLBatchExecutionRule,
    # Credential / data leak (priority 10-11)
    APIKeyLeakRule,
    TokenLeakRule,
    PasswordLeakRule,
    PIILeakRule,
    EnvVarLeakRule,
    # Network (priority 20)
    InternalNetworkAccessRule,
    DomainDenylistRule,
    DomainAllowlistRule,
    DNSRebindingRule,
    # Scope (priority 20-21)
    ToolAllowlistRule,
    CrossAgentScopeRule,
    ArgumentSchemaRule,
    # Rate limiting (priority 30)
    PerToolRateLimitRule,
    SessionRateLimitRule,
    BurstDetectionRule,
    # Cost (priority 35-36)
    SessionCostCeilingRule,
    CostAlertRule,
    # Approval (priority 40)
    RequireApprovalPatternRule,
    RequireApprovalFinancialRule,
    RequireApprovalDataExportRule,
]


def get_default_rules() -> list[BaseRule]:
    """Instantiate and return all built-in rules with default settings.

    Returns:
        A list of :class:`BaseRule` instances sorted by priority (ascending).
    """
    rules = [cls() for cls in ALL_RULE_CLASSES]
    rules.sort(key=lambda r: r.priority)
    return rules


DEFAULT_RULES: list[BaseRule] = get_default_rules()

__all__ = [
    "ALL_RULE_CLASSES",
    "DEFAULT_RULES",
    "get_default_rules",
    "BaseRule",
    # SQL injection
    "DestructiveSQLRule",
    "SQLUnionInjectionRule",
    "SQLCommentInjectionRule",
    "SQLBatchExecutionRule",
    "SQLAdminCommandsRule",
    # Filesystem
    "PathTraversalRule",
    "SensitiveFileReadRule",
    "WriteOutsideSandboxRule",
    "SymlinkAttackRule",
    "ExecutableWriteRule",
    # Shell command
    "DestructiveShellRule",
    "ReverseShellRule",
    "PrivilegeEscalationRule",
    "DataExfiltrationShellRule",
    "DangerousEvalRule",
    # Network
    "InternalNetworkAccessRule",
    "DomainDenylistRule",
    "DomainAllowlistRule",
    "DNSRebindingRule",
    # Credential leak
    "APIKeyLeakRule",
    "TokenLeakRule",
    "PIILeakRule",
    "PasswordLeakRule",
    "EnvVarLeakRule",
    # Prompt injection
    "DirectInjectionRule",
    "EncodedInjectionRule",
    "RoleOverrideRule",
    "DelimiterInjectionRule",
    # Rate limiter
    "PerToolRateLimitRule",
    "SessionRateLimitRule",
    "BurstDetectionRule",
    # Scope
    "ToolAllowlistRule",
    "ArgumentSchemaRule",
    "CrossAgentScopeRule",
    # Cost guard
    "SessionCostCeilingRule",
    "CostAlertRule",
    # Approval
    "RequireApprovalPatternRule",
    "RequireApprovalFinancialRule",
    "RequireApprovalDataExportRule",
    # Custom
    "CustomPatternRule",
]

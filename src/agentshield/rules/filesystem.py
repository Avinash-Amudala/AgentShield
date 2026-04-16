"""Filesystem safety rules (OWASP ASI02 — Tool Misuse)."""

from __future__ import annotations

import os
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


def _resolve_sandbox(sandbox_dir: str) -> str:
    """Return the resolved absolute path for the sandbox directory."""
    return os.path.realpath(os.path.abspath(sandbox_dir))


class PathTraversalRule(BaseRule):
    """Block path traversal attacks via ``../`` sequences or absolute escapes.

    Prevents agents from navigating outside a configured sandbox directory.
    """

    name: str = "path_traversal"
    description: str = "Block ../ path traversal and absolute paths outside sandbox"
    priority: int = 5
    enabled: bool = True
    owasp_id: str = "ASI02"

    sandbox_dir: str = "."

    _TRAVERSAL_PATTERN: re.Pattern[str] = re.compile(r"(?:^|[\\/])\.\.(?:[\\/]|$)")

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Check argument strings for path traversal sequences.

        Args:
            context: The tool-call context to inspect.

        Returns:
            DENY if path traversal is detected, ALLOW otherwise.
        """
        sandbox = _resolve_sandbox(self.sandbox_dir)
        for value in _extract_strings(context.arguments):
            if self._TRAVERSAL_PATTERN.search(value):
                return PolicyResponse(
                    action=PolicyAction.DENY,
                    rule_name=self.name,
                    reason=f"Path traversal detected: '../' in {value!r}",
                    details={"path": value, "sandbox_dir": sandbox},
                    owasp_id=self.owasp_id,
                )
            if os.path.isabs(value):
                resolved = os.path.realpath(value)
                if not resolved.startswith(sandbox):
                    return PolicyResponse(
                        action=PolicyAction.DENY,
                        rule_name=self.name,
                        reason=f"Absolute path outside sandbox: {value!r}",
                        details={
                            "path": value,
                            "resolved": resolved,
                            "sandbox_dir": sandbox,
                        },
                        owasp_id=self.owasp_id,
                    )
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason="No path traversal detected",
        )


class SensitiveFileReadRule(BaseRule):
    """Block reads of sensitive system and credential files.

    Detects access to ``/etc/passwd``, ``/etc/shadow``, ``.env``,
    ``*.pem``, ``*.key``, and similar files.
    """

    name: str = "sensitive_file_read"
    description: str = (
        "Block reads of sensitive files (.env, /etc/passwd, *.pem, *.key)"
    )
    priority: int = 6
    enabled: bool = True
    owasp_id: str = "ASI02"

    _SENSITIVE_PATHS: list[str] = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/master.passwd",
    ]

    _SENSITIVE_PATTERNS: list[re.Pattern[str]] = [
        re.compile(r"(?:^|[\\/])\.env(?:\.[a-zA-Z0-9]+)?$"),
        re.compile(r"\.pem$", re.IGNORECASE),
        re.compile(r"\.key$", re.IGNORECASE),
        re.compile(r"(?:^|[\\/])id_rsa$"),
        re.compile(r"(?:^|[\\/])id_ed25519$"),
    ]

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Check argument strings against known sensitive file patterns.

        Args:
            context: The tool-call context to inspect.

        Returns:
            DENY if a sensitive file path is found, ALLOW otherwise.
        """
        for value in _extract_strings(context.arguments):
            normalised = value.replace("\\", "/").lower()
            for sensitive in self._SENSITIVE_PATHS:
                if normalised.endswith(sensitive) or normalised == sensitive:
                    return PolicyResponse(
                        action=PolicyAction.DENY,
                        rule_name=self.name,
                        reason=f"Sensitive file access blocked: {value!r}",
                        details={"path": value, "matched_sensitive": sensitive},
                        owasp_id=self.owasp_id,
                    )
            for pattern in self._SENSITIVE_PATTERNS:
                if pattern.search(value):
                    return PolicyResponse(
                        action=PolicyAction.DENY,
                        rule_name=self.name,
                        reason=f"Sensitive file access blocked: {value!r}",
                        details={"path": value, "matched_pattern": pattern.pattern},
                        owasp_id=self.owasp_id,
                    )
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason="No sensitive file access detected",
        )


class WriteOutsideSandboxRule(BaseRule):
    """Block write operations targeting paths outside the sandbox directory."""

    name: str = "write_outside_sandbox"
    description: str = "Block file writes outside the configured sandbox directory"
    priority: int = 5
    enabled: bool = True
    owasp_id: str = "ASI02"

    sandbox_dir: str = "."

    _WRITE_TOOLS: set[str] = {
        "write_file",
        "create_file",
        "save_file",
        "write",
        "append_file",
        "move_file",
        "rename_file",
        "copy_file",
    }

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Block writes that target paths outside the sandbox.

        Args:
            context: The tool-call context to inspect.

        Returns:
            DENY if a write targets a path outside the sandbox, ALLOW otherwise.
        """
        if context.tool_name not in self._WRITE_TOOLS:
            return PolicyResponse(
                action=PolicyAction.ALLOW,
                rule_name=self.name,
                reason="Tool is not a write operation",
            )

        sandbox = _resolve_sandbox(self.sandbox_dir)
        for value in _extract_strings(context.arguments):
            candidate = os.path.realpath(os.path.abspath(value))
            if not candidate.startswith(sandbox):
                return PolicyResponse(
                    action=PolicyAction.DENY,
                    rule_name=self.name,
                    reason=f"Write outside sandbox blocked: {value!r}",
                    details={
                        "path": value,
                        "resolved": candidate,
                        "sandbox_dir": sandbox,
                    },
                    owasp_id=self.owasp_id,
                )
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason="Write target is within sandbox",
        )


class SymlinkAttackRule(BaseRule):
    """Block symlink creation targeting destinations outside the sandbox."""

    name: str = "symlink_attack"
    description: str = "Block symbolic link creation pointing outside sandbox"
    priority: int = 5
    enabled: bool = True
    owasp_id: str = "ASI02"

    sandbox_dir: str = "."

    _SYMLINK_TOOLS: set[str] = {"create_symlink", "symlink", "ln"}

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Block symlink creation that escapes the sandbox.

        Args:
            context: The tool-call context to inspect.

        Returns:
            DENY if a symlink targets outside the sandbox, ALLOW otherwise.
        """
        if context.tool_name not in self._SYMLINK_TOOLS:
            return PolicyResponse(
                action=PolicyAction.ALLOW,
                rule_name=self.name,
                reason="Tool is not a symlink operation",
            )

        sandbox = _resolve_sandbox(self.sandbox_dir)
        for value in _extract_strings(context.arguments):
            resolved = os.path.realpath(os.path.abspath(value))
            if not resolved.startswith(sandbox):
                return PolicyResponse(
                    action=PolicyAction.DENY,
                    rule_name=self.name,
                    reason=f"Symlink target outside sandbox blocked: {value!r}",
                    details={
                        "path": value,
                        "resolved": resolved,
                        "sandbox_dir": sandbox,
                    },
                    owasp_id=self.owasp_id,
                )
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason="Symlink targets are within sandbox",
        )


class ExecutableWriteRule(BaseRule):
    """Escalate writes that produce executable files.

    Detects writes targeting ``.sh``, ``.bat``, ``.exe``, and ``.ps1`` files.
    """

    name: str = "executable_write"
    description: str = "Escalate writing executable files (.sh, .bat, .exe, .ps1)"
    priority: int = 7
    enabled: bool = True
    owasp_id: str = "ASI02"

    _EXECUTABLE_EXTENSIONS: set[str] = {".sh", ".bat", ".exe", ".ps1", ".cmd", ".com"}

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Escalate if any argument string targets an executable file extension.

        Args:
            context: The tool-call context to inspect.

        Returns:
            ESCALATE if an executable write is detected, ALLOW otherwise.
        """
        for value in _extract_strings(context.arguments):
            _, ext = os.path.splitext(value)
            if ext.lower() in self._EXECUTABLE_EXTENSIONS:
                return PolicyResponse(
                    action=PolicyAction.ESCALATE,
                    rule_name=self.name,
                    reason=f"Executable file write detected: {value!r}",
                    details={"path": value, "extension": ext.lower()},
                    owasp_id=self.owasp_id,
                )
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason="No executable file writes detected",
        )

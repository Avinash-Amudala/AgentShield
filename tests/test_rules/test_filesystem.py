from __future__ import annotations

import os

import pytest

from agentshield.core.context import ToolCallContext
from agentshield.core.result import PolicyAction
from agentshield.rules.filesystem import (
    ExecutableWriteRule,
    PathTraversalRule,
    SensitiveFileReadRule,
    SymlinkAttackRule,
    WriteOutsideSandboxRule,
)

# ── PathTraversalRule ───────────────────────────────────────────────


class TestPathTraversalRule:
    @pytest.fixture
    def rule(self, tmp_path):
        r = PathTraversalRule()
        r.sandbox_dir = str(tmp_path)
        return r

    async def test_allow_relative_path_inside_sandbox(self, rule):
        ctx = ToolCallContext(
            tool_name="read_file",
            arguments={"path": "data/report.csv"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_allow_absolute_path_inside_sandbox(self, rule, tmp_path):
        target = str(tmp_path / "notes.txt")
        ctx = ToolCallContext(
            tool_name="read_file",
            arguments={"path": target},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_deny_dotdot_traversal(self, rule):
        ctx = ToolCallContext(
            tool_name="read_file",
            arguments={"path": "../../etc/passwd"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY
        assert "../" in result.reason

    async def test_deny_absolute_path_outside_sandbox(self, rule):
        ctx = ToolCallContext(
            tool_name="read_file",
            arguments={
                "path": (
                    "C:\\Windows\\System32\\config\\SAM"
                    if os.name == "nt"
                    else "/etc/shadow"
                )
            },
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_edge_case_backslash_traversal(self, rule):
        ctx = ToolCallContext(
            tool_name="read_file",
            arguments={"path": "..\\..\\secret.txt"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY


# ── SensitiveFileReadRule ───────────────────────────────────────────


class TestSensitiveFileReadRule:
    @pytest.fixture
    def rule(self):
        return SensitiveFileReadRule()

    async def test_allow_normal_file(self, rule):
        ctx = ToolCallContext(
            tool_name="read_file",
            arguments={"path": "app/main.py"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_allow_readme(self, rule):
        ctx = ToolCallContext(
            tool_name="read_file",
            arguments={"path": "/home/user/README.md"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_deny_etc_passwd(self, rule):
        ctx = ToolCallContext(
            tool_name="read_file",
            arguments={"path": "/etc/passwd"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_deny_dot_env(self, rule):
        ctx = ToolCallContext(
            tool_name="read_file",
            arguments={"path": "/app/.env"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_deny_pem_file(self, rule):
        ctx = ToolCallContext(
            tool_name="read_file",
            arguments={"path": "/certs/server.pem"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_deny_key_file(self, rule):
        ctx = ToolCallContext(
            tool_name="read_file",
            arguments={"path": "~/.ssh/id_rsa"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_edge_case_env_with_suffix(self, rule):
        ctx = ToolCallContext(
            tool_name="read_file",
            arguments={"path": ".env.production"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY


# ── WriteOutsideSandboxRule ─────────────────────────────────────────


class TestWriteOutsideSandboxRule:
    @pytest.fixture
    def rule(self, tmp_path):
        r = WriteOutsideSandboxRule()
        r.sandbox_dir = str(tmp_path)
        return r

    async def test_allow_non_write_tool(self, rule):
        ctx = ToolCallContext(
            tool_name="read_file",
            arguments={"path": "/etc/passwd"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_allow_write_inside_sandbox(self, rule, tmp_path):
        target = str(tmp_path / "output.txt")
        ctx = ToolCallContext(
            tool_name="write_file",
            arguments={"path": target},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_deny_write_outside_sandbox(self, rule):
        ctx = ToolCallContext(
            tool_name="write_file",
            arguments={
                "path": "C:\\Windows\\evil.txt" if os.name == "nt" else "/tmp/evil.txt"
            },
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_deny_create_file_outside(self, rule):
        ctx = ToolCallContext(
            tool_name="create_file",
            arguments={
                "path": (
                    "C:\\Users\\Public\\hack.txt"
                    if os.name == "nt"
                    else "/var/hack.txt"
                )
            },
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_edge_case_append_file_outside(self, rule):
        ctx = ToolCallContext(
            tool_name="append_file",
            arguments={
                "path": (
                    "C:\\Windows\\System32\\evil.dll"
                    if os.name == "nt"
                    else "/usr/bin/evil"
                )
            },
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY


# ── SymlinkAttackRule ───────────────────────────────────────────────


class TestSymlinkAttackRule:
    @pytest.fixture
    def rule(self, tmp_path):
        r = SymlinkAttackRule()
        r.sandbox_dir = str(tmp_path)
        return r

    async def test_allow_non_symlink_tool(self, rule):
        ctx = ToolCallContext(
            tool_name="read_file",
            arguments={"target": "/etc/passwd"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_allow_symlink_inside_sandbox(self, rule, tmp_path):
        target = str(tmp_path / "link_target")
        ctx = ToolCallContext(
            tool_name="create_symlink",
            arguments={"target": target},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_deny_symlink_outside_sandbox(self, rule):
        ctx = ToolCallContext(
            tool_name="create_symlink",
            arguments={
                "target": "C:\\Windows\\System32" if os.name == "nt" else "/etc/shadow"
            },
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_deny_ln_outside_sandbox(self, rule):
        ctx = ToolCallContext(
            tool_name="ln",
            arguments={"target": "C:\\Users\\admin" if os.name == "nt" else "/root"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY

    async def test_edge_case_symlink_tool_name(self, rule):
        ctx = ToolCallContext(
            tool_name="symlink",
            arguments={
                "target": "C:\\boot.ini" if os.name == "nt" else "/boot/vmlinuz"
            },
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.DENY


# ── ExecutableWriteRule ─────────────────────────────────────────────


class TestExecutableWriteRule:
    @pytest.fixture
    def rule(self):
        return ExecutableWriteRule()

    async def test_allow_write_text_file(self, rule):
        ctx = ToolCallContext(
            tool_name="write_file",
            arguments={"path": "output.txt"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_allow_write_python_file(self, rule):
        ctx = ToolCallContext(
            tool_name="write_file",
            arguments={"path": "script.py"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ALLOW

    async def test_escalate_write_sh_file(self, rule):
        ctx = ToolCallContext(
            tool_name="write_file",
            arguments={"path": "deploy.sh"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ESCALATE

    async def test_escalate_write_exe_file(self, rule):
        ctx = ToolCallContext(
            tool_name="write_file",
            arguments={"path": "malware.exe"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ESCALATE

    async def test_edge_case_bat_file(self, rule):
        ctx = ToolCallContext(
            tool_name="write_file",
            arguments={"path": "startup.bat"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ESCALATE

    async def test_edge_case_ps1_file(self, rule):
        ctx = ToolCallContext(
            tool_name="write_file",
            arguments={"path": "setup.ps1"},
        )
        result = await rule.evaluate(ctx)
        assert result.action is PolicyAction.ESCALATE

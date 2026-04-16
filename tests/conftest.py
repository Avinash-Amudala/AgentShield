from __future__ import annotations

import pytest

from agentshield.core.context import ToolCallContext


@pytest.fixture
def make_context():
    """Factory fixture to create ToolCallContext easily."""

    def _make(tool_name: str = "test_tool", **kwargs):
        return ToolCallContext(tool_name=tool_name, arguments=kwargs)

    return _make


@pytest.fixture
def make_context_with_session():
    """Factory fixture that pins the session_id for deterministic tests."""

    def _make(
        tool_name: str = "test_tool",
        session_id: str = "test-session",
        agent_id: str = "default",
        **kwargs,
    ):
        return ToolCallContext(
            tool_name=tool_name,
            arguments=kwargs,
            session_id=session_id,
            agent_id=agent_id,
        )

    return _make

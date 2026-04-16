"""Tool-call context dataclass used throughout AgentShield."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import uuid4


@dataclass
class ToolCallContext:
    """Immutable snapshot of a single tool invocation.

    Attributes:
        tool_name: Canonical name of the tool being called (e.g. ``exec``,
            ``read_file``).
        arguments: Mapping of argument names to values the agent supplied.
        agent_id: Identifier for the calling agent.  Defaults to
            ``"default"`` for single-agent setups.
        session_id: Unique session / conversation identifier.  Auto-generated
            when not provided.
        timestamp: UTC time the call was captured.
        metadata: Arbitrary key-value pairs (model name, provider, etc.).
        call_history: Previous tool calls in the same session, ordered
            chronologically.  Useful for rules that reason over sequences.
    """

    tool_name: str
    arguments: dict[str, Any]
    agent_id: str = "default"
    session_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = field(default_factory=dict)
    call_history: list[ToolCallContext] = field(default_factory=list)

"""Rate limiting rules (OWASP ASI07 — Denial of Service)."""
from __future__ import annotations

import collections
import time

from agentshield.core.context import ToolCallContext
from agentshield.core.result import PolicyAction, PolicyResponse
from agentshield.rules.base import BaseRule


class PerToolRateLimitRule(BaseRule):
    """Deny calls when a single tool exceeds its rate limit.

    Uses an in-memory sliding window (``collections.deque`` +
    ``time.monotonic``) keyed by ``(session_id, tool_name)``.
    """

    name: str = "per_tool_rate_limit"
    description: str = "Limit calls to the same tool within a time window"
    priority: int = 30
    enabled: bool = True
    owasp_id: str = "ASI07"

    max_calls: int = 50
    window_seconds: float = 60.0

    def __init__(self) -> None:
        self._windows: dict[tuple[str, str], collections.deque[float]] = {}

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Enforce per-tool rate limits using a sliding window.

        Args:
            context: The tool-call context to inspect.

        Returns:
            DENY if the rate limit is exceeded, ALLOW otherwise.
        """
        key = (context.session_id, context.tool_name)
        now = time.monotonic()

        window = self._windows.setdefault(key, collections.deque())

        cutoff = now - self.window_seconds
        while window and window[0] < cutoff:
            window.popleft()

        if len(window) >= self.max_calls:
            return PolicyResponse(
                action=PolicyAction.DENY,
                rule_name=self.name,
                reason=(
                    f"Rate limit exceeded for tool {context.tool_name!r}: "
                    f"{len(window)} calls in {self.window_seconds}s (max {self.max_calls})"
                ),
                details={
                    "tool_name": context.tool_name,
                    "call_count": len(window),
                    "max_calls": self.max_calls,
                    "window_seconds": self.window_seconds,
                },
                owasp_id=self.owasp_id,
            )

        window.append(now)
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason=f"Tool {context.tool_name!r} within rate limit ({len(window)}/{self.max_calls})",
        )


class SessionRateLimitRule(BaseRule):
    """Deny calls when total session calls exceed a global limit.

    Tracks all tool calls in a session with a sliding window.
    """

    name: str = "session_rate_limit"
    description: str = "Limit total tool calls per session within a time window"
    priority: int = 30
    enabled: bool = True
    owasp_id: str = "ASI07"

    max_calls: int = 500
    window_seconds: float = 3600.0

    def __init__(self) -> None:
        self._windows: dict[str, collections.deque[float]] = {}

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Enforce session-wide rate limits using a sliding window.

        Args:
            context: The tool-call context to inspect.

        Returns:
            DENY if the session rate limit is exceeded, ALLOW otherwise.
        """
        key = context.session_id
        now = time.monotonic()

        window = self._windows.setdefault(key, collections.deque())

        cutoff = now - self.window_seconds
        while window and window[0] < cutoff:
            window.popleft()

        if len(window) >= self.max_calls:
            return PolicyResponse(
                action=PolicyAction.DENY,
                rule_name=self.name,
                reason=(
                    f"Session rate limit exceeded: "
                    f"{len(window)} calls in {self.window_seconds}s (max {self.max_calls})"
                ),
                details={
                    "session_id": context.session_id,
                    "call_count": len(window),
                    "max_calls": self.max_calls,
                    "window_seconds": self.window_seconds,
                },
                owasp_id=self.owasp_id,
            )

        window.append(now)
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason=f"Session within rate limit ({len(window)}/{self.max_calls})",
        )


class BurstDetectionRule(BaseRule):
    """Escalate when calls arrive in rapid bursts.

    Detects more than ``max_burst`` calls within a 1-second micro-window,
    which may indicate automated abuse.
    """

    name: str = "burst_detection"
    description: str = "Escalate rapid bursts of tool calls (>N in 1 second)"
    priority: int = 30
    enabled: bool = True
    owasp_id: str = "ASI07"

    max_burst: int = 10
    burst_window_seconds: float = 1.0

    def __init__(self) -> None:
        self._windows: dict[str, collections.deque[float]] = {}

    async def evaluate(self, context: ToolCallContext) -> PolicyResponse:
        """Detect rapid-fire call bursts.

        Args:
            context: The tool-call context to inspect.

        Returns:
            ESCALATE if a burst is detected, ALLOW otherwise.
        """
        key = context.session_id
        now = time.monotonic()

        window = self._windows.setdefault(key, collections.deque())

        cutoff = now - self.burst_window_seconds
        while window and window[0] < cutoff:
            window.popleft()

        if len(window) >= self.max_burst:
            return PolicyResponse(
                action=PolicyAction.ESCALATE,
                rule_name=self.name,
                reason=(
                    f"Burst detected: {len(window)} calls in "
                    f"{self.burst_window_seconds}s (max {self.max_burst})"
                ),
                details={
                    "session_id": context.session_id,
                    "burst_count": len(window),
                    "max_burst": self.max_burst,
                },
                owasp_id=self.owasp_id,
            )

        window.append(now)
        return PolicyResponse(
            action=PolicyAction.ALLOW,
            rule_name=self.name,
            reason=f"No burst detected ({len(window)}/{self.max_burst})",
        )

"""Terminal-based HITL approval channel (stdlib only)."""

from __future__ import annotations

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from agentshield.hitl.gateway import NotificationChannel

logger = logging.getLogger("agentshield.hitl.terminal")

_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="hitl-term")


class TerminalChannel(NotificationChannel):
    """Interactive terminal prompt for human approval.

    Presents the pending tool-call details on *stdout* and reads a
    ``y/n`` response from *stdin*.  Because :func:`input` blocks, the
    actual I/O runs in a background thread so the asyncio event loop
    stays responsive.

    This channel is **not** able to resolve the gateway future on its
    own — it merely logs the human decision.  Pair it with a gateway
    that also calls :meth:`HITLGateway.resolve` from the terminal
    response, or use it as the sole channel where the gateway spawns
    the terminal prompt and auto-resolves.
    """

    async def send(self, payload: dict[str, Any]) -> None:
        """Print the approval prompt and collect a y/n answer.

        The call blocks (on a thread) until the operator responds or
        presses Ctrl-C.

        Args:
            payload: Notification payload produced by the gateway.
        """
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(_executor, self._prompt, payload)

    # ------------------------------------------------------------------

    @staticmethod
    def _prompt(payload: dict[str, Any]) -> None:
        """Synchronous prompt executed inside a worker thread."""
        border = "=" * 60
        print(f"\n{border}")
        print("  AgentShield — Approval Required")
        print(border)
        print(f"  Event ID : {payload.get('event_id', 'N/A')}")
        print(f"  Tool     : {payload.get('tool_name', 'N/A')}")
        print(f"  Agent    : {payload.get('agent_id', 'N/A')}")
        print(f"  Rule     : {payload.get('rule_name', 'N/A')}")
        print(f"  Reason   : {payload.get('reason', 'N/A')}")
        print(f"  Arguments: {payload.get('arguments', {})}")
        print(border)

        try:
            answer = input("  Approve? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"

        approved = answer in ("y", "yes")
        status = "APPROVED" if approved else "DENIED"
        logger.info("Terminal %s: event_id=%s", status, payload.get("event_id"))

        # Attempt to resolve via gateway if one is reachable.  The
        # gateway's ``resolve`` method is thread-safe.
        _try_resolve(payload.get("event_id", ""), approved)


def _try_resolve(event_id: str, approved: bool) -> None:
    """Best-effort resolution of the pending future.

    Imports :class:`HITLGateway` lazily to avoid circular imports.
    If the active gateway singleton is not set, this is a no-op.
    """
    try:
        from agentshield.hitl import _active_gateway  # type: ignore[attr-defined]

        if _active_gateway is not None:
            _active_gateway.resolve(event_id, approved, reviewer="terminal")
    except (ImportError, AttributeError, KeyError):
        pass

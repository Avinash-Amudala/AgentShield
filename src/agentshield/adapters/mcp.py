"""MCP (Model Context Protocol) server adapter for AgentShield."""

from __future__ import annotations

import functools
import logging
from typing import Any, Callable

from agentshield.core.context import ToolCallContext
from agentshield.core.exceptions import ToolCallBlocked
from agentshield.core.result import PolicyAction
from agentshield.core.shield import Shield

logger = logging.getLogger("agentshield.adapters.mcp")


def _ensure_mcp() -> Any:
    """Lazily import and return the ``mcp.server.Server`` class."""
    try:
        from mcp.server import Server  # type: ignore[import-untyped]
    except ImportError:
        raise ImportError(
            "MCP adapter requires the 'mcp' package. "
            "Install it with:  pip install agentshield[mcp]"
        ) from None
    return Server


def shield_mcp_server(server: Any, shield: Shield) -> None:
    """Shield all tools registered on an MCP server.

    Wraps each tool handler so that every invocation passes through
    AgentShield policy evaluation before the real handler executes.

    Args:
        server: An ``mcp.server.Server`` instance.
        shield: The :class:`Shield` used for policy checks.

    Raises:
        ImportError: If the ``mcp`` package is not installed.
        TypeError: If *server* is not an ``mcp.server.Server`` instance.
    """
    ServerClass = _ensure_mcp()
    if not isinstance(server, ServerClass):
        raise TypeError(
            f"Expected an mcp.server.Server instance, got {type(server).__name__}"
        )

    tool_handlers: dict[str, Callable[..., Any]] = getattr(server, "_tool_handlers", {})
    for name, handler in tool_handlers.items():
        tool_handlers[name] = _wrap_handler(handler, name, shield)
        logger.debug("Shielded MCP tool handler: %s", name)


def _wrap_handler(
    handler: Callable[..., Any],
    tool_name: str,
    shield: Shield,
) -> Callable[..., Any]:
    """Return an async wrapper that checks the shield before calling *handler*."""

    @functools.wraps(handler)
    async def wrapper(**kwargs: Any) -> Any:
        context = ToolCallContext(
            tool_name=tool_name,
            arguments=kwargs,
            metadata={"source": "mcp"},
        )
        response = await shield.check(context)
        if response.action is PolicyAction.DENY:
            raise ToolCallBlocked(response)
        return await handler(**kwargs)

    return wrapper


def shielded_tool(
    shield: Shield,
    *,
    tool_name: str | None = None,
    agent_id: str = "default",
) -> Callable[..., Callable[..., Any]]:
    """Decorator for individual MCP tool handlers.

    Apply directly to an ``async def`` tool function to enforce
    AgentShield policies on every call.

    Args:
        shield: The :class:`Shield` instance used for policy checks.
        tool_name: Override for the context ``tool_name``.  Defaults to
            the decorated function's ``__name__``.
        agent_id: Agent identifier embedded in every context.

    Returns:
        A decorator that wraps the target async function.

    Example::

        @shielded_tool(shield)
        async def read_file(path: str) -> str:
            ...
    """
    _ensure_mcp()

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        resolved_name = tool_name or func.__name__

        @functools.wraps(func)
        async def wrapper(**kwargs: Any) -> Any:
            context = ToolCallContext(
                tool_name=resolved_name,
                arguments=kwargs,
                agent_id=agent_id,
                metadata={"source": "mcp"},
            )
            response = await shield.check(context)
            if response.action is PolicyAction.DENY:
                raise ToolCallBlocked(response)
            return await func(**kwargs)

        return wrapper

    return decorator

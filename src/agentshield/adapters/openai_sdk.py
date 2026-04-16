"""OpenAI Agents SDK adapter for AgentShield."""
from __future__ import annotations

import asyncio
import functools
import logging
from typing import Any, Callable

from agentshield.core.context import ToolCallContext
from agentshield.core.exceptions import ToolCallBlocked
from agentshield.core.result import PolicyAction
from agentshield.core.shield import Shield

logger = logging.getLogger("agentshield.adapters.openai_sdk")


def _ensure_openai_agents() -> tuple[Any, Any]:
    """Lazily import and return ``agents.Agent`` and ``agents.FunctionTool``."""
    try:
        from agents import Agent, FunctionTool  # type: ignore[import-untyped]
    except ImportError:
        raise ImportError(
            "OpenAI Agents SDK adapter requires the 'openai-agents' package. "
            "Install it with:  pip install agentshield[openai]"
        ) from None
    return Agent, FunctionTool


def shield_agent(
    agent: Any,
    shield: Shield,
    *,
    agent_id: str = "default",
) -> None:
    """Shield all function tools registered on an OpenAI Agents SDK agent.

    Wraps each ``FunctionTool`` on the agent so that every invocation
    passes through AgentShield policy evaluation first.

    Args:
        agent: An ``agents.Agent`` instance.
        shield: The :class:`Shield` used for policy checks.
        agent_id: Agent identifier embedded in every context.

    Raises:
        ImportError: If the ``openai-agents`` package is not installed.
        TypeError: If *agent* is not an ``agents.Agent`` instance.
    """
    Agent, FunctionTool = _ensure_openai_agents()
    if not isinstance(agent, Agent):
        raise TypeError(
            f"Expected an agents.Agent instance, got {type(agent).__name__}"
        )

    tools: list[Any] = getattr(agent, "tools", [])
    for idx, tool in enumerate(tools):
        if isinstance(tool, FunctionTool):
            tools[idx] = _wrap_function_tool(tool, shield, agent_id)
            logger.debug(
                "Shielded OpenAI function tool: %s",
                getattr(tool, "name", "unknown"),
            )


def _wrap_function_tool(
    tool: Any,
    shield: Shield,
    agent_id: str,
) -> Any:
    """Wrap a single ``FunctionTool``'s callable with shield checks."""
    _, FunctionTool = _ensure_openai_agents()

    tool_name: str = getattr(tool, "name", "unknown")
    original_fn: Callable[..., Any] = tool.fn

    def _build_context(kwargs: dict[str, Any]) -> ToolCallContext:
        return ToolCallContext(
            tool_name=tool_name,
            arguments=kwargs,
            agent_id=agent_id,
            metadata={"source": "openai_agents_sdk"},
        )

    if asyncio.iscoroutinefunction(original_fn):

        @functools.wraps(original_fn)
        async def guarded_async(*args: Any, **kwargs: Any) -> Any:
            context = _build_context(kwargs)
            response = await shield.check(context)
            if response.action is PolicyAction.DENY:
                raise ToolCallBlocked(response)
            return await original_fn(*args, **kwargs)

        tool.fn = guarded_async
    else:

        @functools.wraps(original_fn)
        def guarded_sync(*args: Any, **kwargs: Any) -> Any:
            context = _build_context(kwargs)
            try:
                loop: asyncio.AbstractEventLoop | None = None
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    pass

                if loop is not None and loop.is_running():
                    import concurrent.futures

                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        future = pool.submit(asyncio.run, shield.check(context))
                        future.result()
                else:
                    asyncio.run(shield.check(context))
            except ToolCallBlocked:
                raise
            return original_fn(*args, **kwargs)

        tool.fn = guarded_sync

    return tool


def shielded_function_tool(
    shield: Shield,
    *,
    tool_name: str | None = None,
    agent_id: str = "default",
) -> Callable[..., Callable[..., Any]]:
    """Decorator for functions that will be used as OpenAI Agents SDK tools.

    Apply before passing the function to ``FunctionTool()`` to ensure every
    call is guarded by AgentShield.

    Args:
        shield: The :class:`Shield` instance used for policy checks.
        tool_name: Override for the context ``tool_name``.
        agent_id: Agent identifier embedded in every context.

    Returns:
        A decorator that wraps the target function.

    Example::

        @shielded_function_tool(shield)
        async def run_query(sql: str) -> str:
            ...

        agent = Agent(tools=[FunctionTool(run_query)])
    """
    _ensure_openai_agents()

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        resolved_name = tool_name or func.__name__

        if asyncio.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                context = ToolCallContext(
                    tool_name=resolved_name,
                    arguments=kwargs,
                    agent_id=agent_id,
                    metadata={"source": "openai_agents_sdk"},
                )
                response = await shield.check(context)
                if response.action is PolicyAction.DENY:
                    raise ToolCallBlocked(response)
                return await func(*args, **kwargs)

            return async_wrapper

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            context = ToolCallContext(
                tool_name=resolved_name,
                arguments=kwargs,
                agent_id=agent_id,
                metadata={"source": "openai_agents_sdk"},
            )
            try:
                loop: asyncio.AbstractEventLoop | None = None
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    pass

                if loop is not None and loop.is_running():
                    import concurrent.futures

                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        future = pool.submit(asyncio.run, shield.check(context))
                        future.result()
                else:
                    asyncio.run(shield.check(context))
            except ToolCallBlocked:
                raise
            return func(*args, **kwargs)

        return sync_wrapper

    return decorator

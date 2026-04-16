"""CrewAI adapter for AgentShield."""
from __future__ import annotations

import asyncio
import functools
import logging
from typing import Any, Callable

from agentshield.core.context import ToolCallContext
from agentshield.core.exceptions import ToolCallBlocked
from agentshield.core.result import PolicyAction
from agentshield.core.shield import Shield

logger = logging.getLogger("agentshield.adapters.crewai")


def _ensure_crewai() -> tuple[Any, Any]:
    """Lazily import and return ``crewai.Crew`` and ``crewai.tools.BaseTool``."""
    try:
        from crewai import Crew  # type: ignore[import-untyped]
        from crewai.tools import BaseTool  # type: ignore[import-untyped]
    except ImportError:
        raise ImportError(
            "CrewAI adapter requires the 'crewai' package. "
            "Install it with:  pip install agentshield[crewai]"
        ) from None
    return Crew, BaseTool


def shield_crew(
    crew: Any,
    shield: Shield,
    *,
    agent_id: str = "default",
) -> None:
    """Shield all tools used by every agent in a CrewAI crew.

    Iterates over all agents and their associated tools, wrapping each
    tool's ``_run`` method with AgentShield policy evaluation.

    Args:
        crew: A ``crewai.Crew`` instance.
        shield: The :class:`Shield` used for policy checks.
        agent_id: Agent identifier embedded in every context.

    Raises:
        ImportError: If the ``crewai`` package is not installed.
        TypeError: If *crew* is not a ``crewai.Crew`` instance.
    """
    Crew, BaseTool = _ensure_crewai()
    if not isinstance(crew, Crew):
        raise TypeError(
            f"Expected a crewai.Crew instance, got {type(crew).__name__}"
        )

    agents = getattr(crew, "agents", [])
    for agent in agents:
        agent_tools: list[Any] = getattr(agent, "tools", [])
        for idx, tool in enumerate(agent_tools):
            agent_tools[idx] = _wrap_tool(tool, shield, agent_id)
        logger.debug(
            "Shielded %d tools for CrewAI agent: %s",
            len(agent_tools),
            getattr(agent, "role", "unknown"),
        )


def _wrap_tool(tool: Any, shield: Shield, agent_id: str) -> Any:
    """Wrap a single CrewAI tool's ``_run`` method with shield checks."""
    tool_name: str = getattr(tool, "name", type(tool).__name__)
    original_run: Callable[..., Any] = tool._run

    def _build_context(kwargs: dict[str, Any]) -> ToolCallContext:
        return ToolCallContext(
            tool_name=tool_name,
            arguments=kwargs,
            agent_id=agent_id,
            metadata={"source": "crewai"},
        )

    @functools.wraps(original_run)
    def guarded_run(*args: Any, **kwargs: Any) -> Any:
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
        except ToolCallBlocked as exc:
            return f"[AgentShield] Action blocked: {exc.response.reason}"
        return original_run(*args, **kwargs)

    tool._run = guarded_run
    logger.debug("Shielded CrewAI tool: %s", tool_name)
    return tool


def shield_tool(
    shield: Shield,
    *,
    tool_name: str | None = None,
    agent_id: str = "default",
) -> Callable[..., Callable[..., Any]]:
    """Decorator for individual CrewAI tool functions.

    Args:
        shield: The :class:`Shield` instance used for policy checks.
        tool_name: Override for the context ``tool_name``.
        agent_id: Agent identifier embedded in every context.

    Returns:
        A decorator that wraps the target function.

    Example::

        @shield_tool(shield)
        def search_web(query: str) -> str:
            ...
    """
    _ensure_crewai()

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        resolved_name = tool_name or func.__name__

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            context = ToolCallContext(
                tool_name=resolved_name,
                arguments=kwargs,
                agent_id=agent_id,
                metadata={"source": "crewai"},
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
            except ToolCallBlocked as exc:
                return f"[AgentShield] Action blocked: {exc.response.reason}"
            return func(*args, **kwargs)

        return wrapper

    return decorator

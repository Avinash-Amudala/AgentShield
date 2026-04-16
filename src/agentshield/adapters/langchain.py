"""LangChain adapter for AgentShield."""
from __future__ import annotations

import asyncio
import functools
import logging
from typing import Any, Callable

from agentshield.core.context import ToolCallContext
from agentshield.core.exceptions import ToolCallBlocked
from agentshield.core.result import PolicyAction
from agentshield.core.shield import Shield

logger = logging.getLogger("agentshield.adapters.langchain")


def _ensure_langchain() -> Any:
    """Lazily import and return ``langchain_core.tools.BaseTool``."""
    try:
        from langchain_core.tools import BaseTool  # type: ignore[import-untyped]
    except ImportError:
        raise ImportError(
            "LangChain adapter requires the 'langchain-core' package. "
            "Install it with:  pip install agentshield[langchain]"
        ) from None
    return BaseTool


class ShieldedToolkit:
    """Wrap LangChain tools with AgentShield protection.

    Instead of raising on a denied call, the wrapped tools return a
    human-readable denial message so that LangChain agents can reason
    about the refusal gracefully.

    Args:
        tools: A list of ``langchain_core.tools.BaseTool`` instances.
        shield: The :class:`Shield` used for policy evaluation.
        agent_id: Agent identifier embedded in every context.

    Example::

        from langchain_community.tools import ShellTool
        toolkit = ShieldedToolkit([ShellTool()], shield=my_shield)
        agent = initialize_agent(toolkit.tools(), llm)
    """

    def __init__(
        self,
        tools: list[Any],
        shield: Shield,
        *,
        agent_id: str = "default",
    ) -> None:
        BaseTool = _ensure_langchain()
        for tool in tools:
            if not isinstance(tool, BaseTool):
                raise TypeError(
                    f"Expected a BaseTool instance, got {type(tool).__name__}"
                )

        self._shield = shield
        self._agent_id = agent_id
        self._original_tools = list(tools)
        self._shielded_tools = [self._wrap_tool(t) for t in tools]

    def tools(self) -> list[Any]:
        """Return the list of shielded tools ready for agent consumption."""
        return list(self._shielded_tools)

    def _wrap_tool(self, tool: Any) -> Any:
        """Clone a tool and replace its ``_run`` / ``_arun`` with guarded versions."""
        BaseTool = _ensure_langchain()
        shield = self._shield
        agent_id = self._agent_id
        tool_name = getattr(tool, "name", tool.__class__.__name__)

        original_run: Callable[..., Any] = tool._run
        original_arun: Callable[..., Any] = tool._arun

        def _build_context(kwargs: dict[str, Any]) -> ToolCallContext:
            return ToolCallContext(
                tool_name=tool_name,
                arguments=kwargs,
                agent_id=agent_id,
                metadata={"source": "langchain"},
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

        @functools.wraps(original_arun)
        async def guarded_arun(*args: Any, **kwargs: Any) -> Any:
            context = _build_context(kwargs)
            try:
                await shield.check(context)
            except ToolCallBlocked as exc:
                return f"[AgentShield] Action blocked: {exc.response.reason}"
            return await original_arun(*args, **kwargs)

        tool._run = guarded_run
        tool._arun = guarded_arun
        logger.debug("Shielded LangChain tool: %s", tool_name)
        return tool

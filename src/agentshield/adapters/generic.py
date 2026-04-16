"""Generic (framework-agnostic) adapter utilities for AgentShield."""
from __future__ import annotations

import asyncio
import functools
import inspect
from typing import Any, Callable

from agentshield.core.context import ToolCallContext
from agentshield.core.result import PolicyAction
from agentshield.core.shield import Shield


def _run_check_sync(shield: Shield, context: ToolCallContext) -> None:
    """Run the async shield check from synchronous code."""
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


def protect_function(
    func: Callable[..., Any],
    shield: Shield,
    *,
    tool_name: str | None = None,
    agent_id: str = "default",
    metadata: dict[str, Any] | None = None,
) -> Callable[..., Any]:
    """Wrap any callable with AgentShield policy evaluation.

    This is the standalone equivalent of ``shield.protect()`` — useful when
    you cannot apply a decorator directly (e.g. third-party functions).

    Args:
        func: The callable to protect.
        shield: The :class:`Shield` instance that evaluates policies.
        tool_name: Override for the context ``tool_name``.  Defaults to
            ``func.__name__``.
        agent_id: Agent identifier embedded in every context.
        metadata: Extra metadata forwarded to the context.

    Returns:
        A wrapped callable with the same signature as *func*.
    """
    resolved_name = tool_name or func.__name__
    sig = inspect.signature(func)

    def _build_context(
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> ToolCallContext:
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        return ToolCallContext(
            tool_name=resolved_name,
            arguments=dict(bound.arguments),
            agent_id=agent_id,
            metadata=metadata or {},
        )

    if asyncio.iscoroutinefunction(func):

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            ctx = _build_context(args, kwargs)
            await shield.check(ctx)
            return await func(*args, **kwargs)

        return async_wrapper

    @functools.wraps(func)
    def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
        ctx = _build_context(args, kwargs)
        _run_check_sync(shield, ctx)
        return func(*args, **kwargs)

    return sync_wrapper


def protect_class_method(
    cls: type,
    method_name: str,
    shield: Shield,
    *,
    tool_name: str | None = None,
    agent_id: str = "default",
    metadata: dict[str, Any] | None = None,
) -> None:
    """Replace a method on *cls* with a shielded version (in-place).

    Args:
        cls: The class whose method will be wrapped.
        method_name: Name of the method to protect.
        shield: The :class:`Shield` instance that evaluates policies.
        tool_name: Override for the context ``tool_name``.  Defaults to
            ``cls.__name__.<method_name>``.
        agent_id: Agent identifier embedded in every context.
        metadata: Extra metadata forwarded to the context.

    Raises:
        AttributeError: If *method_name* does not exist on *cls*.
    """
    original = getattr(cls, method_name)
    resolved_name = tool_name or f"{cls.__name__}.{method_name}"

    wrapped = protect_function(
        original,
        shield,
        tool_name=resolved_name,
        agent_id=agent_id,
        metadata=metadata,
    )
    setattr(cls, method_name, wrapped)

"""Shield — the main entry-point for AgentShield."""

from __future__ import annotations

import asyncio
import functools
import inspect
import logging
from pathlib import Path
from typing import Any, Callable

from agentshield.core.context import ToolCallContext
from agentshield.core.engine import PolicyEngine
from agentshield.core.exceptions import ToolCallBlocked
from agentshield.core.result import PolicyAction, PolicyResponse
from agentshield.rules.base import BaseRule

logger = logging.getLogger("agentshield")

_MODES = frozenset({"enforce", "monitor", "dry-run"})


def _get_default_rules() -> list[BaseRule]:
    """Import and return built-in rules from the rules package.

    Returns an empty list when no default rules have been registered yet so
    that the core module never raises on import.
    """
    try:
        from agentshield.rules import DEFAULT_RULES  # type: ignore[attr-defined]

        return list(DEFAULT_RULES)
    except (ImportError, AttributeError):
        return []


class Shield:
    """Runtime firewall that wraps agent tool calls.

    Args:
        config_path: Optional path to an ``agentshield.yaml`` config file.
        rules: Explicit list of rule instances.  When *None*, built-in
            defaults are loaded via the rules package.
        mode: One of ``"enforce"`` (block), ``"monitor"`` (log-only),
            or ``"dry-run"`` (log + print what *would* be blocked).
        log_file: Optional file path for the JSON audit log.
        dashboard_port: Port reserved for the live dashboard (future use).
        default_action: Fallback action when no rule triggers.

    Raises:
        ValueError: If *mode* is not one of the accepted values.
    """

    def __init__(
        self,
        *,
        config_path: str | Path | None = None,
        rules: list[BaseRule] | None = None,
        mode: str = "enforce",
        log_file: str | Path | None = None,
        dashboard_port: int = 8484,
        default_action: PolicyAction = PolicyAction.ALLOW,
    ) -> None:
        if mode not in _MODES:
            raise ValueError(f"Invalid mode {mode!r}. Must be one of {sorted(_MODES)}.")

        self.mode = mode
        self.config_path = Path(config_path) if config_path else None
        self.log_file = Path(log_file) if log_file else None
        self.dashboard_port = dashboard_port

        resolved_rules = rules if rules is not None else _get_default_rules()
        self._engine = PolicyEngine(resolved_rules, default_action=default_action)
        self._audit_logger = self._build_audit_logger()

    # ------------------------------------------------------------------
    # Audit logging
    # ------------------------------------------------------------------

    def _build_audit_logger(self) -> logging.Logger:
        """Create a dedicated audit logger.

        When *log_file* is set a :class:`~logging.FileHandler` is attached so
        that every evaluation is persisted on disk.
        """
        audit = logging.getLogger("agentshield.audit")
        audit.setLevel(logging.DEBUG)
        if not audit.handlers:
            console = logging.StreamHandler()
            console.setLevel(logging.INFO)
            fmt = logging.Formatter(
                "[%(asctime)s] %(levelname)s %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
            )
            console.setFormatter(fmt)
            audit.addHandler(console)

        if self.log_file and not any(
            isinstance(h, logging.FileHandler) for h in audit.handlers
        ):
            fh = logging.FileHandler(self.log_file, encoding="utf-8")
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
            audit.addHandler(fh)

        return audit

    def _log_evaluation(
        self,
        context: ToolCallContext,
        response: PolicyResponse,
    ) -> None:
        """Emit a structured audit record."""
        record = (
            f"tool={context.tool_name!r} agent={context.agent_id!r} "
            f"action={response.action.value} rule={response.rule_name!r} "
            f"reason={response.reason!r}"
        )
        if response.owasp_id:
            record += f" owasp={response.owasp_id}"

        if response.action is PolicyAction.DENY:
            self._audit_logger.warning("DENY  | %s", record)
        elif response.action is PolicyAction.ESCALATE:
            self._audit_logger.warning("ESCALATE | %s", record)
        else:
            self._audit_logger.info("ALLOW | %s", record)

    # ------------------------------------------------------------------
    # Core evaluation
    # ------------------------------------------------------------------

    async def check(self, context: ToolCallContext) -> PolicyResponse:
        """Evaluate *context* through the policy engine and apply the mode.

        Args:
            context: The tool-call context to evaluate.

        Returns:
            The :class:`PolicyResponse` from the engine.

        Raises:
            ToolCallBlocked: In *enforce* mode when the action is ``DENY``.
        """
        response = await self._engine.evaluate(context)
        self._log_evaluation(context, response)

        if self.mode == "dry-run" and response.action is PolicyAction.DENY:
            print(
                f"[AgentShield dry-run] WOULD BLOCK: "
                f"{context.tool_name} — {response.reason}"
            )

        if self.mode == "enforce" and response.action is PolicyAction.DENY:
            raise ToolCallBlocked(response)

        return response

    # ------------------------------------------------------------------
    # Decorator
    # ------------------------------------------------------------------

    def protect(
        self,
        fn: Callable[..., Any] | None = None,
        *,
        tool_name: str | None = None,
        agent_id: str = "default",
        metadata: dict[str, Any] | None = None,
    ) -> Callable[..., Any]:
        """Decorator that guards a function with AgentShield policy checks.

        Works seamlessly with both synchronous and ``async`` functions.  The
        decorated function's positional and keyword arguments are captured
        into :attr:`ToolCallContext.arguments` by inspecting the original
        signature.

        Can be used with or without parentheses::

            @shield.protect
            def execute_sql(query: str) -> str: ...

            @shield.protect(tool_name="sql")
            def execute_sql(query: str) -> str: ...

        Args:
            fn: When used without parentheses, the decorated function is
                passed directly as the first positional argument.
            tool_name: Override for the context's ``tool_name``.  Defaults to
                the decorated function's ``__name__``.
            agent_id: Agent identifier to embed in the context.
            metadata: Extra metadata forwarded to the context.

        Returns:
            A decorator that wraps the target function, or the wrapped
            function directly when called without parentheses.
        """

        def decorator(fn_inner: Callable[..., Any]) -> Callable[..., Any]:
            resolved_name = tool_name or fn_inner.__name__
            sig = inspect.signature(fn_inner)

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

            if asyncio.iscoroutinefunction(fn_inner):

                @functools.wraps(fn_inner)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    ctx = _build_context(args, kwargs)
                    await self.check(ctx)
                    return await fn_inner(*args, **kwargs)

                return async_wrapper

            @functools.wraps(fn_inner)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                ctx = _build_context(args, kwargs)
                loop: asyncio.AbstractEventLoop | None = None
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    pass

                if loop is not None and loop.is_running():
                    import concurrent.futures

                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        future = pool.submit(asyncio.run, self.check(ctx))
                        future.result()
                else:
                    asyncio.run(self.check(ctx))

                return fn_inner(*args, **kwargs)

            return sync_wrapper

        if fn is not None:
            return decorator(fn)
        return decorator

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    @property
    def rules(self) -> list[BaseRule]:
        """Snapshot of the currently loaded rules (sorted by priority)."""
        return list(self._engine.rules)

    def __repr__(self) -> str:
        return (
            f"<Shield mode={self.mode!r} rules={len(self._engine.rules)} "
            f"dashboard_port={self.dashboard_port}>"
        )

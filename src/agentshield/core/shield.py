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
_UNSET: Any = object()


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

    Configuration is resolved in layers (later overrides earlier):

        1. Built-in defaults
        2. Auto-discovered ``agentshield.yaml`` (CWD, then ``~/.agentshield/``)
        3. Explicit *config_path* YAML file
        4. ``AGENTSHIELD_*`` environment variables
        5. Keyword arguments passed to this constructor

    When *log_file* is set the hash-chained
    :class:`~agentshield.audit.logger.AuditLogger` is used for
    tamper-evident JSONL recording of every policy decision.

    When the ``hitl`` section is present in the resolved config, a
    :class:`~agentshield.hitl.gateway.HITLGateway` is created so that
    ``ESCALATE`` verdicts trigger human-in-the-loop approval.

    Args:
        config_path: Optional path to an ``agentshield.yaml`` config file.
        rules: Explicit list of rule instances.  When *None*, built-in
            defaults are loaded via the rules package.
        mode: One of ``"enforce"`` (block), ``"monitor"`` (log-only),
            or ``"dry-run"`` (log + print what *would* be blocked).
        log_file: Path for the JSONL audit log.  *None* disables file
            logging.
        dashboard_port: Port for the live dashboard, or *None* to disable.
        default_action: Fallback action when no rule triggers.

    Raises:
        ValueError: If *mode* is not one of the accepted values.
    """

    def __init__(
        self,
        *,
        config_path: str | Path | None = None,
        rules: list[BaseRule] | None = None,
        mode: Any = _UNSET,
        log_file: Any = _UNSET,
        dashboard_port: Any = _UNSET,
        default_action: Any = _UNSET,
    ) -> None:
        raw = self._load_raw_config(config_path)

        self.mode: str = mode if mode is not _UNSET else raw.get("mode", "enforce")
        resolved_log = log_file if log_file is not _UNSET else raw.get("log_file")
        resolved_dash = (
            dashboard_port
            if dashboard_port is not _UNSET
            else raw.get("dashboard_port")
        )
        resolved_action = (
            default_action
            if default_action is not _UNSET
            else raw.get("default_action", PolicyAction.ALLOW)
        )

        if self.mode not in _MODES:
            raise ValueError(
                f"Invalid mode {self.mode!r}. Must be one of {sorted(_MODES)}."
            )

        self.config_path: Path | None = Path(config_path) if config_path else None
        self.log_file: Path | None = Path(resolved_log) if resolved_log else None
        self.dashboard_port: int | None = (
            int(resolved_dash) if resolved_dash is not None else None
        )

        if isinstance(resolved_action, str):
            resolved_action = PolicyAction(resolved_action)

        # ── Rules ──────────────────────────────────────────────────
        resolved_rules = rules if rules is not None else _get_default_rules()
        rule_settings = raw.get("rules", {})
        if rule_settings:
            for rule in resolved_rules:
                settings = rule_settings.get(rule.name)
                if settings:
                    rule.configure(settings)

        self._engine = PolicyEngine(resolved_rules, default_action=resolved_action)

        # ── Console logger (human-readable) ────────────────────────
        self._console = self._setup_console_logger()

        # ── Hash-chained JSONL audit logger ────────────────────────
        self._audit: Any = None
        if self.log_file is not None:
            from agentshield.audit.logger import AuditLogger

            self._audit = AuditLogger(log_file=self.log_file)

        # ── HITL gateway ───────────────────────────────────────────
        self._hitl: Any = None
        hitl_cfg = raw.get("hitl")
        if hitl_cfg:
            from agentshield.hitl.gateway import HITLGateway

            self._hitl = HITLGateway(config=self._normalize_hitl_config(hitl_cfg))

        # ── Dashboard (lazy — requires agentshield[dashboard]) ─────
        self._dashboard: Any = None
        if self.dashboard_port is not None:
            try:
                from agentshield.dashboard.app import DashboardApp

                self._dashboard = DashboardApp(
                    audit_log_file=self.log_file or "./shield.jsonl",
                    port=self.dashboard_port,
                )
            except ImportError:
                logger.debug(
                    "Dashboard dependencies not installed — "
                    "run: pip install agentshield[dashboard]"
                )

    # ------------------------------------------------------------------
    # Configuration loading
    # ------------------------------------------------------------------

    @staticmethod
    def _load_raw_config(config_path: str | Path | None) -> dict[str, Any]:
        """Load raw config from YAML file and environment variables.

        Returns an empty dict when no config file exists and no relevant
        environment variables are set, preserving constructor defaults.
        """
        try:
            from agentshield.core.config import (
                _apply_env_overrides,
                _find_config_file,
                _load_yaml,
            )
        except ImportError:
            return {}

        data: dict[str, Any] = {}

        if config_path is not None:
            explicit = Path(config_path)
            if not explicit.is_file():
                raise FileNotFoundError(f"Config file not found: {explicit}")
            data.update(_load_yaml(explicit))
        else:
            discovered = _find_config_file()
            if discovered is not None:
                data.update(_load_yaml(discovered))

        _apply_env_overrides(data)
        return data

    @staticmethod
    def _normalize_hitl_config(raw: dict[str, Any]) -> dict[str, Any]:
        """Translate shorthand HITL YAML keys to the gateway's shape.

        Supports both the shorthand form (``channel`` / ``webhook_url`` /
        ``timeout_seconds``) and the canonical form expected by
        :class:`~agentshield.hitl.gateway.HITLGateway`.
        """
        cfg = dict(raw)

        if "timeout_seconds" in cfg and "timeout" not in cfg:
            cfg["timeout"] = cfg.pop("timeout_seconds")

        if "default_action" in cfg and "timeout_action" not in cfg:
            cfg["timeout_action"] = cfg.pop("default_action")

        if "channels" not in cfg and "channel" in cfg:
            ch: dict[str, Any] = {"type": cfg.pop("channel")}
            webhook = cfg.pop("webhook_url", None)
            if webhook:
                ch["webhook_url"] = webhook
            cfg["channels"] = [ch]

        return cfg

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    @staticmethod
    def _setup_console_logger() -> logging.Logger:
        """Return a console-only logger for human-readable output."""
        console_log = logging.getLogger("agentshield.audit")
        console_log.setLevel(logging.DEBUG)
        if not console_log.handlers:
            handler = logging.StreamHandler()
            handler.setLevel(logging.INFO)
            handler.setFormatter(
                logging.Formatter(
                    "[%(asctime)s] %(levelname)s %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%S",
                )
            )
            console_log.addHandler(handler)
        return console_log

    async def _log_evaluation(
        self,
        context: ToolCallContext,
        response: PolicyResponse,
    ) -> dict | None:
        """Emit a console record and write to the hash-chained audit log.

        Returns the audit entry dict when the JSONL logger is active.
        """
        record = (
            f"tool={context.tool_name!r} agent={context.agent_id!r} "
            f"action={response.action.value} rule={response.rule_name!r} "
            f"reason={response.reason!r}"
        )
        if response.owasp_id:
            record += f" owasp={response.owasp_id}"

        if response.action is PolicyAction.DENY:
            self._console.warning("DENY  | %s", record)
        elif response.action is PolicyAction.ESCALATE:
            self._console.warning("ESCALATE | %s", record)
        else:
            self._console.info("ALLOW | %s", record)

        entry: dict | None = None
        if self._audit is not None:
            entry = await self._audit.log(context, response)
            if self._dashboard is not None:
                self._dashboard.push_event(entry)

        return entry

    # ------------------------------------------------------------------
    # Core evaluation
    # ------------------------------------------------------------------

    async def check(self, context: ToolCallContext) -> PolicyResponse:
        """Evaluate *context* through the policy engine and apply the mode.

        In **enforce** mode:

        * ``DENY`` raises :class:`ToolCallBlocked`.
        * ``ESCALATE`` triggers the HITL gateway (if configured).  When the
          reviewer denies or the request times out, :class:`ToolCallBlocked`
          is raised.  When no gateway is configured, a warning is logged
          and the call is allowed through.

        In **monitor** and **dry-run** modes the response is logged but
        never blocks execution.

        Args:
            context: The tool-call context to evaluate.

        Returns:
            The :class:`PolicyResponse` from the engine.

        Raises:
            ToolCallBlocked: In *enforce* mode when the action is ``DENY``
                or when a human reviewer denies an ``ESCALATE``.
        """
        response = await self._engine.evaluate(context)
        await self._log_evaluation(context, response)

        if self.mode == "dry-run" and response.action is PolicyAction.DENY:
            print(
                f"[AgentShield dry-run] WOULD BLOCK: "
                f"{context.tool_name} — {response.reason}"
            )

        if self.mode == "enforce" and response.action is PolicyAction.ESCALATE:
            if self._hitl is not None:
                approval = await self._hitl.request_approval(context, response)
                if not approval.approved:
                    denied = PolicyResponse(
                        action=PolicyAction.DENY,
                        rule_name=response.rule_name,
                        reason=f"Denied by reviewer ({approval.reviewer}): "
                        f"{response.reason}",
                        owasp_id=response.owasp_id,
                    )
                    await self._log_evaluation(context, denied)
                    raise ToolCallBlocked(denied)
            else:
                logger.warning(
                    "Rule %r escalated but no HITL gateway configured — "
                    "allowing action (add 'hitl' section to agentshield.yaml "
                    "to enable human-in-the-loop approval)",
                    response.rule_name,
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

    @property
    def audit_logger(self) -> Any:
        """The :class:`~agentshield.audit.logger.AuditLogger`, or *None*."""
        return self._audit

    @property
    def hitl_gateway(self) -> Any:
        """The :class:`~agentshield.hitl.gateway.HITLGateway`, or *None*."""
        return self._hitl

    @property
    def dashboard(self) -> Any:
        """The :class:`~agentshield.dashboard.app.DashboardApp`, or *None*."""
        return self._dashboard

    def __repr__(self) -> str:
        parts = [
            f"mode={self.mode!r}",
            f"rules={len(self._engine.rules)}",
        ]
        if self.log_file is not None:
            parts.append(f"log_file={str(self.log_file)!r}")
        if self._hitl is not None:
            parts.append("hitl=enabled")
        if self.dashboard_port is not None:
            parts.append(f"dashboard_port={self.dashboard_port}")
        return f"<Shield {' '.join(parts)}>"

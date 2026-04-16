"""AgentShield Dashboard — Real-time monitoring web UI.

Provides a FastAPI-backed single-page dashboard with Server-Sent Events
for live streaming of audit events.  FastAPI and uvicorn are **optional**
dependencies — imported lazily so the rest of AgentShield works without them.
"""
from __future__ import annotations

import asyncio
import json
import logging
import threading
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def _require_fastapi() -> Any:
    """Lazy-import FastAPI, raising a helpful error when missing."""
    try:
        import fastapi  # noqa: F811
        return fastapi
    except ImportError:
        raise ImportError(
            "The AgentShield dashboard requires FastAPI and uvicorn. "
            "Install them with:  pip install agentshield[dashboard]  "
            "or:  pip install fastapi uvicorn"
        ) from None


def _require_uvicorn() -> Any:
    """Lazy-import uvicorn, raising a helpful error when missing."""
    try:
        import uvicorn
        return uvicorn
    except ImportError:
        raise ImportError(
            "The AgentShield dashboard requires uvicorn. "
            "Install it with:  pip install agentshield[dashboard]  "
            "or:  pip install uvicorn"
        ) from None


class DashboardApp:
    """Self-contained dashboard server for AgentShield.

    Args:
        audit_log_file: Path to the JSONL audit log to read/stream.
        port: TCP port the HTTP server listens on.
    """

    def __init__(
        self,
        audit_log_file: str | Path = "./shield.jsonl",
        port: int = 9090,
    ) -> None:
        self._log_file = Path(audit_log_file)
        self._port = port
        self._app: Any = None
        self._events: list[dict] = []
        self._subscribers: list[asyncio.Queue[dict]] = []
        self._lock = threading.Lock()
        self._load_existing_events()

    def _load_existing_events(self) -> None:
        """Pre-load events from the existing audit log file."""
        if not self._log_file.exists():
            return
        try:
            with self._log_file.open("r", encoding="utf-8") as fh:
                for raw in fh:
                    stripped = raw.strip()
                    if stripped:
                        self._events.append(json.loads(stripped))
        except (json.JSONDecodeError, OSError) as exc:
            log.warning("Could not pre-load audit log: %s", exc)

    def _create_app(self) -> Any:
        """Build and return the FastAPI application (lazy)."""
        if self._app is not None:
            return self._app

        fastapi = _require_fastapi()
        from agentshield.dashboard.routes import register_routes

        app = fastapi.FastAPI(
            title="AgentShield Dashboard",
            description="Real-time monitoring UI for AgentShield",
        )
        register_routes(app, self)
        self._app = app
        return app

    def push_event(self, event: dict) -> None:
        """Push a new event to all SSE subscribers.

        Thread-safe — called from the audit logger whenever a new entry
        is written.

        Args:
            event: A complete audit-log entry dict.
        """
        with self._lock:
            self._events.append(event)
            stale: list[asyncio.Queue[dict]] = []
            for q in self._subscribers:
                try:
                    q.put_nowait(event)
                except Exception:
                    stale.append(q)
            for q in stale:
                self._subscribers.remove(q)

    def subscribe(self) -> asyncio.Queue[dict]:
        """Create and return a new subscriber queue for SSE.

        Returns:
            An asyncio Queue that will receive pushed events.
        """
        q: asyncio.Queue[dict] = asyncio.Queue()
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[dict]) -> None:
        """Remove a subscriber queue.

        Args:
            q: The queue previously returned by :meth:`subscribe`.
        """
        with self._lock:
            try:
                self._subscribers.remove(q)
            except ValueError:
                pass

    @property
    def events(self) -> list[dict]:
        """Snapshot of all loaded events."""
        return list(self._events)

    @property
    def log_file(self) -> Path:
        """Path to the audit log file."""
        return self._log_file

    def start(self, background: bool = True) -> None:
        """Start the dashboard server.

        Args:
            background: When *True* (default), run in a daemon thread so
                the caller is not blocked.  When *False*, block until
                the server shuts down.
        """
        uvicorn = _require_uvicorn()
        app = self._create_app()

        config = uvicorn.Config(
            app,
            host="0.0.0.0",
            port=self._port,
            log_level="info",
        )
        server = uvicorn.Server(config)

        if background:
            thread = threading.Thread(target=server.run, daemon=True)
            thread.start()
            log.info("Dashboard started on http://localhost:%d", self._port)
        else:
            log.info("Dashboard starting on http://localhost:%d", self._port)
            server.run()

"""API route handlers for the AgentShield Dashboard.

Separated from :mod:`app` to keep the FastAPI dependency isolated
and the route logic testable.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from fastapi import FastAPI
    from agentshield.dashboard.app import DashboardApp


def _load_events_from_file(log_file: Path) -> list[dict]:
    """Read all events from the JSONL audit log on disk.

    Args:
        log_file: Path to the ``.jsonl`` file.

    Returns:
        List of parsed event dicts.
    """
    events: list[dict] = []
    if not log_file.exists():
        return events
    with log_file.open("r", encoding="utf-8") as fh:
        for raw in fh:
            stripped = raw.strip()
            if stripped:
                try:
                    events.append(json.loads(stripped))
                except json.JSONDecodeError:
                    continue
    return events


def _compute_stats(events: list[dict]) -> dict[str, Any]:
    """Compute aggregate statistics from a list of events.

    Args:
        events: List of audit-log entry dicts.

    Returns:
        Dictionary of computed statistics.
    """
    total = len(events)
    action_counts: Counter[str] = Counter()
    rule_counts: Counter[str] = Counter()
    tool_counts: Counter[str] = Counter()
    hourly_buckets: Counter[str] = Counter()

    for evt in events:
        action_counts[evt.get("action", "unknown")] += 1
        rule_counts[evt.get("rule_name", "unknown")] += 1
        tool_counts[evt.get("tool_name", "unknown")] += 1
        ts = evt.get("timestamp", "")
        if len(ts) >= 13:
            hourly_buckets[ts[:13]] += 1

    return {
        "total": total,
        "allowed": action_counts.get("allow", 0),
        "denied": action_counts.get("deny", 0),
        "escalated": action_counts.get("escalate", 0),
        "allow_pct": (
            round(action_counts.get("allow", 0) / total * 100, 1) if total else 0
        ),
        "deny_pct": (
            round(action_counts.get("deny", 0) / total * 100, 1) if total else 0
        ),
        "escalate_pct": (
            round(action_counts.get("escalate", 0) / total * 100, 1) if total else 0
        ),
        "top_rules": rule_counts.most_common(10),
        "top_tools": tool_counts.most_common(10),
        "timeline": sorted(hourly_buckets.items()),
    }


def register_routes(app: FastAPI, dashboard: DashboardApp) -> None:
    """Register all HTTP routes on the FastAPI application.

    Args:
        app: The FastAPI instance.
        dashboard: The parent :class:`DashboardApp` that manages state.
    """
    from fastapi import Query
    from fastapi.responses import (
        HTMLResponse,
        JSONResponse,
        StreamingResponse,
        Response,
    )

    _FRONTEND_PATH = Path(__file__).parent / "frontend" / "index.html"

    @app.get("/", response_class=HTMLResponse)
    async def serve_frontend() -> HTMLResponse:
        """Serve the single-page dashboard HTML."""
        html = _FRONTEND_PATH.read_text(encoding="utf-8")
        return HTMLResponse(content=html)

    @app.get("/api/events/stream")
    async def sse_stream() -> StreamingResponse:
        """Server-Sent Events stream for live event updates."""
        queue = dashboard.subscribe()

        async def event_generator() -> Any:
            try:
                while True:
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=30.0)
                        yield f"data: {json.dumps(event)}\n\n"
                    except asyncio.TimeoutError:
                        yield ": keepalive\n\n"
            except asyncio.CancelledError:
                pass
            finally:
                dashboard.unsubscribe(queue)

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    @app.get("/api/stats")
    async def get_stats() -> JSONResponse:
        """Return aggregated statistics from the audit log."""
        events = _load_events_from_file(dashboard.log_file)
        stats = _compute_stats(events)
        return JSONResponse(content=stats)

    @app.get("/api/audit")
    async def get_audit(
        limit: int = Query(100, ge=1, le=10000),
        offset: int = Query(0, ge=0),
    ) -> JSONResponse:
        """Return paginated audit log entries (newest first)."""
        events = _load_events_from_file(dashboard.log_file)
        events.reverse()
        page = events[offset : offset + limit]
        return JSONResponse(
            content={
                "total": len(events),
                "offset": offset,
                "limit": limit,
                "events": page,
            }
        )

    @app.get("/api/rules")
    async def get_rules() -> JSONResponse:
        """Return information about registered rules."""
        try:
            from agentshield.rules import ALL_RULE_CLASSES

            rules_info = []
            for cls in ALL_RULE_CLASSES:
                instance = cls()
                rules_info.append(
                    {
                        "name": instance.name,
                        "description": instance.description,
                        "priority": instance.priority,
                        "enabled": instance.enabled,
                        "owasp_id": instance.owasp_id or "",
                        "class": cls.__name__,
                    }
                )
            return JSONResponse(content={"rules": rules_info})
        except Exception as exc:
            return JSONResponse(
                content={"rules": [], "error": str(exc)},
                status_code=200,
            )

    @app.post("/approve/{event_id}")
    async def approve_event(event_id: str) -> JSONResponse:
        """Approve an escalated action.

        Args:
            event_id: The id of the escalated audit entry.
        """
        approval = {
            "event_id": event_id,
            "decision": "approved",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        dashboard.push_event(
            {
                "id": event_id,
                "action": "approved",
                "timestamp": approval["timestamp"],
                "tool_name": "",
                "rule_name": "manual_review",
                "reason": "Approved by operator via dashboard",
            }
        )
        return JSONResponse(content=approval)

    @app.post("/deny/{event_id}")
    async def deny_event(event_id: str) -> JSONResponse:
        """Deny an escalated action.

        Args:
            event_id: The id of the escalated audit entry.
        """
        denial = {
            "event_id": event_id,
            "decision": "denied",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        dashboard.push_event(
            {
                "id": event_id,
                "action": "denied",
                "timestamp": denial["timestamp"],
                "tool_name": "",
                "rule_name": "manual_review",
                "reason": "Denied by operator via dashboard",
            }
        )
        return JSONResponse(content=denial)

    @app.get("/api/export")
    async def export_audit(
        format: str = Query("csv", regex="^(csv|json)$"),
    ) -> Response:
        """Export the audit log as CSV or JSON.

        Args:
            format: ``"csv"`` or ``"json"``.
        """
        events = _load_events_from_file(dashboard.log_file)

        if format == "json":
            return Response(
                content=json.dumps(events, indent=2),
                media_type="application/json",
                headers={
                    "Content-Disposition": "attachment; filename=shield_audit.json"
                },
            )

        buf = io.StringIO()
        if events:
            columns = list(events[0].keys())
            writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            for evt in events:
                writer.writerow(evt)

        return Response(
            content=buf.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=shield_audit.csv"},
        )

"""Tests for the dashboard app (without starting a real server)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest import mock

import pytest

from agentshield.dashboard.app import DashboardApp


class TestDashboardApp:
    def test_init_no_log(self, tmp_path: Path):
        app = DashboardApp(audit_log_file=tmp_path / "missing.jsonl")
        assert app.events == []

    def test_init_loads_existing(self, tmp_path: Path):
        log = tmp_path / "audit.jsonl"
        log.write_text(
            json.dumps({"id": "1", "action": "allow"})
            + "\n"
            + json.dumps({"id": "2", "action": "deny"})
            + "\n",
            encoding="utf-8",
        )
        app = DashboardApp(audit_log_file=log)
        assert len(app.events) == 2

    def test_init_corrupt_log(self, tmp_path: Path):
        log = tmp_path / "bad.jsonl"
        log.write_text("not json\n", encoding="utf-8")
        app = DashboardApp(audit_log_file=log)
        assert app.events == []

    def test_push_event(self, tmp_path: Path):
        app = DashboardApp(audit_log_file=tmp_path / "a.jsonl")
        app.push_event({"id": "e1"})
        assert len(app.events) == 1

    def test_subscribe_unsubscribe(self, tmp_path: Path):
        app = DashboardApp(audit_log_file=tmp_path / "a.jsonl")
        q = app.subscribe()
        assert len(app._subscribers) == 1
        app.unsubscribe(q)
        assert len(app._subscribers) == 0
        app.unsubscribe(q)

    def test_push_event_to_subscriber(self, tmp_path: Path):
        app = DashboardApp(audit_log_file=tmp_path / "a.jsonl")
        q = app.subscribe()
        app.push_event({"id": "e1"})
        assert not q.empty()

    def test_log_file_property(self, tmp_path: Path):
        log = tmp_path / "test.jsonl"
        app = DashboardApp(audit_log_file=log)
        assert app.log_file == log

    def test_create_app_caches(self, tmp_path: Path):
        app = DashboardApp(audit_log_file=tmp_path / "a.jsonl")
        fa = app._create_app()
        assert fa is app._create_app()


class TestDashboardRoutes:
    @pytest.fixture
    def client(self, tmp_path: Path):
        from fastapi.testclient import TestClient

        log = tmp_path / "audit.jsonl"
        log.write_text(
            json.dumps(
                {
                    "id": "1",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "tool_name": "t",
                    "action": "allow",
                    "rule_name": "default",
                    "agent_id": "a",
                    "prev_hash": "genesis",
                    "entry_hash": "h1",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        app = DashboardApp(audit_log_file=log)
        return TestClient(app._create_app())

    def test_index(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "AgentShield" in resp.text

    def test_stats(self, client):
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data

    def test_audit(self, client):
        resp = client.get("/api/audit")
        assert resp.status_code == 200
        data = resp.json()
        assert "events" in data

    def test_rules(self, client):
        resp = client.get("/api/rules")
        assert resp.status_code == 200
        data = resp.json()
        assert "rules" in data

    def test_export_csv(self, client):
        resp = client.get("/api/export?format=csv")
        assert resp.status_code == 200

    def test_export_json(self, client):
        resp = client.get("/api/export?format=json")
        assert resp.status_code == 200

    def test_approve_event(self, client):
        resp = client.post("/approve/evt-123")
        assert resp.status_code == 200
        data = resp.json()
        assert data["event_id"] == "evt-123"
        assert data["decision"] == "approved"

    def test_deny_event(self, client):
        resp = client.post("/deny/evt-456")
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "denied"

    def test_audit_pagination(self, client):
        resp = client.get("/api/audit?limit=1&offset=0")
        assert resp.status_code == 200
        data = resp.json()
        assert data["limit"] == 1


class TestDashboardStaleSubscriber:
    def test_stale_subscriber_removed(self, tmp_path: Path):
        app = DashboardApp(audit_log_file=tmp_path / "a.jsonl")
        app.subscribe()
        q_full = asyncio.Queue(maxsize=1)
        with app._lock:
            app._subscribers.append(q_full)
        q_full.put_nowait({"dummy": True})
        app.push_event({"id": "overflow"})
        assert q_full not in app._subscribers


class TestDashboardMissingFastAPI:
    def test_require_fastapi_missing(self):
        with mock.patch.dict("sys.modules", {"fastapi": None}):
            from agentshield.dashboard.app import _require_fastapi

            with pytest.raises(ImportError, match="FastAPI"):
                _require_fastapi()

    def test_require_uvicorn_missing(self):
        with mock.patch.dict("sys.modules", {"uvicorn": None}):
            from agentshield.dashboard.app import _require_uvicorn

            with pytest.raises(ImportError, match="uvicorn"):
                _require_uvicorn()


class TestDashboardStart:
    def test_start_background(self, tmp_path: Path):
        app = DashboardApp(audit_log_file=tmp_path / "a.jsonl", port=19999)
        mock_server = mock.MagicMock()
        mock_config = mock.MagicMock()
        with mock.patch("uvicorn.Config", return_value=mock_config):
            with mock.patch("uvicorn.Server", return_value=mock_server):
                app.start(background=True)
        mock_server.run.assert_called_once()

    def test_start_foreground(self, tmp_path: Path):
        app = DashboardApp(audit_log_file=tmp_path / "a.jsonl", port=19998)
        mock_server = mock.MagicMock()
        mock_config = mock.MagicMock()
        with mock.patch("uvicorn.Config", return_value=mock_config):
            with mock.patch("uvicorn.Server", return_value=mock_server):
                app.start(background=False)
        mock_server.run.assert_called_once()


class TestDashboardRouteHelpers:
    def test_load_events_missing_file(self, tmp_path: Path):
        from agentshield.dashboard.routes import _load_events_from_file

        events = _load_events_from_file(tmp_path / "nope.jsonl")
        assert events == []

    def test_load_events_corrupt(self, tmp_path: Path):
        from agentshield.dashboard.routes import _load_events_from_file

        f = tmp_path / "bad.jsonl"
        f.write_text('{"ok": true}\nnot json\n{"ok": true}\n', encoding="utf-8")
        events = _load_events_from_file(f)
        assert len(events) == 2

    def test_compute_stats_empty(self):
        from agentshield.dashboard.routes import _compute_stats

        stats = _compute_stats([])
        assert stats["total"] == 0
        assert stats["allow_pct"] == 0

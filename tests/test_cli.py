"""Tests for the agentshield CLI module."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest import mock

import pytest

from agentshield.cli import (
    main,
    _load_events,
    _cmd_verify,
    _cmd_stats,
    _cmd_export,
    _cmd_version,
)


def _write_audit_log(path: Path, events: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for evt in events:
            fh.write(json.dumps(evt) + "\n")


@pytest.fixture
def sample_log(tmp_path: Path) -> Path:
    log = tmp_path / "audit.jsonl"
    events = [
        {
            "id": "e1",
            "timestamp": "2026-01-01T00:00:00Z",
            "tool_name": "execute_sql",
            "action": "allow",
            "rule_name": "default",
            "agent_id": "agent-1",
            "prev_hash": "genesis",
            "entry_hash": "abc123",
        },
        {
            "id": "e2",
            "timestamp": "2026-01-01T00:01:00Z",
            "tool_name": "shell",
            "action": "deny",
            "rule_name": "destructive_shell",
            "agent_id": "agent-1",
            "prev_hash": "abc123",
            "entry_hash": "def456",
        },
    ]
    _write_audit_log(log, events)
    return log


class TestLoadEvents:
    def test_loads_events(self, sample_log: Path):
        events = _load_events(sample_log)
        assert len(events) == 2
        assert events[0]["id"] == "e1"

    def test_skips_blank_lines(self, tmp_path: Path):
        log = tmp_path / "blank.jsonl"
        log.write_text('{"id":"a"}\n\n{"id":"b"}\n', encoding="utf-8")
        assert len(_load_events(log)) == 2


class TestCmdVersion:
    def test_prints_version(self, capsys):
        args = mock.MagicMock()
        ret = _cmd_version(args)
        assert ret == 0
        assert "agentshield" in capsys.readouterr().out


class TestCmdVerify:
    def test_missing_file(self, capsys):
        args = mock.MagicMock(log_file="nonexistent.jsonl")
        assert _cmd_verify(args) == 1
        assert "not found" in capsys.readouterr().err

    def test_valid_log(self, tmp_path: Path, capsys):
        from agentshield import Shield, ToolCallContext

        log = tmp_path / "v.jsonl"
        shield = Shield(rules=[], log_file=str(log))
        asyncio.run(shield.check(ToolCallContext(tool_name="t", arguments={})))
        args = mock.MagicMock(log_file=str(log))
        assert _cmd_verify(args) == 0
        assert "chain intact" in capsys.readouterr().out


class TestCmdStats:
    def test_missing_file(self, capsys):
        args = mock.MagicMock(log_file="nope.jsonl")
        assert _cmd_stats(args) == 1

    def test_empty_log(self, tmp_path: Path, capsys):
        log = tmp_path / "empty.jsonl"
        log.write_text("", encoding="utf-8")
        args = mock.MagicMock(log_file=str(log))
        assert _cmd_stats(args) == 0
        assert "empty" in capsys.readouterr().out

    def test_stats_output(self, sample_log: Path, capsys):
        args = mock.MagicMock(log_file=str(sample_log))
        assert _cmd_stats(args) == 0
        out = capsys.readouterr().out
        assert "Total events:" in out
        assert "Actions:" in out


class TestCmdExport:
    def test_missing_file(self, capsys):
        args = mock.MagicMock(log_file="nope.jsonl", format="csv", output=None)
        assert _cmd_export(args) == 1

    def test_csv_export(self, sample_log: Path, tmp_path: Path, capsys):
        out = tmp_path / "out.csv"
        args = mock.MagicMock(log_file=str(sample_log), format="csv", output=str(out))
        assert _cmd_export(args) == 0
        assert out.exists()
        assert "Exported 2" in capsys.readouterr().out

    def test_json_export(self, sample_log: Path, tmp_path: Path, capsys):
        out = tmp_path / "out.json"
        args = mock.MagicMock(log_file=str(sample_log), format="json", output=str(out))
        assert _cmd_export(args) == 0
        data = json.loads(out.read_text(encoding="utf-8"))
        assert len(data) == 2

    def test_csv_default_path(self, sample_log: Path, capsys):
        args = mock.MagicMock(log_file=str(sample_log), format="csv", output=None)
        assert _cmd_export(args) == 0

    def test_json_default_path(self, sample_log: Path, capsys):
        args = mock.MagicMock(log_file=str(sample_log), format="json", output=None)
        assert _cmd_export(args) == 0


class TestCmdExportUnsupported:
    def test_unsupported_format(self, sample_log: Path, capsys):
        args = mock.MagicMock(log_file=str(sample_log), format="xml", output=None)
        assert _cmd_export(args) == 1
        assert "unsupported" in capsys.readouterr().err


class TestCmdVerifyBrokenChain:
    def test_broken_chain(self, tmp_path: Path, capsys):
        from agentshield import Shield, ToolCallContext

        log = tmp_path / "audit.jsonl"
        shield = Shield(rules=[], log_file=str(log))
        asyncio.run(shield.check(ToolCallContext(tool_name="a", arguments={})))
        asyncio.run(shield.check(ToolCallContext(tool_name="b", arguments={})))

        lines = log.read_text(encoding="utf-8").strip().split("\n")
        entry = json.loads(lines[1])
        entry["entry_hash"] = "TAMPERED"
        lines[1] = json.dumps(entry)
        log.write_text("\n".join(lines) + "\n", encoding="utf-8")

        args = mock.MagicMock(log_file=str(log))
        assert _cmd_verify(args) == 1
        out = capsys.readouterr().out
        assert "FAIL" in out or "broken" in out.lower()


class TestCmdServe:
    def test_import_error(self, capsys):
        with mock.patch.dict("sys.modules", {"agentshield.dashboard": None}):
            from agentshield.cli import _cmd_serve

            args = mock.MagicMock(port=9090, log_file="./shield.jsonl")
            ret = _cmd_serve(args)
            assert ret == 1

    def test_serve_success(self, capsys):
        mock_dashboard_cls = mock.MagicMock()
        mock_dashboard_inst = mock.MagicMock()
        mock_dashboard_inst.start = mock.MagicMock()
        mock_dashboard_cls.return_value = mock_dashboard_inst

        with mock.patch.dict(
            "sys.modules",
            {"agentshield.dashboard": mock.MagicMock(DashboardApp=mock_dashboard_cls)},
        ):
            from agentshield.cli import _cmd_serve

            args = mock.MagicMock(port=9090, log_file="./shield.jsonl")
            ret = _cmd_serve(args)
            assert ret == 0
            mock_dashboard_inst.start.assert_called_once_with(background=False)

    def test_serve_keyboard_interrupt(self, capsys):
        mock_dashboard_cls = mock.MagicMock()
        mock_dashboard_inst = mock.MagicMock()
        mock_dashboard_inst.start = mock.MagicMock(side_effect=KeyboardInterrupt)
        mock_dashboard_cls.return_value = mock_dashboard_inst

        with mock.patch.dict(
            "sys.modules",
            {"agentshield.dashboard": mock.MagicMock(DashboardApp=mock_dashboard_cls)},
        ):
            from agentshield.cli import _cmd_serve

            args = mock.MagicMock(port=9090, log_file="./shield.jsonl")
            ret = _cmd_serve(args)
            assert ret == 0
            assert "stopped" in capsys.readouterr().out.lower()


class TestMainEntryPoint:
    def test_help(self):
        with pytest.raises(SystemExit) as exc:
            main(["--help"])
        assert exc.value.code == 0

    def test_no_command(self):
        with pytest.raises(SystemExit) as exc:
            main([])
        assert exc.value.code == 0

    def test_version(self):
        with pytest.raises(SystemExit) as exc:
            main(["version"])
        assert exc.value.code == 0

    def test_verify_via_main(self, tmp_path: Path):
        log = tmp_path / "v.jsonl"
        from agentshield import Shield, ToolCallContext

        shield = Shield(rules=[], log_file=str(log))
        asyncio.run(shield.check(ToolCallContext(tool_name="t", arguments={})))
        with pytest.raises(SystemExit) as exc:
            main(["verify", str(log)])
        assert exc.value.code == 0

    def test_stats_via_main(self, sample_log: Path):
        with pytest.raises(SystemExit) as exc:
            main(["stats", str(sample_log)])
        assert exc.value.code == 0

    def test_export_csv_via_main(self, sample_log: Path, tmp_path: Path):
        out = tmp_path / "export.csv"
        with pytest.raises(SystemExit) as exc:
            main(["export", str(sample_log), "-f", "csv", "-o", str(out)])
        assert exc.value.code == 0


class TestMainModule:
    def test_main_module(self):
        from agentshield.__main__ import main as _main  # noqa: F401

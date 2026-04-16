"""Tests for the audit exporters module."""

from __future__ import annotations

import json
from pathlib import Path

from agentshield.audit.exporters import export_to_csv


class TestExportToCsv:
    def test_export(self, tmp_path: Path):
        log = tmp_path / "audit.jsonl"
        log.write_text(
            json.dumps({"id": "1", "action": "allow", "tool_name": "t"})
            + "\n"
            + json.dumps({"id": "2", "action": "deny", "tool_name": "s"})
            + "\n",
            encoding="utf-8",
        )
        csv_out = tmp_path / "out.csv"
        count = export_to_csv(log, csv_out)
        assert count == 2
        content = csv_out.read_text(encoding="utf-8")
        assert "id" in content
        assert "allow" in content

    def test_empty_log(self, tmp_path: Path):
        log = tmp_path / "empty.jsonl"
        log.write_text("", encoding="utf-8")
        csv_out = tmp_path / "out.csv"
        count = export_to_csv(log, csv_out)
        assert count == 0

    def test_custom_columns(self, tmp_path: Path):
        log = tmp_path / "audit.jsonl"
        log.write_text(
            json.dumps({"id": "1", "action": "allow", "extra": "val"}) + "\n",
            encoding="utf-8",
        )
        csv_out = tmp_path / "out.csv"
        count = export_to_csv(log, csv_out, columns=["id", "action"])
        assert count == 1

    def test_creates_parent_dirs(self, tmp_path: Path):
        log = tmp_path / "audit.jsonl"
        log.write_text(json.dumps({"id": "1"}) + "\n", encoding="utf-8")
        csv_out = tmp_path / "sub" / "dir" / "out.csv"
        export_to_csv(log, csv_out)
        assert csv_out.exists()

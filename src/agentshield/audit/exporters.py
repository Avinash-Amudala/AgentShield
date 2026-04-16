"""CSV exporter for AgentShield audit logs.

Reads a JSONL audit log and writes a flat CSV file.  Stdlib only.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

_CSV_COLUMNS: list[str] = [
    "id",
    "timestamp",
    "tool_name",
    "arguments_hash",
    "agent_id",
    "session_id",
    "action",
    "rule_name",
    "reason",
    "owasp_id",
    "prev_hash",
    "entry_hash",
]


def export_to_csv(
    log_file: str | Path,
    csv_file: str | Path,
    *,
    columns: list[str] | None = None,
) -> int:
    """Export a JSONL audit log to CSV.

    Args:
        log_file: Path to the source ``.jsonl`` file.
        csv_file: Destination ``.csv`` path (created or overwritten).
        columns: Column names to include.  Defaults to the standard
            audit-entry fields when *None*.

    Returns:
        Number of rows written.
    """
    cols = columns or _CSV_COLUMNS
    log_path = Path(log_file)
    csv_path = Path(csv_file)

    rows_written = 0
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    with (
        log_path.open("r", encoding="utf-8") as src,
        csv_path.open("w", encoding="utf-8", newline="") as dst,
    ):
        writer = csv.DictWriter(dst, fieldnames=cols, extrasaction="ignore")
        writer.writeheader()

        for raw_line in src:
            stripped = raw_line.strip()
            if not stripped:
                continue
            entry = json.loads(stripped)
            writer.writerow(entry)
            rows_written += 1

    return rows_written

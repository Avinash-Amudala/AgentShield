"""AgentShield CLI — command-line interface for audit, export, and dashboard.

Uses only stdlib (argparse, json, pathlib) for the core commands.
The ``serve`` sub-command lazy-imports the dashboard module so FastAPI
and uvicorn are only required when actually starting the web UI.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Sequence


def _load_events(log_file: Path) -> list[dict]:
    """Read all JSONL entries from *log_file*.

    Args:
        log_file: Path to the ``.jsonl`` audit log.

    Returns:
        List of parsed dicts, one per log line.
    """
    events: list[dict] = []
    with log_file.open("r", encoding="utf-8") as fh:
        for raw in fh:
            stripped = raw.strip()
            if stripped:
                events.append(json.loads(stripped))
    return events


def _cmd_verify(args: argparse.Namespace) -> int:
    """Verify audit log hash-chain integrity.

    Args:
        args: Parsed CLI arguments containing ``log_file``.

    Returns:
        Exit code — 0 if valid, 1 if broken.
    """
    from agentshield.audit.verifier import AuditVerifier

    log_path = Path(args.log_file)
    if not log_path.exists():
        print(f"Error: file not found — {log_path}", file=sys.stderr)
        return 1

    result = AuditVerifier().verify(log_path)

    if result.valid:
        print(f"OK  {result.total_entries} entries verified — chain intact.")
        return 0

    print(
        f"FAIL  {len(result.broken_links)} broken link(s) in {result.total_entries} entries:"
    )
    for link in result.broken_links:
        print(f"  Line {link.line_number}: entry {link.entry_id}")
        print(f"    expected: {link.expected_hash}")
        print(f"    actual:   {link.actual_hash}")
    return 1


def _cmd_stats(args: argparse.Namespace) -> int:
    """Print statistics from the audit log.

    Args:
        args: Parsed CLI arguments containing ``log_file``.

    Returns:
        Exit code — always 0.
    """
    log_path = Path(args.log_file)
    if not log_path.exists():
        print(f"Error: file not found — {log_path}", file=sys.stderr)
        return 1

    events = _load_events(log_path)
    total = len(events)

    if total == 0:
        print("Audit log is empty.")
        return 0

    actions: Counter[str] = Counter()
    rules: Counter[str] = Counter()
    tools: Counter[str] = Counter()
    agents: Counter[str] = Counter()

    for evt in events:
        actions[evt.get("action", "unknown")] += 1
        rules[evt.get("rule_name", "unknown")] += 1
        tools[evt.get("tool_name", "unknown")] += 1
        agents[evt.get("agent_id", "unknown")] += 1

    print("\n  AgentShield Audit Statistics")
    print(f"  {'=' * 40}")
    print(f"  Total events:  {total}")
    print()
    print("  Actions:")
    for action, count in actions.most_common():
        pct = count / total * 100
        bar = "#" * int(pct / 2)
        print(f"    {action:10s}  {count:>6,}  ({pct:5.1f}%)  {bar}")
    print()
    print("  Top rules (by trigger count):")
    for name, count in rules.most_common(10):
        print(f"    {name:30s}  {count:>6,}")
    print()
    print("  Top tools:")
    for name, count in tools.most_common(10):
        print(f"    {name:30s}  {count:>6,}")
    print()
    print(f"  Agents: {', '.join(f'{a} ({c})' for a, c in agents.most_common())}")

    first_ts = events[0].get("timestamp", "?")
    last_ts = events[-1].get("timestamp", "?")
    print(f"  Time range: {first_ts}  ->  {last_ts}")
    print()

    return 0


def _cmd_export(args: argparse.Namespace) -> int:
    """Export audit log to CSV or JSON.

    Args:
        args: Parsed CLI arguments with ``log_file``, ``format``, ``output``.

    Returns:
        Exit code — 0 on success.
    """
    log_path = Path(args.log_file)
    if not log_path.exists():
        print(f"Error: file not found — {log_path}", file=sys.stderr)
        return 1

    events = _load_events(log_path)

    if args.format == "csv":
        out_path = Path(args.output) if args.output else log_path.with_suffix(".csv")
        out_path.parent.mkdir(parents=True, exist_ok=True)

        if events:
            columns = list(events[0].keys())
            with out_path.open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
                writer.writeheader()
                for evt in events:
                    writer.writerow(evt)

        print(f"Exported {len(events)} events to {out_path}")

    elif args.format == "json":
        out_path = Path(args.output) if args.output else log_path.with_suffix(".json")
        out_path.parent.mkdir(parents=True, exist_ok=True)

        with out_path.open("w", encoding="utf-8") as fh:
            json.dump(events, fh, indent=2)

        print(f"Exported {len(events)} events to {out_path}")

    else:
        print(f"Error: unsupported format — {args.format}", file=sys.stderr)
        return 1

    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    """Start the dashboard web server.

    Args:
        args: Parsed CLI arguments with ``port`` and ``log_file``.

    Returns:
        Exit code — 0 (blocks until interrupted).
    """
    try:
        from agentshield.dashboard import DashboardApp
    except ImportError:
        print(
            "Error: The dashboard requires FastAPI and uvicorn.\n"
            "Install with:  pip install agentshield[dashboard]  "
            "or:  pip install fastapi uvicorn",
            file=sys.stderr,
        )
        return 1

    dashboard = DashboardApp(
        audit_log_file=args.log_file,
        port=args.port,
    )
    print(f"Starting AgentShield Dashboard on http://localhost:{args.port}")
    print(f"Audit log: {args.log_file}")
    print("Press Ctrl+C to stop.\n")

    try:
        dashboard.start(background=False)
    except KeyboardInterrupt:
        print("\nDashboard stopped.")

    return 0


def _cmd_version(_args: argparse.Namespace) -> int:
    """Print the installed version.

    Args:
        _args: Unused parsed arguments.

    Returns:
        Exit code — always 0.
    """
    from agentshield import __version__

    print(f"agentshield {__version__}")
    return 0


def main(argv: Sequence[str] | None = None) -> None:
    """Entry point for the ``agentshield`` CLI.

    Args:
        argv: Command-line arguments (defaults to ``sys.argv[1:]``).
    """
    parser = argparse.ArgumentParser(
        prog="agentshield",
        description="AgentShield \u2014 The runtime firewall for AI agents",
    )
    subparsers = parser.add_subparsers(dest="command")

    # --- verify ---
    verify_p = subparsers.add_parser(
        "verify",
        help="Verify audit log hash-chain integrity",
    )
    verify_p.add_argument("log_file", help="Path to the JSONL audit log")

    # --- stats ---
    stats_p = subparsers.add_parser(
        "stats",
        help="Print audit log statistics",
    )
    stats_p.add_argument("log_file", help="Path to the JSONL audit log")

    # --- export ---
    export_p = subparsers.add_parser(
        "export",
        help="Export audit log to CSV or JSON",
    )
    export_p.add_argument("log_file", help="Path to the JSONL audit log")
    export_p.add_argument(
        "--format",
        "-f",
        choices=["csv", "json"],
        default="csv",
        help="Output format (default: csv)",
    )
    export_p.add_argument(
        "--output",
        "-o",
        default=None,
        help="Output file path (default: <log_file>.<format>)",
    )

    # --- serve ---
    serve_p = subparsers.add_parser(
        "serve",
        help="Start the real-time monitoring dashboard",
    )
    serve_p.add_argument(
        "--port",
        "-p",
        type=int,
        default=9090,
        help="Port to listen on (default: 9090)",
    )
    serve_p.add_argument(
        "--log-file",
        "-l",
        default="./shield.jsonl",
        help="Path to the JSONL audit log (default: ./shield.jsonl)",
    )

    # --- version ---
    subparsers.add_parser("version", help="Print installed version")

    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    handlers: dict[str, object] = {
        "verify": _cmd_verify,
        "stats": _cmd_stats,
        "export": _cmd_export,
        "serve": _cmd_serve,
        "version": _cmd_version,
    }

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    sys.exit(handler(args))


if __name__ == "__main__":
    main()

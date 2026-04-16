"""Hash-chained JSONL audit logger for AgentShield.

Provides append-only, tamper-evident logging of every policy decision.
Each entry is hash-chained to its predecessor so any modification or
deletion is detectable by :class:`AuditVerifier`.

**Stdlib only** — no third-party dependencies.
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from agentshield.core.context import ToolCallContext
from agentshield.core.result import PolicyResponse

log = logging.getLogger(__name__)

_GENESIS = "genesis"


class AuditLogger:
    """Append-only, hash-chained JSONL audit logger.

    Every log entry contains a SHA-256 hash computed from the canonical
    JSON representation of the entry (sorted keys, no whitespace) plus
    the previous entry's hash.  The first entry chains from the sentinel
    value ``"genesis"``.

    Arguments supplied to tool calls are **never** stored raw — only
    their SHA-256 digest is recorded to prevent leaking sensitive data.

    Args:
        log_file: Path to the ``.jsonl`` file.  Created on first write.
    """

    def __init__(self, log_file: str | Path = "./shield.jsonl") -> None:
        self._log_file = Path(log_file)
        self._prev_hash: str = _GENESIS
        self._lock = threading.Lock()
        self._load_last_hash()

    def _load_last_hash(self) -> None:
        """Resume the hash chain from the last entry in an existing log."""
        if not self._log_file.exists():
            return
        try:
            last_line = ""
            with self._log_file.open("r", encoding="utf-8") as fh:
                for line in fh:
                    stripped = line.strip()
                    if stripped:
                        last_line = stripped
            if last_line:
                entry = json.loads(last_line)
                self._prev_hash = entry.get("entry_hash", _GENESIS)
        except (json.JSONDecodeError, OSError) as exc:
            log.warning("Could not resume hash chain: %s", exc)

    @staticmethod
    def _hash_arguments(arguments: dict) -> str:
        """Return ``sha256:<hex>`` digest of canonical JSON arguments."""
        canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return f"sha256:{digest}"

    @staticmethod
    def _compute_hash(entry: dict, prev_hash: str) -> str:
        """Compute the chain hash for *entry*.

        The hash covers the canonical JSON of all fields **except**
        ``entry_hash`` itself, concatenated with *prev_hash*.
        """
        hashable = {k: v for k, v in entry.items() if k != "entry_hash"}
        canonical = json.dumps(hashable, sort_keys=True, separators=(",", ":"))
        payload = canonical + prev_hash
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return f"sha256:{digest}"

    def _build_entry(
        self,
        context: ToolCallContext,
        response: PolicyResponse,
    ) -> dict:
        """Construct a log-entry dict and compute its chain hash."""
        entry: dict = {
            "id": str(uuid4()),
            "timestamp": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ"
            ),
            "tool_name": context.tool_name,
            "arguments_hash": self._hash_arguments(context.arguments),
            "agent_id": context.agent_id,
            "session_id": context.session_id,
            "action": response.action.value,
            "rule_name": response.rule_name,
            "reason": response.reason,
            "owasp_id": response.owasp_id or "",
            "prev_hash": self._prev_hash,
        }
        entry["entry_hash"] = self._compute_hash(entry, self._prev_hash)
        return entry

    def _append(self, entry: dict) -> None:
        """Write *entry* as a single JSONL line (thread-safe, append-only)."""
        line = json.dumps(entry, separators=(",", ":")) + "\n"
        self._log_file.parent.mkdir(parents=True, exist_ok=True)
        with self._log_file.open("a", encoding="utf-8") as fh:
            fh.write(line)
        self._prev_hash = entry["entry_hash"]

    async def log(
        self,
        context: ToolCallContext,
        response: PolicyResponse,
    ) -> dict:
        """Create a chained audit entry and append it to the log file.

        This is the async interface; the actual I/O is delegated to
        :meth:`log_sync` under a lock so the hash chain stays consistent.

        Args:
            context: The tool-call context snapshot.
            response: The policy evaluation result.

        Returns:
            The complete log-entry dict (including computed hashes).
        """
        return self.log_sync(context, response)

    def log_sync(
        self,
        context: ToolCallContext,
        response: PolicyResponse,
    ) -> dict:
        """Synchronous version of :meth:`log`.

        Thread-safe — only one thread can build + append at a time so
        the hash chain is never corrupted by concurrent writes.

        Args:
            context: The tool-call context snapshot.
            response: The policy evaluation result.

        Returns:
            The complete log-entry dict (including computed hashes).
        """
        with self._lock:
            entry = self._build_entry(context, response)
            self._append(entry)
            log.debug("Audit entry %s written", entry["id"])
            return entry

"""Audit-log chain integrity verifier for AgentShield.

Walks a JSONL audit log produced by :class:`AuditLogger` and
recomputes every hash to detect tampering or corruption.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class BrokenLink:
    """A single entry whose recomputed hash does not match the stored one.

    Attributes:
        line_number: 1-based line number in the JSONL file.
        entry_id: The ``id`` field of the entry.
        expected_hash: Hash recomputed from the entry contents + chain.
        actual_hash: Hash that was stored in the entry.
    """

    line_number: int
    entry_id: str
    expected_hash: str
    actual_hash: str


@dataclass
class VerificationResult:
    """Outcome of a full chain verification.

    Attributes:
        valid: ``True`` when every entry's hash matches and the chain
            is unbroken.
        total_entries: Number of entries inspected.
        broken_links: Details of each entry that failed verification.
    """

    valid: bool
    total_entries: int
    broken_links: list[BrokenLink] = field(default_factory=list)


class AuditVerifier:
    """Verifies the integrity of a hash-chained JSONL audit log.

    Usage::

        result = AuditVerifier().verify("shield.jsonl")
        if not result.valid:
            for link in result.broken_links:
                print(f"Line {link.line_number}: chain broken")
    """

    @staticmethod
    def _compute_hash(entry: dict, prev_hash: str) -> str:
        """Recompute the expected chain hash for *entry*."""
        hashable = {k: v for k, v in entry.items() if k != "entry_hash"}
        canonical = json.dumps(hashable, sort_keys=True, separators=(",", ":"))
        payload = canonical + prev_hash
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return f"sha256:{digest}"

    def verify(self, log_file: str | Path) -> VerificationResult:
        """Walk every entry and validate the hash chain.

        Args:
            log_file: Path to the ``.jsonl`` audit log.

        Returns:
            A :class:`VerificationResult` summarising chain health.
        """
        path = Path(log_file)
        if not path.exists():
            return VerificationResult(valid=True, total_entries=0)

        broken: list[BrokenLink] = []
        prev_hash = "genesis"
        total = 0

        with path.open("r", encoding="utf-8") as fh:
            for line_no, raw_line in enumerate(fh, start=1):
                stripped = raw_line.strip()
                if not stripped:
                    continue
                total += 1
                entry = json.loads(stripped)

                stored_prev = entry.get("prev_hash", "")
                if stored_prev != prev_hash:
                    broken.append(
                        BrokenLink(
                            line_number=line_no,
                            entry_id=entry.get("id", ""),
                            expected_hash=f"prev_hash should be {prev_hash}",
                            actual_hash=stored_prev,
                        )
                    )

                expected = self._compute_hash(entry, prev_hash)
                actual = entry.get("entry_hash", "")
                if expected != actual:
                    broken.append(
                        BrokenLink(
                            line_number=line_no,
                            entry_id=entry.get("id", ""),
                            expected_hash=expected,
                            actual_hash=actual,
                        )
                    )

                prev_hash = entry.get("entry_hash", "")

        return VerificationResult(
            valid=len(broken) == 0,
            total_entries=total,
            broken_links=broken,
        )

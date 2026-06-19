"""Policy file integrity checking (ADR-0026).

Computes the SHA-256 of the loaded policy YAML and records it in the audit DB.
On subsequent startups the gateway compares the current hash to the stored one
and warns if the file changed — catching silent offline policy tampering.

This module is pure core (no intelligence imports).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class PolicyIntegrityStatus(StrEnum):
    NEW = "new"          # first sighting — hash recorded
    UNCHANGED = "unchanged"  # file matches the stored hash
    CHANGED = "changed"  # file was modified since last run (tamper signal)


@dataclass(frozen=True, slots=True)
class PolicyCheckResult:
    path: str
    status: PolicyIntegrityStatus
    stored_hash: str | None   # what the DB had (None on first run)
    current_hash: str         # what the file hashes to right now


def compute_file_hash(path: str | Path) -> str:
    """SHA-256 hex digest of the file contents at *path*."""
    data = Path(path).read_bytes()
    return hashlib.sha256(data).hexdigest()

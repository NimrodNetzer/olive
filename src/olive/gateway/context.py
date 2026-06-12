"""SecurityContext - the object every enforcement decision reasons about.

One frozen context is built per inspected message (outbound tool call or
inbound tool response). Raw arguments never enter the context: only their
SHA-256 hash (CLAUDE.md rule 3).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

Direction = Literal["outbound", "inbound"]
TrustLevel = Literal["trusted", "untrusted"]


def hash_arguments(arguments: dict[str, Any] | None) -> str:
    """Canonical SHA-256 of tool arguments. The raw values are never stored."""
    canonical = json.dumps(arguments or {}, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class SecurityContext:
    agent_id: str
    session_id: str
    organization_id: str
    role: str
    declared_goal: str
    tool: str
    arguments_hash: str
    direction: Direction
    call_number: int
    session_tool_history: tuple[str, ...]
    source_trust: TrustLevel
    timestamp: str

    @staticmethod
    def now() -> str:
        return datetime.now(UTC).isoformat()

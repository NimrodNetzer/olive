"""Per-session state - the unit the circuit breaker contains (ADR-0006).

Pure data, no I/O and no locking: the CircuitBreaker is the single authority
that mutates these objects under its lock. Keeping this module free of store
and intelligence imports preserves the layering rule (ADR-0003).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from time import monotonic

from olive.gateway.context import SecurityContext


class SessionStatus(StrEnum):
    ACTIVE = "active"
    QUARANTINED = "quarantined"


@dataclass(slots=True)
class SessionState:
    session_id: str
    status: SessionStatus = SessionStatus.ACTIVE
    call_number: int = 0
    tool_history: list[str] = field(default_factory=list)
    block_count: int = 0
    first_seen: str = field(default_factory=SecurityContext.now)
    last_seen: str = field(default_factory=SecurityContext.now)
    # Monotonic clock of last activity, used only for idle eviction math
    # (last_seen is the human-readable ISO timestamp for reporting).
    last_active: float = field(default_factory=monotonic)
    quarantine_reason: str | None = None
    # The incident that tripped the breaker; later quarantined calls reference
    # it instead of each minting a new incident (ADR-0006, CLAUDE.md rule 5).
    quarantine_incident_id: str | None = None
    # The most recently seen JWT token ID (jti) for this session. Updated on
    # each authenticated request so that when a session is quarantined or SIEGE
    # is declared the live token can be revoked immediately (M11). Empty for
    # stdio/unverified sessions.
    current_jti: str = ""

    @property
    def quarantined(self) -> bool:
        return self.status is SessionStatus.QUARANTINED

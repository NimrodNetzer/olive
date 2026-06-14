"""Circuit breaker - deterministic session containment (ADR-0006).

This is the single concurrency authority over session state. It owns the
in-memory session map and one lock, so advancing a call and deciding whether
to trip happen atomically together. Enforcement here is pure deterministic
code: the M6 sentinels will *signal* `trip()`, but never make the decision
themselves (ADR-0005).

No store/intelligence imports (ADR-0003): the breaker returns plain values and
the proxy does the logging.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from time import monotonic

from olive.gateway.context import SecurityContext
from olive.gateway.session import SessionState, SessionStatus


@dataclass(frozen=True, slots=True)
class CallTicket:
    """Snapshot handed to the proxy at the start of a call.

    A quarantined session is reported but NOT advanced: its call number and
    history do not move, because the call will be denied before any work.
    """

    call_number: int
    history: tuple[str, ...]
    quarantined: bool
    reason: str | None = None
    incident_id: str | None = None


class CircuitBreaker:
    def __init__(
        self,
        max_blocks: int = 3,
        idle_ttl_seconds: float = 1800.0,
        sweep_interval_seconds: float = 300.0,
    ) -> None:
        if max_blocks < 1:
            raise ValueError("max_blocks must be >= 1")
        self._max_blocks = max_blocks
        self._idle_ttl = idle_ttl_seconds
        self._sweep_interval = sweep_interval_seconds
        self._last_sweep = monotonic()
        self._sessions: dict[str, SessionState] = {}
        self._lock = asyncio.Lock()

    def _get(self, session_id: str) -> SessionState:
        state = self._sessions.get(session_id)
        if state is None:
            state = SessionState(session_id=session_id)
            self._sessions[session_id] = state
        return state

    def _touch(self, state: SessionState) -> None:
        state.last_seen = SecurityContext.now()
        state.last_active = monotonic()

    def _sweep_locked(self, now: float) -> int:
        """Drop ACTIVE sessions idle past the TTL. Quarantined sessions are
        NEVER evicted: losing that state would let an attacker clear a
        quarantine just by going idle. Caller must hold the lock."""
        stale = [
            sid
            for sid, st in self._sessions.items()
            if not st.quarantined and (now - st.last_active) > self._idle_ttl
        ]
        for sid in stale:
            del self._sessions[sid]
        return len(stale)

    async def begin_call(self, session_id: str) -> CallTicket:
        """Open a call. Quarantined sessions return a denial ticket and are
        left untouched; active sessions get the next call number + a history
        snapshot, atomically."""
        async with self._lock:
            now = monotonic()
            if now - self._last_sweep > self._sweep_interval:
                self._sweep_locked(now)
                self._last_sweep = now
            state = self._get(session_id)
            self._touch(state)
            if state.quarantined:
                return CallTicket(
                    call_number=state.call_number,
                    history=tuple(state.tool_history),
                    quarantined=True,
                    reason=state.quarantine_reason,
                    incident_id=state.quarantine_incident_id,
                )
            state.call_number += 1
            return CallTicket(
                call_number=state.call_number,
                history=tuple(state.tool_history),
                quarantined=False,
            )

    async def record_allowed_call(self, session_id: str, tool: str) -> None:
        """Append a tool to the session's history after it was allowed outbound."""
        async with self._lock:
            state = self._get(session_id)
            state.tool_history.append(tool)
            self._touch(state)

    async def record_block(self, session_id: str, incident_id: str | None) -> bool:
        """Count a block; trip the breaker at the threshold. Returns True only
        on the call that causes the trip (so the proxy can act once)."""
        async with self._lock:
            state = self._get(session_id)
            self._touch(state)
            if state.quarantined:
                return False
            state.block_count += 1
            if state.block_count >= self._max_blocks:
                state.status = SessionStatus.QUARANTINED
                state.quarantine_reason = (
                    f"{state.block_count} blocked calls reached the "
                    f"containment threshold ({self._max_blocks})"
                )
                state.quarantine_incident_id = incident_id
                return True
            return False

    async def trip(self, session_id: str, reason: str, incident_id: str | None = None) -> bool:
        """Force a session into quarantine (the M6 sentinel-signal entry point).
        Returns True if this call changed the state."""
        async with self._lock:
            state = self._get(session_id)
            self._touch(state)
            if state.quarantined:
                return False
            state.status = SessionStatus.QUARANTINED
            state.quarantine_reason = reason
            state.quarantine_incident_id = incident_id
            return True

    async def release(self, session_id: str) -> bool:
        """Reversible human release. Returns True if a quarantine was lifted."""
        async with self._lock:
            state = self._sessions.get(session_id)
            if state is None or not state.quarantined:
                return False
            state.status = SessionStatus.ACTIVE
            state.block_count = 0
            state.quarantine_reason = None
            state.quarantine_incident_id = None
            self._touch(state)
            return True

    async def status(self, session_id: str) -> SessionStatus:
        async with self._lock:
            state = self._sessions.get(session_id)
            return state.status if state is not None else SessionStatus.ACTIVE

    async def evict_idle(self, now: float | None = None) -> int:
        """Evict active sessions idle past the TTL; returns how many were
        removed. Quarantined sessions are kept. Safe to call explicitly (e.g.
        from a periodic task); begin_call also sweeps opportunistically."""
        async with self._lock:
            return self._sweep_locked(monotonic() if now is None else now)

    def snapshot(self, session_id: str) -> SessionState | None:
        """Read-only peek for reporting/tests. Not for enforcement paths."""
        return self._sessions.get(session_id)

    def session_count(self) -> int:
        """Number of tracked sessions (for reporting/tests)."""
        return len(self._sessions)

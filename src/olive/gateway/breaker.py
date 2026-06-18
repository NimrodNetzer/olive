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
from olive.gateway.mode import OperatingMode
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
        # Fleet-wide enforcement posture (ADR-0014). Owned here behind the same
        # lock as session state; the deterministic Commander is the only caller
        # of set_mode, just as SentinelRunner is the only caller of trip.
        self._mode = OperatingMode.NORMAL

    def _effective_max_blocks(self) -> int:
        """Mode-aware containment threshold (deterministic). Tighter posture
        quarantines sooner: suspicious halves the budget, siege trips on the
        first block. Never below 1."""
        if self._mode is OperatingMode.SIEGE:
            return 1
        if self._mode is OperatingMode.SUSPICIOUS:
            return max(1, (self._max_blocks + 1) // 2)
        return self._max_blocks

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
            threshold = self._effective_max_blocks()
            if state.block_count >= threshold:
                state.status = SessionStatus.QUARANTINED
                state.quarantine_reason = (
                    f"{state.block_count} blocked calls reached the "
                    f"containment threshold ({threshold}, mode={self._mode})"
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

    async def set_mode(
        self, mode: OperatingMode, reason: str, incident_id: str | None = None
    ) -> bool:
        """Set the fleet-wide operating posture (ADR-0014) - the second inward
        seam crossing, the same shape as `trip`. The deterministic Commander is
        the only caller. Returns True if the mode actually changed (so the caller
        audits exactly once). `reason`/`incident_id` are for the caller's audit
        row; the breaker itself stays log-free (ADR-0003)."""
        async with self._lock:
            if self._mode is mode:
                return False
            self._mode = mode
            return True

    async def mode(self) -> OperatingMode:
        async with self._lock:
            return self._mode

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

    def quarantined_count(self) -> int:
        """Number of currently quarantined sessions (for Siege crisis reporting)."""
        return sum(1 for s in self._sessions.values() if s.quarantined)

    def restore(
        self,
        session_key: str,
        block_count: int,
        quarantined: bool,
        reason: str | None,
        incident_id: str | None,
    ) -> None:
        """Restore a persisted session from the store on gateway startup.
        Must be called before the event loop begins processing requests."""
        state = SessionState(session_id=session_key)
        state.block_count = block_count
        if quarantined:
            state.status = SessionStatus.QUARANTINED
            state.quarantine_reason = reason
            state.quarantine_incident_id = incident_id
        self._sessions[session_key] = state

    def restore_mode(self, mode: OperatingMode) -> None:
        """Restore operating mode from persistent state on startup.
        Must be called before the event loop begins processing requests."""
        self._mode = mode

    async def record_jti(self, session_id: str, jti: str) -> None:
        """Track the most recently seen JWT token ID for this session.
        Called on every authenticated request so that if the session is
        quarantined or SIEGE is declared the live token can be revoked."""
        if not jti:
            return
        async with self._lock:
            state = self._get(session_id)
            state.current_jti = jti

    def quarantined_jtis(self) -> dict[str, str]:
        """Return {session_id: jti} for every quarantined session that has a
        non-empty jti. Used by the Commander to bulk-revoke tokens on SIEGE."""
        return {
            sid: st.current_jti
            for sid, st in self._sessions.items()
            if st.quarantined and st.current_jti
        }

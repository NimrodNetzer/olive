"""Per-session rate limiting - a deterministic sliding-window throttle.

A throttle is not an attack: exceeding the limit denies the single call but
does not create an incident and does not count toward the circuit breaker's
quarantine threshold (a chatty-but-legitimate agent must not be contained as
if it were hostile). The limit value comes from the role policy
(`max_calls_per_minute`); counting is per session key.

Its own lock, never held while the breaker's lock is held, so the two cannot
deadlock. No store/intelligence imports (ADR-0003).
"""

from __future__ import annotations

import asyncio
from collections import deque
from time import monotonic


class RateLimiter:
    def __init__(self, window_seconds: float = 60.0, sweep_interval_seconds: float = 300.0) -> None:
        self._window = window_seconds
        self._sweep_interval = sweep_interval_seconds
        self._last_sweep = monotonic()
        self._calls: dict[str, deque[float]] = {}
        self._lock = asyncio.Lock()

    def _sweep_locked(self, now: float) -> int:
        """Drop keys whose entire window has expired (no live calls), bounding
        memory under many short-lived sessions. Caller holds the lock."""
        cutoff = now - self._window
        empty = [k for k, w in self._calls.items() if not w or w[-1] <= cutoff]
        for k in empty:
            del self._calls[k]
        return len(empty)

    async def check_and_record(
        self, key: str, limit: int | None, now: float | None = None
    ) -> bool:
        """Return True and record the call if under `limit`; return False
        (recording nothing) if the window is already full. `limit=None` means
        unlimited. The limit is passed per call so one limiter can serve many
        roles, each with its own limit, keyed independently.

        A denied call is *not* recorded, so being over-limit does not keep
        extending the window - standard sliding-window behaviour.
        """
        if limit is None:
            return True
        if limit < 1:
            raise ValueError("limit must be >= 1 or None")
        ts = monotonic() if now is None else now
        async with self._lock:
            if ts - self._last_sweep > self._sweep_interval:
                self._sweep_locked(ts)
                self._last_sweep = ts
            window = self._calls.setdefault(key, deque())
            cutoff = ts - self._window
            while window and window[0] <= cutoff:
                window.popleft()
            if len(window) >= limit:
                return False
            window.append(ts)
            return True

    async def evict_idle(self, now: float | None = None) -> int:
        """Drop fully-expired keys; returns how many were removed."""
        async with self._lock:
            return self._sweep_locked(monotonic() if now is None else now)

    def key_count(self) -> int:
        return len(self._calls)

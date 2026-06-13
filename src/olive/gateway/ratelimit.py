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
    def __init__(self, max_per_minute: int | None, window_seconds: float = 60.0) -> None:
        if max_per_minute is not None and max_per_minute < 1:
            raise ValueError("max_per_minute must be >= 1 or None")
        self._max = max_per_minute
        self._window = window_seconds
        self._calls: dict[str, deque[float]] = {}
        self._lock = asyncio.Lock()

    @property
    def enabled(self) -> bool:
        return self._max is not None

    async def check_and_record(self, key: str, now: float | None = None) -> bool:
        """Return True and record the call if under the limit; return False
        (recording nothing) if the window is already full.

        A denied call is *not* recorded, so being over-limit does not keep
        extending the window - standard sliding-window behaviour.
        """
        if self._max is None:
            return True
        ts = monotonic() if now is None else now
        async with self._lock:
            window = self._calls.setdefault(key, deque())
            cutoff = ts - self._window
            while window and window[0] <= cutoff:
                window.popleft()
            if len(window) >= self._max:
                return False
            window.append(ts)
            return True

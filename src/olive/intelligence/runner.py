"""SentinelRunner - drains the telemetry queue, runs the advisory sentinels, and
asks the deterministic circuit breaker to quarantine when their aggregated
confidence crosses a threshold (ADR-0005, ADR-0012).

The runner is the *only* place a sentinel signal becomes an action, and even here
the action is a single call to `CircuitBreaker.trip` - pure deterministic code
with an explicit threshold. No sentinel output is interpolated into a policy or a
response to the agent. Every sentinel call is fail-safe: an exception becomes
Signal.none, never a crash and never a silent pass that looks like a clear.
"""

from __future__ import annotations

import asyncio
import contextlib

from olive.gateway.breaker import CircuitBreaker
from olive.gateway.pipeline import Decision, Verdict
from olive.gateway.session import SessionStatus
from olive.gateway.telemetry import TelemetryEvent
from olive.intelligence.reporter import IncidentReport, build_report
from olive.intelligence.sentinels import Sentinel
from olive.intelligence.signals import Signal


class SentinelRunner:
    def __init__(
        self,
        queue: asyncio.Queue[TelemetryEvent],
        breaker: CircuitBreaker,
        sentinels: list[Sentinel],
        *,
        threshold: float = 0.8,
        store: object | None = None,
        on_report=None,
    ) -> None:
        self._queue = queue
        self._breaker = breaker
        self._sentinels = list(sentinels)
        self._threshold = threshold
        self._store = store
        self._on_report = on_report
        self._task: asyncio.Task | None = None

    async def _run_sentinel(self, sentinel: Sentinel, event: TelemetryEvent) -> Signal:
        try:
            return await sentinel.analyze(event)
        except Exception:  # noqa: BLE001 - a broken sentinel must never crash the loop
            return Signal.none(sentinel.name)

    async def process(self, event: TelemetryEvent) -> IncidentReport | None:
        """Run every sentinel for this direction, aggregate, and quarantine if the
        threshold is crossed. Returns the incident report when it acts, else None.
        Unit-testable in isolation (the run loop just calls this)."""
        matching = [s for s in self._sentinels if event.ctx.direction in s.directions]
        signals = [await self._run_sentinel(s, event) for s in matching]
        fired = [s for s in signals if s.detected]
        if not fired:
            return None
        confidence = max(s.confidence for s in fired)
        if confidence < self._threshold:
            # Evidence exists but is below the action threshold: observed, not
            # enforced. (A future "suspicious mode" could lower the bar here.)
            return None

        # Already contained: don't write a duplicate incident or re-trip.
        if await self._breaker.status(event.session_key) is SessionStatus.QUARANTINED:
            return None

        attack_types = sorted({s.attack_type for s in fired})
        reason = (
            f"sentinel signals ({', '.join(attack_types)}) crossed the quarantine "
            f"threshold ({self._threshold})"
        )
        incident_id = await self._write_incident(event, fired, confidence, attack_types, reason)
        tripped = await self._breaker.trip(event.session_key, reason, incident_id)
        if tripped and self._store is not None:
            state = self._breaker.snapshot(event.session_key)
            if state is not None:
                try:
                    await self._store.persist_session(  # type: ignore[attr-defined]
                        event.session_key, state.block_count, state.quarantined,
                        state.quarantine_reason, state.quarantine_incident_id,
                    )
                except Exception:  # noqa: BLE001 - persistence must not block the trip
                    pass
        report = build_report(
            session_key=event.session_key,
            agent_id=event.ctx.agent_id,
            organization_id=event.ctx.organization_id,
            signals=fired,
            action="quarantine" if tripped else "observed",
            incident_id=incident_id,
        )
        if self._on_report is not None:
            self._on_report(report)
        return report

    async def _write_incident(
        self,
        event: TelemetryEvent,
        fired: list[Signal],
        confidence: float,
        attack_types: list[str],
        reason: str,
    ) -> str | None:
        if self._store is None:
            return None
        # The quarantine is the deterministic decision; the incident records it
        # with bounded evidence only (rule 3). detection_method marks the source.
        evidence = "; ".join(f"{s.sentinel}: {s.evidence}" for s in fired)[:200]
        verdict = Verdict(
            decision=Decision.QUARANTINE,
            rule="sentinel.quarantine",
            evidence=evidence,
            confidence=confidence,
        )
        try:
            return await self._store.create_incident(  # type: ignore[attr-defined]
                event.ctx,
                verdict,
                attack_type=attack_types[0] if attack_types else "unknown",
                detection_method="sentinel",
            )
        except Exception:  # noqa: BLE001 - audit-write failure must not block the trip
            return None

    async def _loop(self) -> None:
        while True:
            event = await self._queue.get()
            try:
                await self.process(event)
            finally:
                self._queue.task_done()

    def start(self) -> None:
        """Spawn the drain loop as a background task (composition root calls this
        once the event loop is running)."""
        if self._task is None:
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

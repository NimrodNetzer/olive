"""Telemetry seam - the gateway's one outbound channel to the parallel path.

This is the open-core boundary (ADR-0003): the gateway core publishes a
`TelemetryEvent` after a decision and never knows who, if anyone, consumes it.
The intelligence layer (`olive.intelligence`) drains the queue, runs advisory
sentinels, and signals back *only* through `CircuitBreaker.trip` (ADR-0005,
ADR-0012). The gateway never imports the intelligence layer.

Rule 3 (never log raw payloads) still holds: a `TelemetryEvent` may carry the
in-memory content/arguments a sentinel needs to *analyze*, but that raw data is
for in-process analysis only and is never written to the store. Sentinels emit
hashes + bounded evidence, exactly like the inline inspectors.

Publishing must never perturb the fast path: the default sink is a no-op, and the
queue sink drops on a full queue rather than block the gateway. Losing a
telemetry event degrades detection; blocking a tool call would be worse.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from olive.gateway.context import SecurityContext
from olive.gateway.pipeline import Verdict


@dataclass(frozen=True, slots=True)
class TelemetryEvent:
    """One inspected message handed to the parallel path. `content` (inbound
    response text) and `arguments` (outbound call arguments) are present only
    for in-memory sentinel analysis - never persisted (rule 3)."""

    ctx: SecurityContext
    verdict: Verdict
    content: str | None = None
    arguments: dict | None = None
    # The breaker's namespaced (org, agent, session) key, so the parallel path
    # can trip the exact same session the fast path contained (ADR-0006).
    session_key: str = ""


@runtime_checkable
class TelemetrySink(Protocol):
    async def publish(self, event: TelemetryEvent) -> None: ...


class NullSink:
    """Default sink: the gateway runs and enforces with the intelligence layer
    entirely absent. Zero overhead, no behaviour change."""

    async def publish(self, event: TelemetryEvent) -> None:  # noqa: D102
        return None


class QueueSink:
    """A bounded in-memory queue shared with the SentinelRunner. `publish` never
    blocks the fast path: if the queue is full the event is dropped (and counted)
    rather than applying backpressure to a live tool call."""

    def __init__(self, queue: asyncio.Queue[TelemetryEvent] | None = None, maxsize: int = 1024):
        self._queue: asyncio.Queue[TelemetryEvent] = queue or asyncio.Queue(maxsize=maxsize)
        self.dropped = 0

    @property
    def queue(self) -> asyncio.Queue[TelemetryEvent]:
        return self._queue

    async def publish(self, event: TelemetryEvent) -> None:
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self.dropped += 1

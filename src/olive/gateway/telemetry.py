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
import hashlib
import logging
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

_LOG = logging.getLogger(__name__)

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


class MultiSink:
    """Fan one telemetry event out to several sinks (ADR-0020). The gateway takes a
    single `telemetry=` sink, but `olive serve --ui` needs BOTH the SentinelRunner's
    `QueueSink` and the read-only `UIBroker` fed (ADR-0017 §2: the UI is registered
    *alongside*, never replacing, the configured sink).

    Each wrapped sink keeps its own drop/never-block contract: this wrapper must not
    let a slow or failing sink perturb the fast path, so a sink that raises is
    isolated (counted) and the remaining sinks are still published to. It imports
    nothing intelligence-side - the sinks are passed in as the `TelemetrySink`
    protocol, so the layering rule (ADR-0003) holds."""

    def __init__(self, *sinks: TelemetrySink) -> None:
        self._sinks = tuple(sinks)
        self.errors = 0  # observable: a sink that raised, never silently swallowed

    async def publish(self, event: TelemetryEvent) -> None:
        for sink in self._sinks:
            try:
                await sink.publish(event)
            except Exception:  # noqa: BLE001 - one broken sink must not stop the others or the fast path
                self.errors += 1


class WebhookSink:
    """Fire-and-forget HTTP POST of a bounded event summary to an operator-supplied URL.

    Rule 3 compliance: only hashes and metadata are sent — raw arguments, content,
    and evidence are never included in the outbound payload. Failures are logged and
    counted; the enforcement path is never blocked (ADR-0003 open-core seam)."""

    def __init__(self, url: str, token: str | None = None) -> None:
        self._url = url
        self._headers = {"Content-Type": "application/json"}
        if token:
            self._headers["Authorization"] = f"Bearer {token}"
        self._client: "httpx.AsyncClient | None" = None
        self.errors = 0

    def _get_client(self) -> "httpx.AsyncClient":
        if self._client is None:
            import httpx
            self._client = httpx.AsyncClient(timeout=5.0)
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def publish(self, event: TelemetryEvent) -> None:
        # Extract only the scalar fields _post needs before handing off to the
        # task — this unbinds content/arguments (raw payloads, in-process only)
        # from the task closure so they can be GC'd immediately (rule 3 intent).
        tool = event.ctx.tool
        decision = event.verdict.decision
        rule = event.verdict.rule
        evidence = event.verdict.evidence or ""
        # Hash session_key (org:agent:session) before leaving the process — the
        # raw triple may contain identity data (agent_id, org name) which must
        # not be sent to an operator-controlled external endpoint verbatim.
        session_hash = hashlib.sha256(event.session_key.encode()).hexdigest()
        asyncio.create_task(self._post(tool, decision, rule, evidence, session_hash))

    async def _post(
        self,
        tool: str,
        decision: str,
        rule: str,
        evidence: str,
        session_hash: str,
    ) -> None:
        import json
        from datetime import datetime, timezone

        payload = {
            "tool": tool,
            "decision": decision,
            "rule": rule,
            "evidence_hash": hashlib.sha256(evidence.encode()).hexdigest(),
            "session_hash": session_hash,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        try:
            client = self._get_client()
            resp = await client.post(self._url, content=json.dumps(payload).encode(), headers=self._headers)
            if resp.status_code >= 400:
                _LOG.warning("webhook POST returned %d", resp.status_code)
                self.errors += 1
        except Exception as exc:  # noqa: BLE001
            _LOG.debug("webhook POST failed: %s", exc)
            self.errors += 1

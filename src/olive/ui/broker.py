"""UIBroker - the read-only projection feeding the Agentic Command Center (ADR-0017).

`UIBroker` is a THIRD consumer of the two seams ADR-0012/0014 already sanctioned:

  - it implements `TelemetrySink` (gateway/telemetry.py), registered as an
    ADDITIONAL sink alongside whatever sink is already configured - never a
    replacement. Like `QueueSink`, it drops on a full queue rather than apply
    backpressure to the fast path.
  - it subscribes to the `IncidentBus` (intelligence/bus.py) for live fan-out.

Both inputs are projected into a single bounded `UIEvent` DTO. Rule 3 holds:
`UIEvent` carries only the already-bounded `Verdict.decision/rule/evidence`
(<=200 chars) and non-secret context/report fields - it has NO `content` or
`arguments` field, and this module never reads `TelemetryEvent.content`/
`arguments` (those exist only for in-memory sentinel analysis).

THIS MODULE IS READ-ONLY BY CONSTRUCTION (ADR-0017 SS2): it calls no breaker,
policy, mode, or Commander method, directly or indirectly, and DELIBERATELY does
not import `gateway.breaker`, `gateway.proxy`, or `intelligence.commander`. A
test asserts that import set.

`make_operator_request` is the one write `olive/ui` performs: a signed,
announce-only `operator-request` bus object (ADR-0017 SS5). Publishing it never
itself changes mode or trips the breaker - it is an audit record of a request, not
an enforcement action.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from enum import StrEnum

from olive.gateway.pipeline import bound_evidence
from olive.gateway.telemetry import TelemetryEvent, TelemetrySink
from olive.intelligence.bus import IncidentBus, IncidentObject
from olive.intelligence.reporter import IncidentReport

# The closed set of UI-initiated requests (ADR-0017 SS5). force-mode-request is
# announce-only; the other two target authorities with no enforcement-write path.
OPERATOR_ACTIONS = frozenset(
    {"force-mode-request", "run-campaign-request", "toggle-redteam-dept-request"}
)


class DeptStatus(StrEnum):
    IDLE = "idle"
    THINKING = "thinking"
    EXECUTING = "executing"


@dataclass(frozen=True, slots=True)
class UIEvent:
    """Rule-3-safe projection of a `TelemetryEvent` or `IncidentObject`. Never
    carries `content`, `arguments`, or any other raw-payload field."""

    kind: str  # "decision" (from telemetry) | the IncidentObject.kind (from the bus)
    decision: str | None = None
    rule: str | None = None
    evidence: str | None = None
    agent_id: str | None = None
    session_id: str | None = None
    tool: str | None = None
    direction: str | None = None
    timestamp: str | None = None
    source_dept: str | None = None
    object_id: str | None = None
    confidence: float | None = None
    attack_types: tuple[str, ...] = ()


class UIBroker(TelemetrySink):
    """Bounded queue of `UIEvent`s for the Command Center to stream. Drops on a
    full queue (never blocks a publisher) - the same contract as `QueueSink`."""

    def __init__(self, maxsize: int = 512) -> None:
        self._queue: asyncio.Queue[UIEvent] = asyncio.Queue(maxsize=maxsize)
        self.dropped = 0

    async def publish(self, event: TelemetryEvent) -> None:
        ctx = event.ctx
        self._put(
            UIEvent(
                kind="decision",
                decision=event.verdict.decision.value,
                rule=event.verdict.rule,
                evidence=bound_evidence(event.verdict.evidence or ""),
                agent_id=ctx.agent_id,
                session_id=ctx.session_id,
                tool=ctx.tool,
                direction=ctx.direction,
                timestamp=ctx.timestamp,
            )
        )

    async def on_incident(self, obj: IncidentObject) -> None:
        """Register via `IncidentBus.subscribe(broker.on_incident)` for live
        fan-out. Projects the object's already-bounded `IncidentReport` fields -
        `report.signals` evidence is truncated again defensively."""
        evidence = "; ".join(
            f"{s.get('sentinel', '?')}: {s.get('evidence', '')}" for s in obj.report.signals
        )
        self._put(
            UIEvent(
                kind=obj.kind,
                evidence=bound_evidence(evidence),
                timestamp=obj.created_at,
                source_dept=obj.source_dept,
                object_id=obj.object_id,
                confidence=obj.report.confidence,
                attack_types=tuple(obj.report.attack_types),
            )
        )

    def _put(self, event: UIEvent) -> None:
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self.dropped += 1

    def seed(self, event: UIEvent) -> None:
        """Pre-populate the stream from `IncidentBus.history()` on startup -
        same drop-on-full contract as a live `_put`."""
        self._put(event)

    async def stream(self):
        """Async generator the UI consumes - yields until cancelled."""
        while True:
            yield await self._queue.get()


def make_operator_request(
    bus: IncidentBus, *, action: str, evidence: str = ""
) -> IncidentObject:
    """Build (unsigned) an `operator-request` object for the UI to publish.

    `action` must be one of `OPERATOR_ACTIONS` - the closed set ADR-0017 SS5
    defines. The caller signs and publishes via `bus.publish(obj)` (the default
    `signature=None` signs with the bus's own key, the same precedent as every
    other department, ADR-0014 SS4)."""
    if action not in OPERATOR_ACTIONS:
        raise ValueError(f"unknown operator action: {action!r}")
    report = IncidentReport(
        session_key="",
        agent_id="ui",
        organization_id="",
        confidence=0.0,
        attack_types=[],
        action=action,
        signals=[{"sentinel": "ui", "confidence": 0.0, "evidence": bound_evidence(evidence)}]
        if evidence
        else [],
    )
    return bus.make_object(kind="operator-request", source_dept="ui", report=report)

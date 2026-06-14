"""SentinelRunner tests - the only place a signal becomes an action, and even
then only a deterministic breaker.trip above an explicit threshold (ADR-0005)."""

from __future__ import annotations

import asyncio

from olive.gateway.breaker import CircuitBreaker
from olive.gateway.context import Direction, SecurityContext, hash_arguments
from olive.gateway.pipeline import ALLOW
from olive.gateway.session import SessionStatus
from olive.gateway.telemetry import TelemetryEvent
from olive.intelligence.reporter import build_report
from olive.intelligence.runner import SentinelRunner
from olive.intelligence.signals import Signal

SK = "o:a:s"


def _event(direction: Direction = "inbound") -> TelemetryEvent:
    ctx = SecurityContext(
        agent_id="a",
        session_id="s",
        organization_id="o",
        role="customer-support",
        declared_goal="t",
        tool="read_faq",
        arguments_hash=hash_arguments(None),
        direction=direction,
        call_number=1,
        session_tool_history=(),
        source_trust="untrusted",
        timestamp=SecurityContext.now(),
    )
    return TelemetryEvent(ctx=ctx, verdict=ALLOW, content="x", session_key=SK)


class FakeSentinel:
    def __init__(self, name, signal, directions=frozenset({"inbound"}), boom=False):
        self.name = name
        self.directions = directions
        self._signal = signal
        self._boom = boom
        self.calls = 0

    async def analyze(self, event):
        self.calls += 1
        if self._boom:
            raise RuntimeError("sentinel exploded")
        return self._signal


class FakeStore:
    def __init__(self):
        self.created = []

    async def create_incident(self, ctx, verdict, attack_type, detection_method):
        self.created.append((attack_type, detection_method, verdict.decision))
        return "INC-0007"


def _runner(breaker, sentinels, **kw):
    return SentinelRunner(asyncio.Queue(), breaker, sentinels, **kw)


async def test_high_confidence_signal_quarantines():
    breaker = CircuitBreaker(max_blocks=99)
    sig = Signal.fire("prompt-injection", 0.95, "evil", "prompt-injection")
    runner = _runner(breaker, [FakeSentinel("pi", sig)], threshold=0.8)
    report = await runner.process(_event())
    assert report is not None and report.action == "quarantine"
    assert await breaker.status(SK) is SessionStatus.QUARANTINED


async def test_below_threshold_does_not_quarantine():
    breaker = CircuitBreaker(max_blocks=99)
    sig = Signal.fire("behavior", 0.5, "soft", "suspicious-sequence")
    runner = _runner(breaker, [FakeSentinel("b", sig)], threshold=0.8)
    assert await runner.process(_event()) is None
    assert await breaker.status(SK) is SessionStatus.ACTIVE


async def test_no_detection_no_action():
    breaker = CircuitBreaker(max_blocks=99)
    runner = _runner(breaker, [FakeSentinel("pi", Signal.none("pi"))])
    assert await runner.process(_event()) is None


async def test_already_quarantined_is_deduped():
    breaker = CircuitBreaker(max_blocks=99)
    await breaker.trip(SK, "earlier")
    store = FakeStore()
    sig = Signal.fire("pi", 1.0, "evil", "prompt-injection")
    runner = _runner(breaker, [FakeSentinel("pi", sig)], store=store)
    assert await runner.process(_event()) is None
    assert store.created == []  # no duplicate incident


async def test_sentinel_exception_is_swallowed():
    breaker = CircuitBreaker(max_blocks=99)
    runner = _runner(breaker, [FakeSentinel("boom", Signal.none("boom"), boom=True)])
    # No crash, no detection -> no action.
    assert await runner.process(_event()) is None
    assert await breaker.status(SK) is SessionStatus.ACTIVE


async def test_direction_dispatch_skips_non_matching_sentinels():
    breaker = CircuitBreaker(max_blocks=99)
    outbound_only = FakeSentinel(
        "leak", Signal.fire("leak", 1.0, "x", "data-exfiltration"),
        directions=frozenset({"outbound"}),
    )
    runner = _runner(breaker, [outbound_only])
    assert await runner.process(_event(direction="inbound")) is None
    assert outbound_only.calls == 0


async def test_incident_written_to_store_with_id():
    breaker = CircuitBreaker(max_blocks=99)
    store = FakeStore()
    sig = Signal.fire("pi", 0.99, "evil", "prompt-injection")
    runner = _runner(breaker, [FakeSentinel("pi", sig)], store=store, threshold=0.8)
    report = await runner.process(_event())
    assert report.incident_id == "INC-0007"
    assert store.created and store.created[0][1] == "sentinel"


async def test_run_loop_drains_queue():
    breaker = CircuitBreaker(max_blocks=99)
    sig = Signal.fire("pi", 1.0, "evil", "prompt-injection")
    runner = _runner(breaker, [FakeSentinel("pi", sig)])
    runner.start()
    await runner._queue.put(_event())
    await runner._queue.join()
    await runner.stop()
    assert await breaker.status(SK) is SessionStatus.QUARANTINED


# --- reporter ---


def test_report_render_is_bounded_and_structured():
    fired = [Signal.fire("pi", 0.9, "deterministic trigger", "prompt-injection")]
    report = build_report(
        session_key=SK, agent_id="a", organization_id="o",
        signals=fired, action="quarantine", incident_id="INC-0001",
    )
    text = report.render()
    assert "INC-0001" in text and "prompt-injection" in text
    assert report.confidence == 0.9
    assert "pi" in report.to_json()

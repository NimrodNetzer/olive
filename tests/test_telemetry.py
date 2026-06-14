"""Telemetry seam tests - the gateway's outbound channel must never block the
fast path and must default to a true no-op."""

from __future__ import annotations

import asyncio

from olive.gateway.context import SecurityContext, hash_arguments
from olive.gateway.pipeline import ALLOW
from olive.gateway.telemetry import NullSink, QueueSink, TelemetryEvent


def _event() -> TelemetryEvent:
    ctx = SecurityContext(
        agent_id="a",
        session_id="s",
        organization_id="o",
        role="customer-support",
        declared_goal="t",
        tool="read_faq",
        arguments_hash=hash_arguments(None),
        direction="inbound",
        call_number=1,
        session_tool_history=(),
        source_trust="untrusted",
        timestamp=SecurityContext.now(),
    )
    return TelemetryEvent(ctx=ctx, verdict=ALLOW, content="hello", session_key="o:a:s")


async def test_null_sink_is_noop():
    await NullSink().publish(_event())  # must not raise, returns None


async def test_queue_sink_delivers():
    sink = QueueSink()
    ev = _event()
    await sink.publish(ev)
    got = await sink.queue.get()
    assert got is ev
    assert sink.dropped == 0


async def test_queue_sink_drops_when_full_never_blocks():
    sink = QueueSink(maxsize=1)
    await sink.publish(_event())
    # Second publish must not block even though the queue is full.
    await asyncio.wait_for(sink.publish(_event()), timeout=0.5)
    assert sink.dropped == 1
    assert sink.queue.qsize() == 1

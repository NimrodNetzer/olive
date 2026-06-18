"""Telemetry seam tests - the gateway's outbound channel must never block the
fast path and must default to a true no-op."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from olive.gateway.context import SecurityContext, hash_arguments
from olive.gateway.pipeline import ALLOW
from olive.gateway.telemetry import NullSink, QueueSink, TelemetryEvent, WebhookSink


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


# ---- WebhookSink -----------------------------------------------------------


async def _drain_tasks() -> None:
    """Give fire-and-forget tasks one event-loop turn to complete."""
    await asyncio.sleep(0)
    current = asyncio.current_task()
    pending = [t for t in asyncio.all_tasks() if not t.done() and t is not current]
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)


async def test_webhook_sink_posts_bounded_payload():
    """WebhookSink must POST a JSON summary with hashes only — no raw content."""
    posted: list[dict] = []
    posted_headers: list[dict] = {}

    mock_resp = MagicMock()
    mock_resp.status_code = 200

    async def fake_post(url, content, headers):
        posted.append(json.loads(content))
        posted_headers.update(headers)
        return mock_resp

    mock_client = AsyncMock()
    mock_client.post = fake_post
    mock_client.aclose = AsyncMock()

    sink = WebhookSink("http://example.test/hook", token="secret")
    sink._client = mock_client

    await sink.publish(_event())
    await _drain_tasks()

    assert len(posted) == 1
    body = posted[0]
    assert body["tool"] == "read_faq"
    assert body["decision"] == "allow"
    assert "evidence_hash" in body
    # session_key must be hashed, not raw (security-reviewer BLOCKER 1)
    assert "session_hash" in body
    assert "session_key" not in body
    # Rule 3: raw content must NOT appear in the payload.
    assert "hello" not in json.dumps(body)
    assert posted_headers.get("Authorization") == "Bearer secret"
    await sink.close()


async def test_webhook_sink_drops_on_failure_never_blocks():
    """A failing webhook must increment errors but never raise or block."""
    async def fail_post(url, content, headers):
        raise httpx.ConnectError("refused")

    mock_client = AsyncMock()
    mock_client.post = fail_post
    mock_client.aclose = AsyncMock()

    sink = WebhookSink("http://bad.test/hook")
    sink._client = mock_client

    await asyncio.wait_for(sink.publish(_event()), timeout=0.5)
    await _drain_tasks()

    assert sink.errors == 1
    await sink.close()

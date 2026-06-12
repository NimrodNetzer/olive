from __future__ import annotations

import sqlite3

import pytest

from olive.gateway.context import hash_arguments
from olive.gateway.pipeline import ALLOW, Decision, Verdict
from olive.store.events import EventStore


@pytest.fixture
async def store(tmp_path):
    s = EventStore(tmp_path / "events.db")
    await s.open()
    yield s
    await s.close()


async def test_event_roundtrip(store, make_context, tmp_path):
    ctx = make_context(tool="read_faq")
    event_id = await store.log_event(ctx, ALLOW, latency_ms=3)
    assert event_id.startswith("evt-")

    db = sqlite3.connect(tmp_path / "events.db")
    row = db.execute(
        "SELECT tool, decision, arguments_hash, incident_id FROM events WHERE event_id=?",
        (event_id,),
    ).fetchone()
    db.close()
    assert row == ("read_faq", "allow", ctx.arguments_hash, None)


async def test_incident_ids_are_sequential(store, make_context):
    verdict = Verdict(Decision.BLOCK, rule="policy.forbidden_tool", evidence="e")
    ctx = make_context(tool="access_payroll")
    first = await store.create_incident(ctx, verdict, "privilege-escalation", "deterministic")
    second = await store.create_incident(ctx, verdict, "privilege-escalation", "deterministic")
    assert (first, second) == ("INC-0001", "INC-0002")


async def test_concurrent_incidents_get_unique_ids(store, make_context):
    """Security review finding: id generation must not race under concurrency."""
    import asyncio

    verdict = Verdict(Decision.BLOCK, rule="r", evidence="e")
    ctx = make_context()
    ids = await asyncio.gather(
        *(store.create_incident(ctx, verdict, "prompt-injection", "pattern") for _ in range(20))
    )
    assert len(set(ids)) == 20, f"duplicate incident ids: {sorted(ids)}"


async def test_summary_counts(store, make_context):
    ctx = make_context()
    await store.log_event(ctx, ALLOW)
    blocked = Verdict(Decision.BLOCK, rule="r", evidence="e")
    incident = await store.create_incident(ctx, blocked, "prompt-injection", "pattern")
    await store.log_event(ctx, blocked, incident_id=incident)

    summary = await store.summary()
    assert (summary.total, summary.allowed, summary.blocked, summary.incidents) == (2, 1, 1, 1)


async def test_no_raw_arguments_ever_persisted(store, make_context, tmp_path):
    """CLAUDE.md rule 3: the secret value must not appear anywhere in the DB file."""
    secret = "super-secret-api-key-12345"
    ctx = make_context(tool="send_email", arguments={"body": secret})
    await store.log_event(ctx, ALLOW)
    await store.close()

    raw = (tmp_path / "events.db").read_bytes()
    assert secret.encode() not in raw
    assert hash_arguments({"body": secret}).encode() in raw

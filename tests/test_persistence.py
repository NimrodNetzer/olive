"""M8: State persistence — quarantine state and operating mode survive a gateway restart.

A security product that loses session quarantine when the process restarts is
not a security product. These tests verify the full round-trip: quarantine a
session (via record_block or trip), restart the store+breaker, and confirm the
session is still quarantined and the mode is preserved.
"""

from __future__ import annotations

import pytest
import pytest_asyncio

from olive.gateway.breaker import CircuitBreaker
from olive.gateway.mode import OperatingMode
from olive.gateway.session import SessionStatus
from olive.store.events import EventStore


@pytest_asyncio.fixture
async def store(tmp_path):
    s = EventStore(tmp_path / "test.db")
    await s.open()
    yield s
    await s.close()


# ── Session persistence ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_persist_and_reload_quarantined_session(store):
    sid = "org:agent:session-1"
    await store.persist_session(sid, block_count=3, quarantined=True,
                                reason="3 blocks hit threshold", incident_id="INC-0001")

    rows = await store.load_sessions()
    assert len(rows) == 1
    r = rows[0]
    assert r["session_key"] == sid
    assert r["block_count"] == 3
    assert r["quarantined"] is True
    assert r["quarantine_reason"] == "3 blocks hit threshold"
    assert r["quarantine_incident_id"] == "INC-0001"


@pytest.mark.asyncio
async def test_delete_session_removes_row(store):
    sid = "org:agent:session-2"
    await store.persist_session(sid, block_count=2, quarantined=True,
                                reason="test", incident_id=None)
    assert len(await store.load_sessions()) == 1

    await store.delete_session(sid)
    assert await store.load_sessions() == []


@pytest.mark.asyncio
async def test_restore_revives_quarantined_session(store):
    sid = "org:agent:session-3"
    await store.persist_session(sid, block_count=3, quarantined=True,
                                reason="threshold", incident_id="INC-0002")

    # Simulate restart: new breaker, restore from store
    breaker = CircuitBreaker()
    for row in await store.load_sessions():
        breaker.restore(
            row["session_key"], row["block_count"], row["quarantined"],
            row["quarantine_reason"], row["quarantine_incident_id"],
        )

    status = await breaker.status(sid)
    assert status is SessionStatus.QUARANTINED

    ticket = await breaker.begin_call(sid)
    assert ticket.quarantined is True
    assert ticket.reason == "threshold"
    assert ticket.incident_id == "INC-0002"


@pytest.mark.asyncio
async def test_restore_active_session_stays_active(store):
    """An active (non-quarantined) session row is restored without quarantine."""
    sid = "org:agent:session-4"
    await store.persist_session(sid, block_count=1, quarantined=False,
                                reason=None, incident_id=None)

    breaker = CircuitBreaker()
    for row in await store.load_sessions():
        breaker.restore(
            row["session_key"], row["block_count"], row["quarantined"],
            row["quarantine_reason"], row["quarantine_incident_id"],
        )

    status = await breaker.status(sid)
    assert status is SessionStatus.ACTIVE


@pytest.mark.asyncio
async def test_upsert_session_overwrites_previous(store):
    sid = "org:agent:session-5"
    await store.persist_session(sid, block_count=1, quarantined=False,
                                reason=None, incident_id=None)
    await store.persist_session(sid, block_count=3, quarantined=True,
                                reason="hit threshold", incident_id="INC-0003")

    rows = await store.load_sessions()
    assert len(rows) == 1
    assert rows[0]["block_count"] == 3
    assert rows[0]["quarantined"] is True


# ── Mode persistence ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_persist_and_reload_mode(store):
    assert await store.load_mode() is None

    await store.persist_mode("suspicious")
    assert await store.load_mode() == "suspicious"

    await store.persist_mode("siege")
    assert await store.load_mode() == "siege"


@pytest.mark.asyncio
async def test_restore_mode_revives_siege(store):
    await store.persist_mode("siege")

    breaker = CircuitBreaker()
    saved = await store.load_mode()
    if saved:
        breaker.restore_mode(OperatingMode(saved))

    assert await breaker.mode() is OperatingMode.SIEGE


@pytest.mark.asyncio
async def test_restore_mode_suspicious(store):
    await store.persist_mode("suspicious")

    breaker = CircuitBreaker()
    saved = await store.load_mode()
    if saved:
        breaker.restore_mode(OperatingMode(saved))

    assert await breaker.mode() is OperatingMode.SUSPICIOUS


# ── Integration: breaker quarantine → store → new breaker ─────────────────────


@pytest.mark.asyncio
async def test_record_block_trip_persists_via_snapshot(store):
    """Simulates the proxy's post-trip persist pattern: snapshot after record_block."""
    breaker = CircuitBreaker(max_blocks=1)
    sid = "org:agent:session-6"

    tripped = await breaker.record_block(sid, "INC-0004")
    assert tripped is True

    state = breaker.snapshot(sid)
    assert state is not None
    await store.persist_session(
        sid, state.block_count, state.quarantined,
        state.quarantine_reason, state.quarantine_incident_id,
    )

    # "Restart": new breaker, restore
    breaker2 = CircuitBreaker()
    for row in await store.load_sessions():
        breaker2.restore(
            row["session_key"], row["block_count"], row["quarantined"],
            row["quarantine_reason"], row["quarantine_incident_id"],
        )

    ticket = await breaker2.begin_call(sid)
    assert ticket.quarantined is True


@pytest.mark.asyncio
async def test_release_removes_from_store(store):
    """Releasing a quarantined session also removes it from the persistence table."""
    sid = "org:agent:session-7"
    await store.persist_session(sid, block_count=3, quarantined=True,
                                reason="threshold", incident_id=None)

    rows = await store.load_sessions()
    assert len(rows) == 1

    await store.delete_session(sid)  # mirrors proxy.release_session
    assert await store.load_sessions() == []
